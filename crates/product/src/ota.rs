//! OTA channel policy: which bootloader the application runs under, which
//! OTA identity it advertises, when it queries, and when it accepts an
//! offered image.
//!
//! # Channels
//!
//! The application binary is identical under both bootloaders; only the
//! signing key and the OTA identity differ, so each published image goes
//! through exactly one channel:
//!
//! | Loader at `0x0`        | Channel     | Manufacturer       | Image type | Key            |
//! |------------------------|-------------|--------------------|------------|----------------|
//! | `bootloader/` (ours)   | [`Own`]     | `0x1234`           | `0x2341`/`0x2342` | own key |
//! | koptserg's MCUboot     | [`Migrate`] | `0xBEBE` / `0xBABA`| `0x2340`   | TI sample key  |
//! | another zigbee-rs loader | [`Foreign`] | —                | —          | never accepts  |
//!
//! Our loader is recognised by its [`LoaderInfo`] record at
//! [`flower_layout::LOADER_INFO_ADDR`], which also names the key it
//! trusts. MCUboot carries no record, so its absence means koptserg's
//! loader: a migrated board keeps that loader for good (it cannot be
//! replaced safely over the air) and keeps receiving TI-key-signed images
//! with koptserg's OTA identity and higher file versions.
//!
//! [`Own`]: Channel::Own
//! [`Migrate`]: Channel::Migrate
//! [`Foreign`]: Channel::Foreign
//!
//! # File version
//!
//! The OTA file version is `0x25MMmmpp` from the package version
//! `MM.mm.pp`. koptserg's releases use `0x240x00yy`, so every version of
//! this firmware is newer than every koptserg release.

use core::sync::atomic::{AtomicU16, Ordering};

use embedded_storage::nor_flash::NorFlash;
use flower_layout::{IMAGE_HEADER_SIZE, LOADER_INFO_ADDR, MCUBOOT, OWN_KEY_XY, TI_KEY_XY};
use mcuboot_image::{LoaderInfo, SlotPolicy, SlotWriter, TrustedKey};
use sensor_sed_app::{
    OtaActivationOutcome as AppOtaActivationOutcome, OtaEventOutcome as AppOtaEventOutcome,
    OtaLifecycle, OtaServiceOutcome, is_ota_event,
};
use zigbee_mac::MacDriver;
use zigbee_runtime::event_loop::StackEvent;
use zigbee_runtime::firmware_writer::FirmwareWriter;
use zigbee_runtime::node::ZigbeeNode;
use zigbee_runtime::ota::{OtaConfig, OtaManager};
use zigbee_runtime::ota_transport::{OtaEventOutcome as RuntimeOtaEventOutcome, OtaSession};
use zigbee_runtime::profile::{ProfileError, WithOta};
use zigbee_runtime::security_store::SecurityStateStore;

use crate::ENDPOINT;
use crate::detection::DetectedSensors;
use crate::profile::{FlowerProfile, flower_profile};
use crate::storage::OtaFlash;

/// Manufacturer code of the [`Channel::Own`] images: the zigbee-rs
/// development code also used by the ESP32 devkit product. It is not a
/// Zigbee Alliance assignment.
pub const OWN_MANUFACTURER_CODE: u16 = 0x1234;
/// koptserg's OTA manufacturer code for his own board build.
pub const KOPTSERG_MANUFACTURER_CODE: u16 = 0xBEBE;
/// koptserg's OTA manufacturer code for the DIYZi board build.
pub const DIYZI_MANUFACTURER_CODE: u16 = 0xBABA;
/// koptserg's flower image type (both board builds).
pub const MIGRATE_IMAGE_TYPE: u16 = 0x2340;
/// Our image types: one per calibration, so an index can never offer a
/// DIYZi build to a koptserg board.
pub const OWN_IMAGE_TYPE_KOPTSERG: u16 = 0x2341;
pub const OWN_IMAGE_TYPE_DIYZI: u16 = 0x2342;

/// Most significant byte of every file version of this firmware.
pub const FILE_VERSION_PREFIX: u8 = 0x25;
/// Highest file versions koptserg released (`BEBE-2340-24000013.zigbee` and
/// `BABA-2340-24100013.zigbee` in the reference project's `Debug/` and
/// `Diyzi/` build directories); [`FILE_VERSION`] must exceed both.
pub const KOPTSERG_LATEST_RELEASES: [u32; 2] = [0x2400_0013, 0x2410_0013];

/// No download below this (compensated) supply: a CR2032 near its end
/// could brown out during the minutes of radio activity, and the
/// bootloader's copy erases and programs the whole primary slot. Checked
/// when an image is offered, again while the session runs and right before
/// activation.
pub const OTA_MIN_SUPPLY_MV: u16 = 2_500;
/// First client query after joining, then one per day.
pub const FIRST_QUERY_DELAY_SECS: u32 = 300;
pub const QUERY_INTERVAL_SECS: u32 = 24 * 60 * 60;
/// Fast-poll window after OTA traffic (as on the TRADFRI product).
pub const OTA_KEEP_AWAKE_MS: u32 = 120_000;
/// The OTA server: the coordinator's endpoint 1 (Zigbee2MQTT, ZHA).
pub const OTA_SERVER: (u16, u8) = (0x0000, 1);
/// Image Block Request size.
pub const OTA_BLOCK_SIZE: u8 = 48;

/// Board build, selected by the calibration feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Koptserg,
    Diyzi,
}

#[cfg(not(feature = "diyzi"))]
pub const VARIANT: Variant = Variant::Koptserg;
#[cfg(feature = "diyzi")]
pub const VARIANT: Variant = Variant::Diyzi;

/// Which bootloader, and therefore which key and OTA identity, applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Our `bootloader/` with this build's own key.
    Own,
    /// koptserg's MCUboot (no loader record): TI sample key.
    Migrate,
    /// A zigbee-rs loader trusting another key. Images this build could
    /// stage would never be installed, so OTA stays disabled.
    Foreign,
}

impl Channel {
    /// Classify the loader record read from [`LOADER_INFO_ADDR`].
    pub fn detect(info: Option<&LoaderInfo>) -> Self {
        match info {
            None => Self::Migrate,
            Some(info) if info.trusts(&OWN_KEY_XY) => Self::Own,
            Some(_) => Self::Foreign,
        }
    }

    /// Read the loader record from flash. A read error is treated like an
    /// unknown loader: OTA is disabled rather than guessed.
    pub fn read<F: NorFlash>(flash: &mut F) -> Self {
        match LoaderInfo::read(flash, LOADER_INFO_ADDR) {
            Ok(info) => Self::detect(info.as_ref()),
            Err(_) => Self::Foreign,
        }
    }

    pub const fn accepts_images(self) -> bool {
        !matches!(self, Self::Foreign)
    }
}

/// What the OTA client advertises and which key staged images must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtaIdentity {
    pub channel: Channel,
    pub manufacturer_code: u16,
    pub image_type: u16,
    pub key_xy: [u8; 64],
}

impl OtaIdentity {
    pub const fn new(channel: Channel, variant: Variant) -> Self {
        let (manufacturer_code, image_type, key_xy) = match (channel, variant) {
            (Channel::Migrate, Variant::Koptserg) => {
                (KOPTSERG_MANUFACTURER_CODE, MIGRATE_IMAGE_TYPE, TI_KEY_XY)
            }
            (Channel::Migrate, Variant::Diyzi) => {
                (DIYZI_MANUFACTURER_CODE, MIGRATE_IMAGE_TYPE, TI_KEY_XY)
            }
            (_, Variant::Koptserg) => (OWN_MANUFACTURER_CODE, OWN_IMAGE_TYPE_KOPTSERG, OWN_KEY_XY),
            (_, Variant::Diyzi) => (OWN_MANUFACTURER_CODE, OWN_IMAGE_TYPE_DIYZI, OWN_KEY_XY),
        };
        Self {
            channel,
            manufacturer_code,
            image_type,
            key_xy,
        }
    }

    /// The OTA client configuration. Offers are never auto-accepted: the
    /// lifecycle applies the battery and channel policy first.
    pub fn config(&self) -> OtaConfig {
        OtaConfig {
            manufacturer_code: self.manufacturer_code,
            image_type: self.image_type,
            current_version: FILE_VERSION,
            endpoint: ENDPOINT,
            block_size: OTA_BLOCK_SIZE,
            auto_accept: false,
            hardware_version: None,
        }
    }

    /// The staging writer for the secondary slot. It refuses images not
    /// signed with this channel's key, with another header size, or older
    /// than the running image, and writes the upgrade request only on
    /// activation.
    pub fn writer<F: NorFlash>(&self, flash: F) -> FlowerWriter<F> {
        SlotWriter::new(
            OtaFlash::new(flash),
            MCUBOOT,
            SlotPolicy {
                key: TrustedKey::new(self.key_xy),
                header_size: IMAGE_HEADER_SIZE as u16,
            },
        )
    }
}

/// The product's firmware writer over main flash `F`.
pub type FlowerWriter<F> = SlotWriter<OtaFlash<F>>;

/// `0x25MMmmpp`.
pub const fn file_version(major: u8, minor: u8, patch: u8) -> u32 {
    (FILE_VERSION_PREFIX as u32) << 24 | (major as u32) << 16 | (minor as u32) << 8 | patch as u32
}

const fn parse_u8(text: &str) -> u8 {
    let bytes = text.as_bytes();
    assert!(!bytes.is_empty());
    let mut value: u32 = 0;
    let mut index = 0;
    while index < bytes.len() {
        let digit = bytes[index];
        assert!(digit.is_ascii_digit());
        value = value * 10 + (digit - b'0') as u32;
        assert!(value <= 0xFF, "version components must fit a byte");
        index += 1;
    }
    value as u8
}

/// This build's OTA file version, from the package version.
pub const FILE_VERSION: u32 = file_version(
    parse_u8(env!("CARGO_PKG_VERSION_MAJOR")),
    parse_u8(env!("CARGO_PKG_VERSION_MINOR")),
    parse_u8(env!("CARGO_PKG_VERSION_PATCH")),
);

const _: () = {
    assert!(FILE_VERSION > KOPTSERG_LATEST_RELEASES[0]);
    assert!(FILE_VERSION > KOPTSERG_LATEST_RELEASES[1]);
};

/// The most recent compensated supply voltage, published by the
/// measurement and read by the OTA policy. `0` means not measured yet.
pub struct SupplyLatch(AtomicU16);

impl SupplyLatch {
    pub const fn new() -> Self {
        Self(AtomicU16::new(0))
    }

    pub fn record(&self, millivolts: u16) {
        self.0.store(millivolts, Ordering::Relaxed);
    }

    pub fn get(&self) -> Option<u16> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            millivolts => Some(millivolts),
        }
    }
}

impl Default for SupplyLatch {
    fn default() -> Self {
        Self::new()
    }
}

/// The firmware's latch.
pub static SUPPLY: SupplyLatch = SupplyLatch::new();

/// Why an offered image is not downloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decline {
    /// The supply is below [`OTA_MIN_SUPPLY_MV`] or not measured yet.
    Battery,
    /// [`Channel::Foreign`].
    Channel,
}

/// Offer policy: download only on a known channel with enough supply.
pub fn offer_decision(channel: Channel, supply_mv: Option<u16>) -> Result<(), Decline> {
    if !channel.accepts_images() {
        return Err(Decline::Channel);
    }
    match supply_mv {
        Some(millivolts) if millivolts >= OTA_MIN_SUPPLY_MV => Ok(()),
        _ => Err(Decline::Battery),
    }
}

/// Client-initiated Query Next Image schedule, in joined seconds (the
/// lifecycle only services OTA while joined).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuerySchedule {
    remaining_secs: u32,
}

impl QuerySchedule {
    pub const fn new() -> Self {
        Self {
            remaining_secs: FIRST_QUERY_DELAY_SECS,
        }
    }

    /// Advance by `elapsed_secs`; `true` when a query is due, which restarts
    /// the daily interval.
    pub fn advance(&mut self, elapsed_secs: u16) -> bool {
        self.remaining_secs = self.remaining_secs.saturating_sub(u32::from(elapsed_secs));
        if self.remaining_secs == 0 {
            self.remaining_secs = QUERY_INTERVAL_SECS;
            true
        } else {
            false
        }
    }

    pub const fn remaining_secs(&self) -> u32 {
        self.remaining_secs
    }
}

impl Default for QuerySchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// The flower endpoint with its OTA client.
pub type FlowerOtaProfile<W> = WithOta<FlowerProfile, W>;

/// The endpoint for `sensors` plus the OTA Upgrade client staging into the
/// secondary slot of `flash` under `identity`.
pub fn flower_ota_profile<F: NorFlash>(
    sensors: DetectedSensors,
    identity: &OtaIdentity,
    flash: F,
) -> Result<FlowerOtaProfile<FlowerWriter<F>>, ProfileError> {
    WithOta::new(
        flower_profile(sensors),
        OtaManager::new(identity.writer(flash), identity.config()),
    )
}

/// OTA lifecycle for [`sensor_sed_app::SensorApp`]: periodic queries, Image
/// Notify, the offer policy, fast polling while downloading, and a reset
/// into the bootloader after activation.
pub struct FlowerOtaLifecycle {
    session: OtaSession,
    channel: Channel,
    schedule: QuerySchedule,
    supply: &'static SupplyLatch,
    /// Resets into the bootloader once the upgrade request is written.
    reset: fn() -> !,
}

impl FlowerOtaLifecycle {
    pub const fn new(channel: Channel, supply: &'static SupplyLatch, reset: fn() -> !) -> Self {
        Self {
            session: OtaSession::new(),
            channel,
            schedule: QuerySchedule::new(),
            supply,
            reset,
        }
    }

    pub const fn channel(&self) -> Channel {
        self.channel
    }

    /// Re-apply the offer's supply check to a session in progress: the
    /// battery can sag during the long download, and the bootloader's copy
    /// that follows activation rewrites the whole primary slot. A session
    /// abandoned here discards its staged image; the server offers it again
    /// later.
    fn abandon_on_low_supply<W: FirmwareWriter>(&mut self, manager: &mut OtaManager<W>) -> bool {
        if !OtaSession::is_active(manager) && !self.session.activation_pending() {
            return false;
        }
        if offer_decision(self.channel, self.supply.get()).is_ok() {
            return false;
        }
        log::warn!("[ota] supply below {OTA_MIN_SUPPLY_MV} mV: abandoning the upgrade");
        manager.abort();
        if self.session.activation_pending() {
            // Clear the session's flag without a checkpoint: the aborted
            // manager refuses the activation and writes nothing.
            let _ = self.session.activate(manager);
        }
        true
    }

    fn log_status(status: Option<&StackEvent>) {
        match status {
            Some(StackEvent::OtaImageAvailable { version, size }) => {
                log::info!("[ota] offer version=0x{version:08X} size={size}");
            }
            Some(StackEvent::OtaProgress { percent }) => log::info!("[ota] {percent}%"),
            Some(StackEvent::OtaComplete) => log::info!("[ota] verified"),
            Some(StackEvent::OtaFailed) => log::warn!("[ota] failed"),
            _ => {}
        }
    }
}

impl<M, S, W> OtaLifecycle<M, S, FlowerOtaProfile<W>> for FlowerOtaLifecycle
where
    M: MacDriver,
    S: SecurityStateStore,
    W: FirmwareWriter,
{
    const ENABLED: bool = true;

    fn is_active(&self, profile: &FlowerOtaProfile<W>) -> bool {
        OtaSession::is_active(profile.ota())
    }

    fn next_deadline_ms(&self, _profile: &FlowerOtaProfile<W>) -> Option<u32> {
        // The query schedule and the manager count whole seconds of the
        // lifecycle's service calls; no earlier wake-up is needed.
        None
    }

    async fn handle_event(
        &mut self,
        node: &mut ZigbeeNode<'_, M, S, FlowerOtaProfile<W>>,
        event: &StackEvent,
    ) -> AppOtaEventOutcome {
        let (device, profile) = node.device_and_profile_mut();
        let manager = profile.ota_mut();
        let outcome = self
            .session
            .handle_event(device, manager, ENDPOINT, event)
            .await;
        match outcome {
            RuntimeOtaEventOutcome::NotOta if !is_ota_event(event) => {
                return AppOtaEventOutcome::NotHandled;
            }
            // A status event the transport itself raised earlier.
            RuntimeOtaEventOutcome::NotOta => Self::log_status(Some(event)),
            RuntimeOtaEventOutcome::Ignored => {}
            RuntimeOtaEventOutcome::Consumed(status) => Self::log_status(status.as_ref()),
        }

        if self.session.offer_pending(manager) {
            match offer_decision(self.channel, self.supply.get()) {
                Ok(()) => {
                    let status = self.session.accept_offer(device, manager).await;
                    Self::log_status(status.as_ref());
                }
                Err(reason) => {
                    log::warn!("[ota] offer declined: {reason:?}");
                    self.session.decline_offer(manager);
                }
            }
        }

        let active = OtaSession::is_active(manager);
        AppOtaEventOutcome::Handled {
            keep_awake_ms: active.then_some(OTA_KEEP_AWAKE_MS),
            activation_pending: self.session.activation_pending()
                || matches!(event, StackEvent::OtaComplete),
        }
    }

    async fn service(
        &mut self,
        node: &mut ZigbeeNode<'_, M, S, FlowerOtaProfile<W>>,
        elapsed_secs: u16,
    ) -> OtaServiceOutcome {
        let (device, profile) = node.device_and_profile_mut();
        let manager = profile.ota_mut();
        self.abandon_on_low_supply(manager);
        let mut queried = false;
        if self.schedule.advance(elapsed_secs) && self.channel.accepts_images() {
            self.session
                .query_next_image(device, manager, OTA_SERVER)
                .await;
            queried = OtaSession::is_active(manager);
        }
        let status = self.session.service(device, manager, elapsed_secs).await;
        Self::log_status(status.as_ref());

        OtaServiceOutcome {
            keep_awake_ms: (queried || status.is_some()).then_some(OTA_KEEP_AWAKE_MS),
            activation_pending: self.session.activation_pending(),
        }
    }

    fn activate(
        &mut self,
        node: &mut ZigbeeNode<'_, M, S, FlowerOtaProfile<W>>,
    ) -> AppOtaActivationOutcome {
        // SensorApp has just checkpointed the security state. The writer
        // writes the upgrade request magic; the bootloader installs on the
        // next reset. With too little supply the image is discarded first,
        // so the activation fails without writing the request.
        let manager = node.profile_mut().ota_mut();
        if self.abandon_on_low_supply(manager) {
            return AppOtaActivationOutcome::Failed;
        }
        match self.session.activate(manager) {
            Ok(()) => {
                log::info!("[ota] activated, resetting into the bootloader");
                (self.reset)()
            }
            Err(error) => {
                log::warn!("[ota] activation failed: {error:?}");
                AppOtaActivationOutcome::Failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;
    use crate::storage::mock::MockMainFlash;
    use flower_layout::{NV_START, PRIMARY_SLOT, SECONDARY_SLOT, SLOT_SIZE};
    use mcuboot_image::{BOOT_MAGIC, MagicState, trailer::read_magic};
    use zigbee_runtime::firmware_writer::{FirmwareError, MockFirmwareWriter};
    use zigbee_zcl::clusters::ota::{CMD_QUERY_NEXT_IMAGE_RESPONSE, OtaState};

    const TEST_KEY_XY: &[u8; 64] = include_bytes!("../tests/vectors/test-key.xy");
    const TEST_V1: &[u8] = include_bytes!("../tests/vectors/test-v1.bin");
    const TEST_V2: &[u8] = include_bytes!("../tests/vectors/test-v2.bin");
    const TEST_V2_1: &[u8] = include_bytes!("../tests/vectors/test-v2.1.bin");
    const TI_V2_1: &[u8] = include_bytes!("../tests/vectors/ti-v2.1.bin");

    fn test_identity() -> OtaIdentity {
        OtaIdentity {
            key_xy: *TEST_KEY_XY,
            ..OtaIdentity::new(Channel::Own, Variant::Koptserg)
        }
    }

    /// `imgtool sign --pad`: fill the slot and append the request magic.
    fn padded(image: &[u8]) -> Vec<u8> {
        let mut out = std::vec![0xFF; SLOT_SIZE as usize];
        out[..image.len()].copy_from_slice(image);
        let magic = SLOT_SIZE as usize - BOOT_MAGIC.len();
        out[magic..].copy_from_slice(&BOOT_MAGIC);
        out
    }

    /// Flash with `running` in the primary slot and a journal page in NV.
    fn device(running: &[u8]) -> MockMainFlash {
        let mut flash = MockMainFlash::new();
        let primary = PRIMARY_SLOT as usize;
        flash.bytes[primary..primary + running.len()].copy_from_slice(running);
        let nv = NV_START as usize;
        flash.bytes[nv..nv + 64].fill(0x5A);
        flash
    }

    fn download<F: NorFlash>(writer: &mut FlowerWriter<F>, image: &[u8]) {
        writer.erase_slot().unwrap();
        for (index, block) in image.chunks(OTA_BLOCK_SIZE as usize).enumerate() {
            writer
                .write_block((index * OTA_BLOCK_SIZE as usize) as u32, block)
                .unwrap();
        }
    }

    fn request<F: embedded_storage::nor_flash::ReadNorFlash>(flash: &mut F) -> MagicState {
        read_magic(flash, SECONDARY_SLOT, SLOT_SIZE).ok().unwrap()
    }

    #[test]
    fn file_version_follows_the_package_version() {
        assert_eq!(file_version(2, 0, 0), 0x2502_0000);
        assert_eq!(file_version(2, 10, 3), 0x2502_0A03);
        let expected = file_version(
            env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
            env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
            env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
        );
        assert_eq!(FILE_VERSION, expected);
        assert!(KOPTSERG_LATEST_RELEASES.iter().all(|v| FILE_VERSION > *v));
        // Even 0.0.0 of this firmware is newer than any koptserg release.
        assert!(file_version(0, 0, 0) > 0x24FF_FFFF);
    }

    #[test]
    fn channel_follows_the_loader_record() {
        let ours = LoaderInfo::new(0, 1, &OWN_KEY_XY);
        let other = LoaderInfo::new(0, 1, &[0x42; 64]);
        assert_eq!(Channel::detect(Some(&ours)), Channel::Own);
        assert_eq!(Channel::detect(Some(&other)), Channel::Foreign);
        assert_eq!(Channel::detect(None), Channel::Migrate);

        // From flash: erased (koptserg's MCUboot), our record, garbage.
        let mut flash = MockMainFlash::new();
        assert_eq!(Channel::read(&mut flash), Channel::Migrate);
        let at = LOADER_INFO_ADDR as usize;
        flash.bytes[at..at + 32].copy_from_slice(&ours.encode());
        assert_eq!(Channel::read(&mut flash), Channel::Own);
        flash.bytes[at + 20] ^= 1;
        assert_eq!(Channel::read(&mut flash), Channel::Migrate);
        flash.bytes[at..at + 32].copy_from_slice(&other.encode());
        assert_eq!(Channel::read(&mut flash), Channel::Foreign);
    }

    #[test]
    fn identity_per_channel_and_variant() {
        let cases = [
            (
                Channel::Migrate,
                Variant::Koptserg,
                0xBEBE,
                0x2340,
                TI_KEY_XY,
            ),
            (Channel::Migrate, Variant::Diyzi, 0xBABA, 0x2340, TI_KEY_XY),
            (Channel::Own, Variant::Koptserg, 0x1234, 0x2341, OWN_KEY_XY),
            (Channel::Own, Variant::Diyzi, 0x1234, 0x2342, OWN_KEY_XY),
        ];
        for (channel, variant, manufacturer, image_type, key) in cases {
            let identity = OtaIdentity::new(channel, variant);
            assert_eq!(identity.manufacturer_code, manufacturer);
            assert_eq!(identity.image_type, image_type);
            assert_eq!(identity.key_xy, key);
            let config = identity.config();
            assert_eq!(config.manufacturer_code, manufacturer);
            assert_eq!(config.image_type, image_type);
            assert_eq!(config.current_version, FILE_VERSION);
            assert_eq!(config.endpoint, ENDPOINT);
            assert!(!config.auto_accept);
        }
    }

    #[test]
    fn offers_need_a_known_channel_and_supply() {
        assert_eq!(offer_decision(Channel::Own, Some(2_900)), Ok(()));
        assert_eq!(offer_decision(Channel::Migrate, Some(2_500)), Ok(()));
        assert_eq!(
            offer_decision(Channel::Own, Some(2_499)),
            Err(Decline::Battery)
        );
        assert_eq!(offer_decision(Channel::Own, None), Err(Decline::Battery));
        assert_eq!(
            offer_decision(Channel::Foreign, Some(3_000)),
            Err(Decline::Channel)
        );

        let latch = SupplyLatch::new();
        assert_eq!(latch.get(), None);
        latch.record(2_750);
        assert_eq!(latch.get(), Some(2_750));
    }

    #[test]
    fn queries_five_minutes_after_join_then_daily() {
        let mut schedule = QuerySchedule::new();
        let mut due_at = Vec::new();
        let mut now = 0u32;
        // Irregular service intervals, as the sleepy lifecycle produces.
        for step in [30u16, 1, 250, 19, 7, 3_600, 30].iter().cycle().take(200) {
            now += u32::from(*step);
            if schedule.advance(*step) {
                due_at.push(now);
            }
        }
        assert_eq!(due_at[0], 300, "first query once 300 s have elapsed");
        for pair in due_at.windows(2) {
            let gap = pair[1] - pair[0];
            assert!((QUERY_INTERVAL_SECS..QUERY_INTERVAL_SECS + 3_600).contains(&gap));
        }
        assert!(due_at.len() >= 2);
        // A huge gap (long sleep) does not cause a burst of queries.
        let mut schedule = QuerySchedule::new();
        assert!(schedule.advance(u16::MAX));
        assert!(!schedule.advance(1));
    }

    #[test]
    fn own_image_is_staged_and_requested_only_on_activation() {
        let mut flash = device(TEST_V2);
        let nv_before = flash.bytes[NV_START as usize..].to_vec();
        let mut writer = test_identity().writer(&mut flash);
        download(&mut writer, TEST_V2_1);
        writer.verify(TEST_V2_1.len() as u32, None).unwrap();
        assert_eq!(request(writer.flash_mut()), MagicState::Erased);
        writer.activate().unwrap();
        assert_eq!(request(&mut flash), MagicState::Good);
        let secondary = SECONDARY_SLOT as usize;
        assert_eq!(
            &flash.bytes[secondary..secondary + TEST_V2_1.len()],
            TEST_V2_1
        );
        assert_eq!(&flash.bytes[NV_START as usize..], &nv_before[..]);
    }

    #[test]
    fn padded_image_withholds_its_magic_until_activation() {
        let mut flash = device(TEST_V2);
        let image = padded(TEST_V2_1);
        let mut writer = test_identity().writer(&mut flash);
        download(&mut writer, &image);
        assert_eq!(request(writer.flash_mut()), MagicState::Erased);
        writer.verify(image.len() as u32, None).unwrap();
        assert_eq!(request(writer.flash_mut()), MagicState::Erased);
        writer.activate().unwrap();
        assert_eq!(request(writer.flash_mut()), MagicState::Good);
    }

    #[test]
    fn migrate_channel_accepts_only_ti_signed_images() {
        let migrate = OtaIdentity::new(Channel::Migrate, VARIANT);
        let mut flash = device(TEST_V2);
        let mut writer = migrate.writer(&mut flash);
        download(&mut writer, &padded(TI_V2_1));
        writer.verify(SLOT_SIZE, None).unwrap();

        let mut flash = device(TEST_V2);
        let mut writer = migrate.writer(&mut flash);
        download(&mut writer, TEST_V2_1);
        assert_eq!(
            writer.verify(TEST_V2_1.len() as u32, None),
            Err(FirmwareError::VerifyFailed)
        );
        assert_eq!(writer.activate(), Err(FirmwareError::ActivateFailed));
    }

    #[test]
    fn wrong_key_downgrade_and_truncation_are_refused() {
        // TI-signed image on the own channel.
        let mut flash = device(TEST_V2);
        let mut writer = test_identity().writer(&mut flash);
        download(&mut writer, TI_V2_1);
        assert_eq!(
            writer.verify(TI_V2_1.len() as u32, None),
            Err(FirmwareError::VerifyFailed)
        );
        // Older than the running image.
        let mut flash = device(TEST_V2);
        let mut writer = test_identity().writer(&mut flash);
        download(&mut writer, TEST_V1);
        assert_eq!(
            writer.verify(TEST_V1.len() as u32, None),
            Err(FirmwareError::VerifyFailed)
        );
        // Truncated download.
        let mut flash = device(TEST_V2);
        let mut writer = test_identity().writer(&mut flash);
        download(&mut writer, &TEST_V2_1[..TEST_V2_1.len() - 100]);
        assert_eq!(
            writer.verify(TEST_V2_1.len() as u32, None),
            Err(FirmwareError::VerifyFailed)
        );
        assert_eq!(writer.activate(), Err(FirmwareError::ActivateFailed));
        assert_eq!(request(writer.flash_mut()), MagicState::Erased);
    }

    #[test]
    fn ota_profile_keeps_the_detected_clusters_and_adds_the_client() {
        use zigbee_mac::mock::MockMac;
        use zigbee_runtime::ZigbeeDevice;
        use zigbee_runtime::profile::ApplicationProfile;
        use zigbee_zcl::ClusterId;

        let descriptor = |profile: &mut dyn FnMut(
            zigbee_runtime::builder::DeviceBuilder<MockMac>,
        ) -> ZigbeeDevice<MockMac>| {
            let device = profile(zigbee_runtime::ZigbeeDevice::builder(MockMac::new([
                1, 2, 3, 4, 5, 6, 7, 8,
            ])));
            let endpoint = &device.endpoints()[0];
            (
                endpoint.server_clusters.to_vec(),
                endpoint.client_clusters.to_vec(),
            )
        };
        for bits in 0..8u8 {
            let sensors = DetectedSensors::from_bits(bits).unwrap();
            let mut flash = MockMainFlash::new();
            let identity = OtaIdentity::new(Channel::Own, VARIANT);
            let with_ota = flower_ota_profile(sensors, &identity, &mut flash).unwrap();
            let plain = flower_profile(sensors);
            assert!(!OtaSession::is_active(with_ota.ota()));
            let (servers, clients) = descriptor(&mut |builder| {
                builder
                    .endpoint(
                        with_ota.endpoint(),
                        with_ota.profile_id(),
                        with_ota.device_id(),
                        |endpoint| with_ota.configure_endpoint(endpoint),
                    )
                    .build()
            });
            let (plain_servers, plain_clients) = descriptor(&mut |builder| {
                builder
                    .endpoint(
                        plain.endpoint(),
                        plain.profile_id(),
                        plain.device_id(),
                        |endpoint| plain.configure_endpoint(endpoint),
                    )
                    .build()
            });
            assert_eq!(servers, plain_servers, "{sensors:?}");
            assert!(plain_clients.is_empty());
            assert_eq!(clients, [ClusterId::OTA_UPGRADE]);
        }
    }

    fn downloading_manager() -> OtaManager<MockFirmwareWriter> {
        let identity = test_identity();
        let mut manager = OtaManager::new(MockFirmwareWriter::new(4096), identity.config());
        let mut response = [0u8; 13];
        response[1..3].copy_from_slice(&identity.manufacturer_code.to_le_bytes());
        response[3..5].copy_from_slice(&identity.image_type.to_le_bytes());
        response[5..9].copy_from_slice(&file_version(2, 0, 1).to_le_bytes());
        response[9..13].copy_from_slice(&1024u32.to_le_bytes());
        manager.start_query();
        manager.handle_incoming(CMD_QUERY_NEXT_IMAGE_RESPONSE.0, &response, None);
        manager.accept_ota();
        manager.handle_incoming(CMD_QUERY_NEXT_IMAGE_RESPONSE.0, &response, None);
        assert!(matches!(manager.state(), OtaState::Downloading { .. }));
        manager
    }

    fn no_reset() -> ! {
        panic!("reset")
    }

    #[test]
    fn a_running_download_is_abandoned_when_the_supply_sags() {
        static SUPPLY: SupplyLatch = SupplyLatch::new();
        let mut lifecycle = FlowerOtaLifecycle::new(Channel::Own, &SUPPLY, no_reset);

        let mut idle = OtaManager::new(MockFirmwareWriter::new(4096), test_identity().config());
        assert!(!lifecycle.abandon_on_low_supply(&mut idle));

        SUPPLY.record(OTA_MIN_SUPPLY_MV);
        let mut manager = downloading_manager();
        assert!(!lifecycle.abandon_on_low_supply(&mut manager));
        assert!(matches!(manager.state(), OtaState::Downloading { .. }));

        SUPPLY.record(OTA_MIN_SUPPLY_MV - 1);
        assert!(lifecycle.abandon_on_low_supply(&mut manager));
        assert_eq!(manager.state(), OtaState::Idle);
        assert!(!manager.is_suspended());
    }

    #[test]
    fn declined_offer_does_not_touch_flash() {
        let mut flash = device(TEST_V2);
        let before = flash.bytes.clone();
        let mut writer = test_identity().writer(&mut flash);
        writer.abort().unwrap();
        assert!(flash.bytes == before);
    }
}
