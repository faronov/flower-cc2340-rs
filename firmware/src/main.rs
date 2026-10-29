//! Composition root for koptserg's CC2340R5 "flower" soil-moisture sensor.
//!
//! - The board crate owns the pin map and the fitted peripherals.
//! - The product crate owns identity, the flash layout, sensor detection,
//!   the endpoint and the measurement policy.
//! - [`SensorApp`] owns commissioning, polling, reporting, reset/rejoin and
//!   durable security checkpoints.
//!
//! This file only wires them together. The endpoint's cluster set is
//! resolved *before* the device is built (the Simple Descriptor is fixed
//! from then on): a commissioned boot reuses the persisted detection, while
//! a factory-new boot probes the I2C bus. After the device leaves its
//! network the firmware reboots, so the next boot is factory-new and probes
//! again.
//!
//! The image runs from `0x4100` behind a 0x100-byte MCUboot header, under
//! either koptserg's MCUboot or `bootloader/`; [`product::ota::Channel`]
//! tells them apart and selects the OTA identity.
//!
//! Not validated on hardware: see the README.

#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

mod platform;
mod startup;

#[cfg(all(feature = "logs", feature = "quiet", not(debug_assertions)))]
compile_error!(
    "`logs` has no effect in release builds with `quiet`: use --no-default-features --features <calibration>,logs"
);

use core::cell::{Cell, RefCell};
use core::mem::MaybeUninit;

use cortex_m as _;
use panic_halt as _;

use cc2340_flower_product as product;
use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use flower_cc2340r5 as board;
use flower_cc2340r5::reset::SystemReset;
use product::detection::DetectedSensors;
use product::ota::{Channel, FlowerOtaLifecycle, OtaIdentity};
use product::storage::{NvContents, SharedFlash};
use sensor_sed_app::{DiagnosticEvent, Diagnostics, ForceReportAction, SensorApp, SensorSedParts};
use zigbee_mac::cc2340::{Cc2340Mac, RadioError};
use zigbee_runtime::ZigbeeDevice;
use zigbee_runtime::node::ZigbeeNode;
use zigbee_runtime::profile::ApplicationProfile;
use zigbee_zcl::clusters::basic::PowerSource;

/// Pause between the leave indication and the reboot (as the reference).
const REBOOT_AFTER_LEAVE_MS: u64 = 2_000;

type Flash = product::storage::HardwareFlash;
type Store = product::storage::HardwareSecurityStore<'static>;
type Profile =
    product::ota::FlowerOtaProfile<product::ota::FlowerWriter<SharedFlash<'static, Flash>>>;
type Measurement = product::measurement::FlowerMeasurement<
    board::i2c::I2c,
    board::SoilProbe,
    board::batmon::Batmon,
    embassy_time::Delay,
>;
type Parts = SensorSedParts<
    platform::FlowerWake<'static>,
    platform::StatusLeds<'static>,
    Measurement,
    product::battery::SampledWithSensors,
    FlowerOtaLifecycle,
    ForceReportAction,
    platform::ResetOnlySupervisor<'static>,
    platform::RttDiagnostics<'static>,
>;
type FlowerApp = SensorApp<'static, Cc2340Mac, Store, Profile, Parts>;

/// What the main loop needs once [`setup`] has returned.
struct Running {
    app: &'static mut FlowerApp,
    leds: &'static RefCell<platform::Indicators>,
    left_network: &'static Cell<bool>,
    reset: &'static SystemReset,
}

/// The uninitialised `static` slot of type `$ty` for this expansion, as the
/// only reference to it.
///
/// Each expansion declares a separate slot. Slots are only taken in
/// [`setup`], which runs at most once: it starts with `board::take()`,
/// which hands out the board resources a single time, and halts otherwise.
/// Stage functions receive their slot as `&'static mut MaybeUninit<T>` and
/// build the value directly next to it, so no large temporary outlives the
/// stage's (popped) frame.
macro_rules! slot {
    ($ty:ty) => {{
        static mut SLOT: MaybeUninit<$ty> = MaybeUninit::uninit();
        // SAFETY: see the macro documentation; this is the first and only
        // reference taken to SLOT.
        unsafe { &mut *core::ptr::addr_of_mut!(SLOT) }
    }};
}

/// Move `value` into a [`slot!`] of its own and return the only reference.
macro_rules! place {
    ($ty:ty, $value:expr) => {{
        let value: $ty = $value;
        slot!($ty).write(value)
    }};
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    // All construction happens in `setup`, a plain function whose frame is
    // popped before the stack's deepest paths (steering, discovery, ZCL
    // dispatch) run. Constructing in this async body instead kept every
    // temporary in the main task's poll frame (10.7 KB), which sits under
    // all of those paths and overflowed the stack into .bss.
    let Running {
        app,
        leds,
        left_network,
        reset,
    } = setup();

    if app.initialize().await.is_err() {
        platform::halt();
    }
    loop {
        if app.step().await.is_err() {
            platform::halt();
        }
        if left_network.get() {
            // The step that observed the leave has already persisted the
            // factory-new security state.
            platform::play(leds, platform::Pattern::Left).await;
            Timer::after(Duration::from_millis(REBOOT_AFTER_LEAVE_MS)).await;
            reset.reset();
        }
    }
}

/// Build every long-lived object in static storage.
#[inline(never)]
fn setup() -> Running {
    let Some(resources) = board::take() else {
        platform::halt();
    };
    let left_network: &'static Cell<bool> = place!(Cell<bool>, Cell::new(false));
    let mut diagnostics = platform::init_diagnostics(left_network);
    let board::Resources {
        green_led,
        red_led,
        button,
        mut i2c,
        soil,
        flash,
        batmon,
        reset,
    } = resources;
    let leds: &'static RefCell<platform::Indicators> = place!(
        RefCell<platform::Indicators>,
        RefCell::new(platform::Indicators::new(green_led, red_led))
    );
    let reset: &'static SystemReset = place!(SystemReset, reset);
    log::info!(
        "[FLOWER] starting {} / {} ({} calibration)",
        board::BOARD_NAME,
        board::TARGET_PART,
        product::calibration::ACTIVE.name
    );

    let ieee = match board::identity::factory_ieee_address() {
        Ok(address) => address,
        Err(error) => {
            log::error!("[FLOWER] factory identity unavailable: {error}");
            fatal(leds);
        }
    };
    log::info!("[FLOWER] factory EUI-64: {:02X?}", ieee);

    // One internal-flash token shared by the journal, the OTA writer and
    // the loader-record read; each operation borrows it briefly.
    let flash: &'static RefCell<Flash> = place!(RefCell<Flash>, RefCell::new(flash));
    let channel = Channel::read(&mut SharedFlash::new(flash));
    let identity = OtaIdentity::new(channel, product::ota::VARIANT);
    log::info!(
        "[FLOWER] OTA channel {channel:?}: manufacturer 0x{:04X} image type 0x{:04X} version 0x{:08X}",
        identity.manufacturer_code,
        identity.image_type,
        product::ota::FILE_VERSION
    );

    // Persistent data and the endpoint, which is fixed from here on.
    let (security_store, sensors) = open_storage(slot!(Store), flash, ieee, &mut i2c);

    let profile = build_profile(slot!(Profile), sensors, &identity, flash, leds);
    let device = build_device(ieee, profile, leds);

    match device.reset_security_state_if_identity_changed(security_store, ieee) {
        Ok(true) => log::warn!("[FLOWER] cleared persisted state for a different EUI-64"),
        Ok(false) => {}
        Err(error) => {
            diagnostics.record(DiagnosticEvent::SecurityFailure(error));
            fatal(leds);
        }
    }

    let measurement = product::measurement::FlowerMeasurement::new(
        i2c,
        soil,
        batmon,
        embassy_time::Delay,
        sensors,
        product::calibration::ACTIVE,
        product::measurement::CADENCE,
    )
    .with_supply_latch(&product::ota::SUPPLY);
    let node = ZigbeeNode::new(device, security_store, profile);
    let Ok(app) = SensorApp::new(
        node,
        &product::policy::SENSOR_POLICY,
        SensorSedParts {
            wake: platform::FlowerWake::new(button, leds),
            status: platform::StatusLeds::new(leds),
            environment: measurement,
            battery: product::battery::SampledWithSensors,
            ota: FlowerOtaLifecycle::new(channel, &product::ota::SUPPLY, reset_into_bootloader),
            actions: product::policy::USER_ACTIONS,
            supervisor: platform::ResetOnlySupervisor::new(reset),
            diagnostics,
        },
    ) else {
        // Manual runtime polling and a valid policy are fixed above.
        log::error!("[FLOWER] SensorApp rejected the node or the policy");
        fatal(leds);
    };
    let app = place!(FlowerApp, app);

    Running {
        app,
        leds,
        left_network,
        reset,
    }
}

/// Open (or recover) the persistent data and resolve the endpoint's sensor
/// set. Separate from [`setup`] so the by-value `Opened` and the journal
/// recovery path below it do not stack on setup's other temporaries.
#[inline(never)]
fn open_storage(
    slot: &'static mut MaybeUninit<Store>,
    flash: &'static RefCell<Flash>,
    ieee: [u8; 8],
    i2c: &mut board::i2c::I2c,
) -> (&'static mut Store, DetectedSensors) {
    let product::boot::Opened {
        journal,
        sensors,
        origin,
        nv,
    } = product::boot::open(SharedFlash::new(flash), ieee, i2c);
    let security_store = slot.write(journal);
    match nv {
        Ok(NvContents::ErasedForeign) => {
            log::warn!("[FLOWER] erased foreign persistent data (migrated board): joining as new")
        }
        Ok(contents) => log::info!("[FLOWER] persistent data: {contents:?}"),
        Err(error) => log::error!("[FLOWER] persistent data unusable: {error:?}"),
    }
    log::info!("[FLOWER] sensors {sensors:?} ({origin:?})");
    (security_store, sensors)
}

#[inline(never)]
fn start_radio(ieee: [u8; 8], leds: &RefCell<platform::Indicators>) -> Cc2340Mac {
    let mut mac = match Cc2340Mac::new(ieee) {
        Ok(mac) => mac,
        Err(error) => {
            log::error!("[FLOWER] rejected factory identity: {error:?}");
            fatal(leds);
        }
    };
    if let Err(error) = mac.initialize_radio() {
        match error {
            RadioError::FirmwareUnavailable => {
                log::error!("[FLOWER] radio firmware unavailable (fallback build)");
            }
            RadioError::RadioConfigUnavailable => {
                log::error!("[FLOWER] PHY/board radio configuration unavailable (partial SDK)");
            }
            _ => log::error!("[FLOWER] radio initialization failed: {error:?}"),
        }
        fatal(leds);
    }
    mac
}

/// The endpoint (fixed from here on) with the OTA client.
#[inline(never)]
fn build_profile(
    slot: &'static mut MaybeUninit<Profile>,
    sensors: DetectedSensors,
    identity: &OtaIdentity,
    flash: &'static RefCell<Flash>,
    leds: &RefCell<platform::Indicators>,
) -> &'static mut Profile {
    let Ok(profile) = product::ota::flower_ota_profile(sensors, identity, SharedFlash::new(flash))
    else {
        log::error!("[FLOWER] OTA client endpoint mismatch");
        fatal(leds);
    };
    slot.write(profile)
}

/// Start the radio and build the device in place: by-value `build()` needs
/// a frame larger than this part's whole stack.
#[inline(never)]
fn build_device(
    ieee: [u8; 8],
    profile: &mut Profile,
    leds: &RefCell<platform::Indicators>,
) -> &'static mut ZigbeeDevice<Cc2340Mac> {
    static mut DEVICE_STORAGE: MaybeUninit<ZigbeeDevice<Cc2340Mac>> = MaybeUninit::uninit();
    ZigbeeDevice::builder(start_radio(ieee, leds))
        .power_mode(product::policy::SENSOR_POLICY.power_mode())
        .automatic_polling(false)
        .manufacturer(product::MANUFACTURER)
        .model(product::MODEL)
        .date_code(product::DATE_CODE)
        .sw_build(product::SW_BUILD)
        .power_source(PowerSource::Battery)
        .channels(zigbee_types::ChannelMask::ALL_2_4GHZ)
        .endpoint(
            profile.endpoint(),
            profile.profile_id(),
            profile.device_id(),
            |endpoint| profile.configure_endpoint(endpoint),
        )
        // SAFETY: only `setup` calls this, once (see `slot!`), so this is
        // the only reference ever taken to DEVICE_STORAGE.
        .build_into(unsafe { &mut *core::ptr::addr_of_mut!(DEVICE_STORAGE) })
}

/// After the upgrade request is written: the bootloader installs the
/// staged image on this reset.
fn reset_into_bootloader() -> ! {
    cortex_m::peripheral::SCB::sys_reset()
}

fn fatal(leds: &RefCell<platform::Indicators>) -> ! {
    leds.borrow_mut().fault();
    platform::halt()
}
