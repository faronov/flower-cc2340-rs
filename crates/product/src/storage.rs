//! Product-owned flash partitions on koptserg's MCUboot layout
//! ([`flower_layout`]).
//!
//! ```text
//! 0x7F000..0x80000  SecurityStateJournal: two 2-KiB sectors (NvWindow)
//! 0x41800..0x7F000  secondary slot: OTA download (OtaFlash may write here)
//! 0x00000..0x41800  bootloader and running image: read-only at runtime
//! ```
//!
//! Every runtime flash user sees the internal flash through a bounded view:
//! the journal through [`NvWindow`], the OTA writer through [`OtaFlash`].
//! Neither can erase or write the bootloader, the running image or the
//! other's partition. [`SharedFlash`] lets both views share the single
//! internal-flash token; each operation borrows it only for its own
//! duration.
//!
//! # Persistent data in 4 KiB
//!
//! The earlier bootloader-less layout used a separate erase sector for the
//! detected sensor set and 4-KiB journal sectors. koptserg's layout leaves
//! 4 KiB, so:
//!
//! - the journal runs with 2-KiB logical sectors (16 slots of 128 bytes);
//! - the sensor set is the journal's 16-bit product tag
//!   ([`crate::detection::encode_tag`]), committed atomically with the next
//!   security-state record at no flash cost.
//!
//! The journal's crash-safety argument is unchanged: a rollover writes the
//! replay snapshot first and the state record last into the freshly erased
//! other sector, and the previous sector stays authoritative until that
//! record is committed. Only the number of commits between erases shrinks
//! (see [`JOURNAL_SECTOR_SIZE`]).
//!
//! # Foreign contents
//!
//! Boards migrated from koptserg's firmware arrive with ZBOSS NVS data in
//! `0x7F000..0x80000`; boards reflashed over SWD from the earlier layout may
//! hold an untagged journal there. [`prepare_nv`] treats the region as ours
//! only if it is erased or its newest committed record carries a valid
//! flower tag, and erases it otherwise, so such a board starts factory-new
//! and joins again.

use core::cell::RefCell;

use embedded_storage::nor_flash::{
    ErrorType, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash, check_erase, check_read,
    check_write,
};
use flower_layout::{NV_SIZE, NV_START, SECONDARY_SLOT, SECTOR_SIZE};
use zigbee_runtime::security_journal::{SECURITY_JOURNAL_MIN_SECTOR_SIZE, SecurityStateJournal};
use zigbee_runtime::security_store::SecurityStateStore;

use crate::detection::{DetectedSensors, decode_tag};

pub const FLASH_CAPACITY: usize = flower_layout::FLASH_SIZE as usize;
pub const PHYSICAL_ERASE_SIZE: usize = SECTOR_SIZE as usize;

/// One logical journal sector per physical 2-KiB erase sector.
///
/// With every supported replay domain populated (48 in this SED build) a
/// rollover snapshot takes 13 of the 16 slots, leaving 12 replay commits
/// before the next erase. A SED with a handful of peers gets about 56
/// commits per erase.
pub const JOURNAL_SECTOR_SIZE: usize = PHYSICAL_ERASE_SIZE;
pub const NV_PARTITION_START: u32 = NV_START;
pub const NV_PARTITION_SIZE: usize = NV_SIZE as usize;
pub const JOURNAL_SECTOR_A: u32 = 0;
pub const JOURNAL_SECTOR_B: u32 = JOURNAL_SECTOR_SIZE as u32;

/// OTA erases and writes are confined to the secondary slot.
pub const OTA_WRITE_START: u32 = SECONDARY_SLOT;
pub const OTA_WRITE_END: u32 = NV_START;

const _: () = assert!(SECURITY_JOURNAL_MIN_SECTOR_SIZE <= JOURNAL_SECTOR_SIZE);
const _: () = assert!(NV_PARTITION_SIZE == 2 * JOURNAL_SECTOR_SIZE);
const _: () = assert!((NV_PARTITION_START as usize).is_multiple_of(PHYSICAL_ERASE_SIZE));
const _: () = assert!(NV_PARTITION_START as usize + NV_PARTITION_SIZE == FLASH_CAPACITY);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionError<E> {
    OutOfBounds,
    NotAligned,
    Backend(E),
}

impl<E: NorFlashError> NorFlashError for PartitionError<E> {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            Self::OutOfBounds => NorFlashErrorKind::OutOfBounds,
            Self::NotAligned => NorFlashErrorKind::NotAligned,
            Self::Backend(error) => error.kind(),
        }
    }
}

const fn map_layout_error<E>(error: NorFlashErrorKind) -> PartitionError<E> {
    match error {
        NorFlashErrorKind::NotAligned => PartitionError::NotAligned,
        _ => PartitionError::OutOfBounds,
    }
}

/// Bounded view `[START, START + SIZE)` of the main flash with offsets
/// relative to `START`.
pub struct FlashWindow<F, const START: u32, const SIZE: usize> {
    flash: F,
}

impl<F, const START: u32, const SIZE: usize> FlashWindow<F, START, SIZE> {
    pub const fn new(flash: F) -> Self {
        Self { flash }
    }

    pub const fn inner(&self) -> &F {
        &self.flash
    }

    pub fn into_inner(self) -> F {
        self.flash
    }

    /// Translate a window range to its physical start address.
    pub const fn physical_offset(offset: u32, length: usize) -> Option<u32> {
        let Some(end) = (offset as usize).checked_add(length) else {
            return None;
        };
        if end > SIZE {
            return None;
        }
        START.checked_add(offset)
    }
}

impl<F: ErrorType, const START: u32, const SIZE: usize> ErrorType for FlashWindow<F, START, SIZE>
where
    F::Error: NorFlashError,
{
    type Error = PartitionError<F::Error>;
}

impl<F: ReadNorFlash, const START: u32, const SIZE: usize> ReadNorFlash
    for FlashWindow<F, START, SIZE>
where
    F::Error: NorFlashError,
{
    const READ_SIZE: usize = F::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        check_read(self, offset, bytes.len()).map_err(map_layout_error)?;
        let physical =
            Self::physical_offset(offset, bytes.len()).ok_or(PartitionError::OutOfBounds)?;
        self.flash
            .read(physical, bytes)
            .map_err(PartitionError::Backend)
    }

    fn capacity(&self) -> usize {
        SIZE
    }
}

impl<F: NorFlash, const START: u32, const SIZE: usize> NorFlash for FlashWindow<F, START, SIZE>
where
    F::Error: NorFlashError,
{
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const ERASE_SIZE: usize = F::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        check_erase(self, from, to).map_err(map_layout_error)?;
        let length = usize::try_from(to - from).map_err(|_| PartitionError::OutOfBounds)?;
        let physical_from =
            Self::physical_offset(from, length).ok_or(PartitionError::OutOfBounds)?;
        let physical_to = physical_from
            .checked_add(to - from)
            .ok_or(PartitionError::OutOfBounds)?;
        self.flash
            .erase(physical_from, physical_to)
            .map_err(PartitionError::Backend)
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        check_write(self, offset, bytes.len()).map_err(map_layout_error)?;
        let physical =
            Self::physical_offset(offset, bytes.len()).ok_or(PartitionError::OutOfBounds)?;
        self.flash
            .write(physical, bytes)
            .map_err(PartitionError::Backend)
    }
}

/// A [`NorFlash`] shared through a [`RefCell`]: every operation borrows
/// the flash only for its own duration, so several bounded views can use
/// one flash token in a single-threaded executor.
pub struct SharedFlash<'a, F> {
    flash: &'a RefCell<F>,
}

impl<'a, F> SharedFlash<'a, F> {
    pub const fn new(flash: &'a RefCell<F>) -> Self {
        Self { flash }
    }
}

impl<F: ErrorType> ErrorType for SharedFlash<'_, F> {
    type Error = F::Error;
}

impl<F: ReadNorFlash> ReadNorFlash for SharedFlash<'_, F> {
    const READ_SIZE: usize = F::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.flash.borrow_mut().read(offset, bytes)
    }

    fn capacity(&self) -> usize {
        self.flash.borrow().capacity()
    }
}

impl<F: NorFlash> NorFlash for SharedFlash<'_, F> {
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const ERASE_SIZE: usize = F::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.flash.borrow_mut().erase(from, to)
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.flash.borrow_mut().write(offset, bytes)
    }
}

/// The OTA writer's view, with absolute addresses: reads anywhere below the
/// persistent-data partition (downgrade prevention reads the running
/// image's header), erases and writes only inside the secondary slot.
pub struct OtaFlash<F> {
    flash: F,
}

impl<F> OtaFlash<F> {
    pub const fn new(flash: F) -> Self {
        Self { flash }
    }

    pub fn into_inner(self) -> F {
        self.flash
    }

    const fn writable(from: u32, to: u32) -> bool {
        OTA_WRITE_START <= from && from <= to && to <= OTA_WRITE_END
    }
}

impl<F: ErrorType> ErrorType for OtaFlash<F>
where
    F::Error: NorFlashError,
{
    type Error = PartitionError<F::Error>;
}

impl<F: ReadNorFlash> ReadNorFlash for OtaFlash<F>
where
    F::Error: NorFlashError,
{
    const READ_SIZE: usize = F::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        check_read(self, offset, bytes.len()).map_err(map_layout_error)?;
        self.flash
            .read(offset, bytes)
            .map_err(PartitionError::Backend)
    }

    fn capacity(&self) -> usize {
        OTA_WRITE_END as usize
    }
}

impl<F: NorFlash> NorFlash for OtaFlash<F>
where
    F::Error: NorFlashError,
{
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const ERASE_SIZE: usize = F::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        check_erase(self, from, to).map_err(map_layout_error)?;
        if !Self::writable(from, to) {
            return Err(PartitionError::OutOfBounds);
        }
        self.flash.erase(from, to).map_err(PartitionError::Backend)
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        check_write(self, offset, bytes.len()).map_err(map_layout_error)?;
        let end = offset
            .checked_add(bytes.len() as u32)
            .ok_or(PartitionError::OutOfBounds)?;
        if !Self::writable(offset, end) {
            return Err(PartitionError::OutOfBounds);
        }
        self.flash
            .write(offset, bytes)
            .map_err(PartitionError::Backend)
    }
}

pub type NvWindow<F> = FlashWindow<F, NV_PARTITION_START, NV_PARTITION_SIZE>;
pub type SecurityStore<F> = SecurityStateJournal<NvWindow<F>, JOURNAL_SECTOR_SIZE>;

pub fn security_journal<F: NorFlash>(flash: F) -> SecurityStore<F>
where
    F::Error: NorFlashError,
{
    SecurityStateJournal::new_with_sector_size(
        NvWindow::new(flash),
        JOURNAL_SECTOR_A,
        JOURNAL_SECTOR_B,
    )
}

/// What [`prepare_nv`] found in the persistent-data partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvContents {
    /// Fully erased: factory-new.
    Erased,
    /// This firmware's journal; the sensor set of its newest record.
    Ours(DetectedSensors),
    /// Not ours (ZBOSS NVS, an untagged older journal, or an interrupted
    /// first commit): erased, so the board starts factory-new.
    ErasedForeign,
    /// The journal reported an error. Nothing was erased; the lifecycle
    /// reports the failure when it loads the journal.
    Unreadable,
}

/// Classify the persistent-data partition at boot and erase it if it holds
/// anything but this firmware's journal. Runs before the journal is handed
/// to the Zigbee runtime.
///
/// Ownership is decided by the product tag, which this firmware selects at
/// every boot before its first commit ([`crate::boot::open`]), so every
/// record it ever writes is tagged. A committed record without a valid tag
/// was written by other firmware; contents without any committed record are
/// foreign data or an interrupted first commit. Erasing either cannot lose a
/// frame-counter reservation of this firmware. The erase is idempotent: a
/// power cut during it is classified and erased again at the next boot. A
/// journal error never erases anything.
pub fn prepare_nv<F: NorFlash>(
    journal: &mut SecurityStore<F>,
) -> Result<NvContents, PartitionError<F::Error>>
where
    F::Error: NorFlashError,
{
    let committed = match journal.load() {
        Ok(state) => state.is_some(),
        Err(_) => return Ok(NvContents::Unreadable),
    };
    if committed {
        if let Ok(Some(tag)) = journal.product_tag()
            && let Some(sensors) = decode_tag(tag)
        {
            return Ok(NvContents::Ours(sensors));
        }
    } else if is_erased(journal.storage_mut())? {
        return Ok(NvContents::Erased);
    }
    // `storage_mut` also drops the journal's cached scan.
    journal.storage_mut().erase(0, NV_PARTITION_SIZE as u32)?;
    Ok(NvContents::ErasedForeign)
}

fn is_erased<S: ReadNorFlash>(storage: &mut S) -> Result<bool, S::Error> {
    let mut chunk = [0u8; 64];
    let mut offset = 0;
    while offset < storage.capacity() {
        storage.read(offset as u32, &mut chunk)?;
        if chunk.iter().any(|byte| *byte != 0xFF) {
            return Ok(false);
        }
        offset += chunk.len();
    }
    Ok(true)
}

#[cfg(target_os = "none")]
pub type HardwareFlash = flower_cc2340r5::flash::InternalFlash;

/// The journal over the shared internal flash.
#[cfg(target_os = "none")]
pub type HardwareSecurityStore<'a> = SecurityStore<SharedFlash<'a, HardwareFlash>>;

#[cfg(test)]
pub(crate) mod mock {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Whole 512-KiB main flash with NOR semantics (writes only clear bits)
    /// and optional power-cut injection.
    pub struct MockMainFlash {
        pub bytes: Vec<u8>,
        pub erased_physical_sectors: usize,
        pub writes: usize,
        /// Erase/write operations still allowed before the simulated power
        /// cut. The cut operation is left half done and every later one
        /// fails.
        pub budget: Option<usize>,
    }

    impl MockMainFlash {
        pub fn new() -> Self {
            Self {
                bytes: vec![0xFF; FLASH_CAPACITY],
                erased_physical_sectors: 0,
                writes: 0,
                budget: None,
            }
        }

        /// `Ok(true)` to perform the operation, `Ok(false)` to tear it.
        fn spend(&mut self) -> Result<bool, NorFlashErrorKind> {
            match &mut self.budget {
                None => Ok(true),
                Some(0) => Err(NorFlashErrorKind::Other),
                Some(left) => {
                    *left -= 1;
                    Ok(*left != 0)
                }
            }
        }

        pub fn power_cycle(&mut self) {
            self.budget = None;
        }
    }

    impl ErrorType for MockMainFlash {
        type Error = NorFlashErrorKind;
    }

    impl ReadNorFlash for MockMainFlash {
        const READ_SIZE: usize = 1;

        fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            check_read(self, offset, bytes.len())?;
            let start = offset as usize;
            bytes.copy_from_slice(&self.bytes[start..start + bytes.len()]);
            Ok(())
        }

        fn capacity(&self) -> usize {
            self.bytes.len()
        }
    }

    impl NorFlash for MockMainFlash {
        const WRITE_SIZE: usize = 4;
        const ERASE_SIZE: usize = PHYSICAL_ERASE_SIZE;

        fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
            check_erase(self, from, to)?;
            let complete = self.spend()?;
            let (from, to) = (from as usize, to as usize);
            if !complete {
                // Torn erase: only the first half of the first sector.
                self.bytes[from..from + PHYSICAL_ERASE_SIZE / 2].fill(0xFF);
                return Err(NorFlashErrorKind::Other);
            }
            self.bytes[from..to].fill(0xFF);
            self.erased_physical_sectors += (to - from) / PHYSICAL_ERASE_SIZE;
            Ok(())
        }

        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
            check_write(self, offset, bytes.len())?;
            let complete = self.spend()?;
            let start = offset as usize;
            let len = if complete {
                bytes.len()
            } else {
                (bytes.len() / 2) & !3
            };
            for (stored, new) in self.bytes[start..start + len].iter_mut().zip(bytes) {
                if *stored & *new != *new {
                    return Err(NorFlashErrorKind::Other);
                }
                *stored &= *new;
            }
            if !complete {
                return Err(NorFlashErrorKind::Other);
            }
            self.writes += 1;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::mock::MockMainFlash;
    use super::*;
    use crate::detection::encode_tag;
    use flower_layout::{LOADER_INFO_ADDR, PRIMARY_SLOT, SLOT_SIZE};
    use zigbee_runtime::security_store::PersistentSecurityState;

    const NV: usize = NV_PARTITION_START as usize;

    fn sensors(bits: u8) -> DetectedSensors {
        DetectedSensors::from_bits(bits).unwrap()
    }

    fn state(limit: u32) -> PersistentSecurityState {
        PersistentSecurityState {
            commissioned: true,
            ieee_address: [1, 2, 3, 4, 5, 6, 7, 8],
            channel: 15,
            pan_id: 0x1A62,
            short_address: 0x4C21,
            global_counter_limit: limit,
            legacy_default_tclk: true,
            tclk_counter_limit: limit,
            ..PersistentSecurityState::default()
        }
    }

    fn outside_nv_is_erased(flash: &MockMainFlash) -> bool {
        flash.bytes[..NV].iter().all(|byte| *byte == 0xFF)
    }

    #[test]
    fn nv_window_is_the_top_4k_and_cannot_reach_the_slots() {
        assert_eq!(NV_PARTITION_START, 0x7F000);
        assert_eq!(
            NvWindow::<MockMainFlash>::physical_offset(NV_PARTITION_SIZE as u32, 0),
            Some(0x80000)
        );
        assert_eq!(
            NvWindow::<MockMainFlash>::physical_offset(NV_PARTITION_SIZE as u32, 1),
            None
        );
        let mut window = NvWindow::new(MockMainFlash::new());
        assert_eq!(
            window.erase(0, 3 * PHYSICAL_ERASE_SIZE as u32),
            Err(PartitionError::OutOfBounds)
        );
        window.write(0, &[0x5A; 4]).unwrap();
        let flash = window.into_inner();
        assert_eq!(&flash.bytes[NV..NV + 4], &[0x5A; 4]);
        assert!(outside_nv_is_erased(&flash));
    }

    #[test]
    fn ota_view_writes_only_the_secondary_slot() {
        let mut ota = OtaFlash::new(MockMainFlash::new());
        let sector = PHYSICAL_ERASE_SIZE as u32;
        for (from, to) in [
            (0, sector),                                 // loader
            (PRIMARY_SLOT, PRIMARY_SLOT + sector),       // running image
            (OTA_WRITE_START - sector, OTA_WRITE_START), // primary trailer
            (OTA_WRITE_END, OTA_WRITE_END + sector),     // journal
        ] {
            assert!(ota.erase(from, to).is_err(), "{from:#x}..{to:#x}");
            assert!(ota.write(from, &[0; 4]).is_err(), "{from:#x}");
        }
        // Straddling the slot boundaries.
        assert!(
            ota.erase(OTA_WRITE_END - sector, OTA_WRITE_END + sector)
                .is_err()
        );
        assert!(
            ota.erase(OTA_WRITE_START - sector, OTA_WRITE_START + sector)
                .is_err()
        );
        assert!(ota.write(OTA_WRITE_END - 4, &[0; 8]).is_err());
        assert!(ota.write(OTA_WRITE_START - 4, &[0; 8]).is_err());
        ota.erase(OTA_WRITE_START, OTA_WRITE_END).unwrap();
        ota.write(OTA_WRITE_END - 4, &[0; 4]).unwrap();
        ota.write(OTA_WRITE_START, &[0; 4]).unwrap();
        // Reads cover the running image and the loader record.
        let mut word = [0u8; 4];
        ota.read(PRIMARY_SLOT, &mut word).unwrap();
        ota.read(LOADER_INFO_ADDR, &mut word).unwrap();
        assert!(ota.read(OTA_WRITE_END, &mut word).is_err());
        assert_eq!(OTA_WRITE_END - OTA_WRITE_START, SLOT_SIZE);
        let flash = ota.into_inner();
        assert!(
            flash.bytes[..OTA_WRITE_START as usize]
                .iter()
                .all(|b| *b == 0xFF)
        );
        assert!(flash.bytes[NV..].iter().all(|b| *b == 0xFF));
    }

    #[test]
    fn journal_and_ota_share_one_flash() {
        let flash = RefCell::new(MockMainFlash::new());
        let mut journal = security_journal(SharedFlash::new(&flash));
        let mut ota = OtaFlash::new(SharedFlash::new(&flash));
        journal.set_product_tag(encode_tag(sensors(0b101)));
        journal.store(&state(0x4000)).unwrap();
        ota.erase(
            OTA_WRITE_START,
            OTA_WRITE_START + PHYSICAL_ERASE_SIZE as u32,
        )
        .unwrap();
        ota.write(OTA_WRITE_START, &[0x3D, 0xB8, 0xF3, 0x96])
            .unwrap();
        drop((journal, ota));
        let mut journal = security_journal(SharedFlash::new(&flash));
        assert_eq!(journal.load(), Ok(Some(state(0x4000))));
        assert_eq!(
            prepare_nv(&mut journal),
            Ok(NvContents::Ours(sensors(0b101)))
        );
    }

    #[test]
    fn erased_nv_is_factory_new() {
        let mut flash = MockMainFlash::new();
        assert_eq!(
            prepare_nv(&mut security_journal(&mut flash)),
            Ok(NvContents::Erased)
        );
        assert_eq!(flash.erased_physical_sectors, 0);
    }

    #[test]
    fn zboss_nvs_is_erased() {
        let mut flash = MockMainFlash::new();
        // Something NVS-like: headers and payloads, but no journal record.
        for (index, byte) in flash.bytes[NV..NV + 600].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37) ^ 0x5A;
        }
        flash.bytes[NV + 2048..NV + 2048 + 16].fill(0x00);
        assert_eq!(
            prepare_nv(&mut security_journal(&mut flash)),
            Ok(NvContents::ErasedForeign)
        );
        assert!(flash.bytes[NV..].iter().all(|byte| *byte == 0xFF));
        assert_eq!(flash.erased_physical_sectors, 2);
        assert_eq!(
            prepare_nv(&mut security_journal(&mut flash)),
            Ok(NvContents::Erased)
        );
    }

    #[test]
    fn untagged_journal_from_other_firmware_is_erased() {
        let mut flash = MockMainFlash::new();
        security_journal(&mut flash).store(&state(0x9000)).unwrap();
        assert_eq!(
            prepare_nv(&mut security_journal(&mut flash)),
            Ok(NvContents::ErasedForeign)
        );
        assert_eq!(security_journal(&mut flash).load(), Ok(None));
    }

    #[test]
    fn tagged_journal_is_kept_with_its_sensor_set() {
        for bits in 0..8 {
            let mut flash = MockMainFlash::new();
            let mut journal = security_journal(&mut flash);
            journal.set_product_tag(encode_tag(sensors(bits)));
            journal.store(&state(0x1000)).unwrap();
            let erased = flash.erased_physical_sectors;
            let written = flash.bytes[NV..].to_vec();
            assert_eq!(
                prepare_nv(&mut security_journal(&mut flash)),
                Ok(NvContents::Ours(sensors(bits)))
            );
            assert_eq!(flash.erased_physical_sectors, erased);
            assert_eq!(&flash.bytes[NV..], &written[..]);
        }
    }

    #[test]
    fn torn_first_commit_is_never_ours() {
        // Operations of an uninterrupted first commit.
        let mut reference = MockMainFlash::new();
        reference.budget = Some(usize::MAX);
        {
            let mut journal = security_journal(&mut reference);
            journal.set_product_tag(encode_tag(sensors(1)));
            journal.store(&state(0x1000)).unwrap();
        }
        let operations = usize::MAX - reference.budget.unwrap();

        let mut foreign = 0;
        for cut in 1..=operations {
            let mut flash = MockMainFlash::new();
            flash.budget = Some(cut);
            let mut journal = security_journal(&mut flash);
            journal.set_product_tag(encode_tag(sensors(1)));
            assert!(journal.store(&state(0x1000)).is_err(), "cut {cut}");
            flash.power_cycle();
            match prepare_nv(&mut security_journal(&mut flash)) {
                Ok(NvContents::Erased) => {}
                Ok(NvContents::ErasedForeign) => foreign += 1,
                other => panic!("cut {cut}: {other:?}"),
            }
            assert!(flash.bytes[NV..].iter().all(|byte| *byte == 0xFF));
        }
        assert!(foreign > 0, "some cut must leave partial data");
    }

    #[test]
    fn interrupted_foreign_erase_is_completed_at_the_next_boot() {
        let half = NV + JOURNAL_SECTOR_SIZE;
        // Torn erase of the window, and a cut between the two sectors.
        for torn in [true, false] {
            let mut flash = MockMainFlash::new();
            flash.bytes[NV..].fill(0x12);
            if torn {
                flash.budget = Some(1);
                assert!(prepare_nv(&mut security_journal(&mut flash)).is_err());
                flash.power_cycle();
            } else {
                flash.bytes[NV..half].fill(0xFF);
            }
            assert!(flash.bytes[NV..].iter().any(|byte| *byte != 0xFF));
            assert_eq!(
                prepare_nv(&mut security_journal(&mut flash)),
                Ok(NvContents::ErasedForeign)
            );
            assert!(flash.bytes[NV..].iter().all(|byte| *byte == 0xFF));
        }
    }

    /// Commit an increasing reservation across many 2-KiB rollovers and cut
    /// the power at every single erase/write. After each cut the next boot
    /// must keep the journal (tag intact) and never return a reservation
    /// below the last acknowledged one.
    #[test]
    fn two_kib_journal_survives_a_power_cut_at_every_step() {
        const COMMITS: u32 = 40;
        let tag = encode_tag(sensors(0b011));
        // Count the operations of an uninterrupted run.
        let mut reference = MockMainFlash::new();
        reference.budget = Some(usize::MAX);
        {
            let mut journal = security_journal(&mut reference);
            journal.set_product_tag(tag);
            for commit in 1..=COMMITS {
                journal.store(&state(commit * 0x100)).unwrap();
            }
        }
        let operations = usize::MAX - reference.budget.unwrap();
        assert!(reference.erased_physical_sectors >= 2, "must roll over");

        for cut in 1..=operations {
            let mut flash = MockMainFlash::new();
            flash.budget = Some(cut);
            let mut acknowledged = 0;
            {
                let mut journal = security_journal(&mut flash);
                journal.set_product_tag(tag);
                for commit in 1..=COMMITS {
                    if journal.store(&state(commit * 0x100)).is_err() {
                        break;
                    }
                    acknowledged = commit * 0x100;
                }
            }
            flash.power_cycle();

            let mut journal = security_journal(&mut flash);
            let contents = prepare_nv(&mut journal).unwrap();
            if acknowledged == 0 {
                // Nothing durable yet: erased or a torn first commit.
                assert!(
                    matches!(contents, NvContents::Erased | NvContents::ErasedForeign)
                        || contents == NvContents::Ours(sensors(0b011)),
                    "cut {cut}: {contents:?}"
                );
                continue;
            }
            assert_eq!(contents, NvContents::Ours(sensors(0b011)), "cut {cut}");
            let loaded = journal.load().unwrap().unwrap();
            assert!(
                loaded.global_counter_limit >= acknowledged,
                "cut {cut}: {:#x} < {acknowledged:#x}",
                loaded.global_counter_limit
            );
            // The journal keeps working after the cut.
            journal
                .store(&state(loaded.global_counter_limit + 0x100))
                .unwrap();
            assert_eq!(journal.product_tag(), Ok(Some(tag)));
        }
    }

    #[test]
    fn linker_script_matches_the_layout() {
        let script = include_str!("../link/memory.x");
        assert!(script.contains("ORIGIN = 0x00004100, LENGTH = 0x3CC00"));
        assert!(script.contains("_nv_start             = 0x0007F000"));
        assert!(script.contains("_secondary_slot_start = 0x00041800"));
        assert_eq!(flower_layout::APP_START, 0x4100);
        assert_eq!(flower_layout::APP_MAX_LEN, 0x3CC00);
    }
}
