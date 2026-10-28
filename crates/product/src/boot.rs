//! Boot-time preparation of the persistent data and resolution of the
//! sensor set that defines the endpoint.
//!
//! [`open`] runs before the Zigbee device is built, because the Simple
//! Descriptor is fixed at build time. It
//!
//! 1. erases foreign persistent data ([`prepare_nv`]),
//! 2. learns from the journal whether this boot resumes a commissioned
//!    network and which sensor set that network was told about,
//! 3. reuses that set or probes the bus ([`resolve`]), and
//! 4. selects the set as the journal's product tag, so the runtime's next
//!    commit (the join, or the leave) persists it atomically.

use embedded_hal::i2c::I2c;
use embedded_storage::nor_flash::{NorFlash, NorFlashError};
use zigbee_runtime::security_store::{
    PersistentSecurityState, SecurityStateStore, SecurityStoreError,
};

use crate::detection::{DetectedSensors, DetectionOrigin, detect, encode_tag, resolve};
use crate::storage::{NvContents, PartitionError, SecurityStore, prepare_nv, security_journal};

/// Whether the persisted security state will resume a network for this
/// device identity. Mirrors
/// `ZigbeeDevice::reset_security_state_if_identity_changed`: a state
/// recorded for another EUI-64 is about to be cleared, so the boot is
/// effectively factory-new. An unreadable journal also counts as not
/// commissioned (the lifecycle then reports the security failure).
pub fn resumes_network(
    state: Result<Option<PersistentSecurityState>, SecurityStoreError>,
    ieee: [u8; 8],
) -> bool {
    matches!(
        state,
        Ok(Some(state))
            if state.commissioned
                && (state.ieee_address == [0; 8] || state.ieee_address == ieee)
    )
}

/// The journal ready for the runtime, and how this boot resolved.
pub struct Opened<F: NorFlash>
where
    F::Error: NorFlashError,
{
    pub journal: SecurityStore<F>,
    pub sensors: DetectedSensors,
    pub origin: DetectionOrigin,
    pub nv: Result<NvContents, PartitionError<F::Error>>,
}

/// Open the security journal over `flash` (the whole main flash; only the
/// persistent-data partition is accessed) and resolve this boot's sensor
/// set, probing `bus` only when the device is factory-new.
pub fn open<F, I2C>(flash: F, ieee: [u8; 8], bus: &mut I2C) -> Opened<F>
where
    F: NorFlash,
    F::Error: NorFlashError,
    I2C: I2c,
{
    let mut journal = security_journal(flash);
    let nv = prepare_nv(&mut journal);
    let commissioned = resumes_network(journal.load(), ieee);
    let tag = journal.product_tag().ok().flatten();
    let (sensors, origin) = resolve(tag, commissioned, || detect(bus));
    journal.set_product_tag(encode_tag(sensors));
    Opened {
        journal,
        sensors,
        origin,
        nv,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::fake_bus::FakeBus;
    use crate::storage::mock::MockMainFlash;

    const IEEE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// A minimal record that passes the journal's validation: joined with
    /// the legacy default Trust Center link key.
    fn commissioned_state(ieee: [u8; 8]) -> PersistentSecurityState {
        PersistentSecurityState {
            commissioned: true,
            ieee_address: ieee,
            channel: 15,
            pan_id: 0x1A62,
            short_address: 0x4C21,
            global_counter_limit: 0x1000,
            legacy_default_tclk: true,
            tclk_counter_limit: 0x1000,
            ..PersistentSecurityState::default()
        }
    }

    /// Boot, then let the runtime commit `state` with the boot's tag (the
    /// join or the leave), as `SensorApp` does through the same journal.
    fn boot_and_commit(
        flash: &mut MockMainFlash,
        bus: &mut FakeBus,
        state: Option<PersistentSecurityState>,
    ) -> (DetectedSensors, DetectionOrigin, NvContents) {
        let mut opened = open(&mut *flash, IEEE, bus);
        if let Some(state) = state {
            opened.journal.store(&state).unwrap();
        }
        (opened.sensors, opened.origin, opened.nv.unwrap())
    }

    #[test]
    fn factory_new_boot_probes_and_the_join_persists_the_set() {
        let mut flash = MockMainFlash::new();
        let mut bus = FakeBus::with(true, false, true);
        let (sensors, origin, nv) =
            boot_and_commit(&mut flash, &mut bus, Some(commissioned_state(IEEE)));
        assert_eq!(
            sensors,
            DetectedSensors {
                tmp102: true,
                bh1750: false,
                opt3001: true,
            }
        );
        assert_eq!(
            (origin, nv),
            (DetectionOrigin::Detected, NvContents::Erased)
        );
        assert!(!bus.log.is_empty());

        let mut silent = FakeBus::default();
        let (again, origin, nv) = boot_and_commit(&mut flash, &mut silent, None);
        assert_eq!((again, origin), (sensors, DetectionOrigin::Persisted));
        assert_eq!(nv, NvContents::Ours(sensors));
        assert!(silent.log.is_empty());
    }

    #[test]
    fn commissioned_boot_keeps_the_descriptor_even_if_a_sensor_vanishes() {
        let mut flash = MockMainFlash::new();
        boot_and_commit(
            &mut flash,
            &mut FakeBus::with(false, true, false),
            Some(commissioned_state(IEEE)),
        );
        // The BH1750 stops answering; commissioned boots do not probe, and
        // every later commit keeps the set.
        for _ in 0..20 {
            let mut silent = FakeBus::with(false, false, false);
            let (sensors, origin, _) =
                boot_and_commit(&mut flash, &mut silent, Some(commissioned_state(IEEE)));
            assert_eq!(origin, DetectionOrigin::Persisted);
            assert!(sensors.bh1750);
            assert!(silent.log.is_empty());
        }
    }

    #[test]
    fn boot_without_a_commit_does_not_persist_a_new_set() {
        // Factory-new boot that never joins: nothing is written.
        let mut flash = MockMainFlash::new();
        boot_and_commit(&mut flash, &mut FakeBus::with(true, true, true), None);
        assert!(flash.bytes.iter().all(|byte| *byte == 0xFF));
    }

    #[test]
    fn leave_redetects_at_the_next_boot() {
        let mut flash = MockMainFlash::new();
        boot_and_commit(
            &mut flash,
            &mut FakeBus::with(false, true, false),
            Some(commissioned_state(IEEE)),
        );
        // Leave: the runtime commits a not-commissioned state (still with
        // the old set's tag), then the firmware reboots.
        let left = PersistentSecurityState {
            commissioned: false,
            ieee_address: IEEE,
            global_counter_limit: 0x2000,
            ..PersistentSecurityState::default()
        };
        let mut opened = open(&mut flash, IEEE, &mut FakeBus::with(false, true, false));
        opened.journal.store(&left).unwrap();
        drop(opened);

        let (sensors, origin, nv) = boot_and_commit(
            &mut flash,
            &mut FakeBus::with(true, false, false),
            Some(PersistentSecurityState {
                global_counter_limit: 0x3000,
                tclk_counter_limit: 0x3000,
                ..commissioned_state(IEEE)
            }),
        );
        assert_eq!(origin, DetectionOrigin::Detected);
        assert!(sensors.tmp102 && !sensors.bh1750);
        assert!(matches!(nv, NvContents::Ours(_)));
        // The rejoin committed the new set.
        let (sensors, origin, _) = boot_and_commit(&mut flash, &mut FakeBus::default(), None);
        assert_eq!(origin, DetectionOrigin::Persisted);
        assert!(sensors.tmp102 && !sensors.bh1750);
    }

    #[test]
    fn state_of_another_identity_redetects() {
        let mut flash = MockMainFlash::new();
        let mut opened = open(&mut flash, [9; 8], &mut FakeBus::with(false, true, false));
        opened.journal.store(&commissioned_state([9; 8])).unwrap();
        drop(opened);
        let (sensors, origin, _) =
            boot_and_commit(&mut flash, &mut FakeBus::with(true, false, false), None);
        assert_eq!(origin, DetectionOrigin::Detected);
        assert!(sensors.tmp102 && !sensors.bh1750);
    }

    #[test]
    fn migrated_board_starts_factory_new() {
        let mut flash = MockMainFlash::new();
        let nv = crate::storage::NV_PARTITION_START as usize;
        flash.bytes[nv..nv + 1024].fill(0x3C);
        let (_, origin, contents) =
            boot_and_commit(&mut flash, &mut FakeBus::with(false, false, true), None);
        assert_eq!(origin, DetectionOrigin::Detected);
        assert_eq!(contents, NvContents::ErasedForeign);
        assert!(flash.bytes[nv..].iter().all(|byte| *byte == 0xFF));
    }

    #[test]
    fn resumes_network_rules() {
        assert!(resumes_network(Ok(Some(commissioned_state(IEEE))), IEEE));
        assert!(!resumes_network(Ok(Some(commissioned_state([9; 8]))), IEEE));
        let unbound = PersistentSecurityState {
            ieee_address: [0; 8],
            ..commissioned_state(IEEE)
        };
        assert!(resumes_network(Ok(Some(unbound)), IEEE));
        let left = PersistentSecurityState {
            commissioned: false,
            ..commissioned_state(IEEE)
        };
        assert!(!resumes_network(Ok(Some(left)), IEEE));
        assert!(!resumes_network(Ok(None), IEEE));
        assert!(!resumes_network(Err(SecurityStoreError::Corrupt), IEEE));
    }
}
