//! Autodetection and persistence of the optional I2C sensors.
//!
//! The flower board can be populated with any subset of TMP102 (0x48),
//! BH1750 (0x23) and OPT3001 (0x44). The Simple Descriptor advertised to the
//! coordinator is derived from the detected set (see
//! [`crate::profile::flower_profile`]), so the set must stay stable while
//! the device is commissioned: a sensor that fails to answer one boot must
//! not make a cluster disappear from an interviewed device.
//!
//! [`resolve`] therefore probes the bus only while the device is
//! factory-new (never joined, or after leave/factory reset). The result is
//! persisted as the security journal's product tag ([`encode_tag`]), which
//! is committed atomically with the security state it was advertised in. A
//! commissioned boot reuses the persisted set without touching the bus.

use embedded_hal::i2c::I2c;

/// The set of fitted optional sensors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DetectedSensors {
    pub tmp102: bool,
    pub bh1750: bool,
    pub opt3001: bool,
}

/// Temperature cluster source (the cluster itself is always present).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemperatureSource {
    Tmp102,
    /// CC2340 BATMON die temperature: coarse, but keeps 0x0402 meaningful
    /// on boards without a TMP102.
    DieTemperature,
}

/// Illuminance cluster source; absent means no Illuminance cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LightSensor {
    Opt3001,
    Bh1750,
}

const BIT_TMP102: u8 = 1 << 0;
const BIT_BH1750: u8 = 1 << 1;
const BIT_OPT3001: u8 = 1 << 2;
const KNOWN_BITS: u8 = BIT_TMP102 | BIT_BH1750 | BIT_OPT3001;

impl DetectedSensors {
    pub const NONE: Self = Self {
        tmp102: false,
        bh1750: false,
        opt3001: false,
    };

    pub const fn bits(self) -> u8 {
        (self.tmp102 as u8 * BIT_TMP102)
            | (self.bh1750 as u8 * BIT_BH1750)
            | (self.opt3001 as u8 * BIT_OPT3001)
    }

    /// Decode a persisted set, rejecting bits this firmware does not know.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !KNOWN_BITS != 0 {
            return None;
        }
        Some(Self {
            tmp102: bits & BIT_TMP102 != 0,
            bh1750: bits & BIT_BH1750 != 0,
            opt3001: bits & BIT_OPT3001 != 0,
        })
    }

    pub const fn temperature_source(self) -> TemperatureSource {
        if self.tmp102 {
            TemperatureSource::Tmp102
        } else {
            TemperatureSource::DieTemperature
        }
    }

    /// The light sensor used for the Illuminance cluster. If both are
    /// fitted, the OPT3001 wins: it has the wider range, a positive device
    /// ID check, and automatic full-scale ranging.
    pub const fn light_sensor(self) -> Option<LightSensor> {
        if self.opt3001 {
            Some(LightSensor::Opt3001)
        } else if self.bh1750 {
            Some(LightSensor::Bh1750)
        } else {
            None
        }
    }

    pub const fn has_light_sensor(self) -> bool {
        self.light_sensor().is_some()
    }
}

/// Probe every supported sensor and leave each detected one in its lowest
/// power state. A sensor counts as present only if it acknowledges both the
/// probe and the power-down command.
pub fn detect<I2C: I2c>(bus: &mut I2C) -> DetectedSensors {
    let mut tmp102 = zigbee_tmp102::Tmp102::new(&mut *bus, zigbee_tmp102::ADDRESS_GND);
    let tmp102_present = tmp102.probe().is_ok() && tmp102.shutdown().is_ok();

    // The BH1750 has no ID register; the reference also detects it by an
    // acknowledged command. Power-down is the harmless one.
    let mut bh1750 = zigbee_bh1750::Bh1750::new(&mut *bus, zigbee_bh1750::ADDRESS_LOW);
    let bh1750_present = bh1750.power_down().is_ok();

    let mut opt3001 = zigbee_opt3001::Opt3001::new(&mut *bus, zigbee_opt3001::ADDRESS_GND);
    let opt3001_present = opt3001.probe().is_ok() && opt3001.shutdown().is_ok();

    DetectedSensors {
        tmp102: tmp102_present,
        bh1750: bh1750_present,
        opt3001: opt3001_present,
    }
}

// ── Persistence as the security-journal product tag ─────────────────

const TAG_MARKER: u16 = 0xA500;

/// Encode a sensor set as the security journal's product tag
/// (`0xA5`, complement nibble, set bits). The tag is committed atomically
/// with the next security-state record, so the persisted set always belongs
/// to the network state it was advertised in.
pub const fn encode_tag(sensors: DetectedSensors) -> u16 {
    let bits = sensors.bits() as u16;
    TAG_MARKER | ((!bits & 0x7) << 4) | bits
}

/// Decode a product tag. The untagged value `0xFFFF`, tags of other
/// products, and unknown sensor bits are rejected.
pub const fn decode_tag(tag: u16) -> Option<DetectedSensors> {
    if tag & 0xFF00 != TAG_MARKER || tag & 0x0080 != 0 {
        return None;
    }
    let bits = (tag & 0x0F) as u8;
    let check = ((tag >> 4) & 0x7) as u8;
    if bits & 0x08 != 0 || check != !bits & 0x7 {
        return None;
    }
    DetectedSensors::from_bits(bits)
}

/// How the boot-time sensor set was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionOrigin {
    /// Commissioned boot: the set persisted with the network state was
    /// reused without probing.
    Persisted,
    /// Factory-new boot: probed. The set is committed with the next
    /// security-state record.
    Detected,
}

/// Resolve the sensor set that defines this boot's endpoint.
///
/// A commissioned boot whose newest journal record carries a valid tag
/// reuses that set and does not touch the bus: a sensor that fails to
/// answer once must not remove a cluster from an interviewed device.
/// Otherwise (factory-new, after leave, or no valid tag) `probe` runs.
pub fn resolve(
    tag: Option<u16>,
    commissioned: bool,
    probe: impl FnOnce() -> DetectedSensors,
) -> (DetectedSensors, DetectionOrigin) {
    match tag.and_then(decode_tag) {
        Some(sensors) if commissioned => (sensors, DetectionOrigin::Persisted),
        _ => (probe(), DetectionOrigin::Detected),
    }
}

#[cfg(test)]
pub(crate) mod fake_bus {
    extern crate std;

    use embedded_hal::i2c::{ErrorKind, ErrorType, I2c, NoAcknowledgeSource, Operation};
    use std::vec::Vec;

    /// I2C bus emulating the subset of TMP102/BH1750/OPT3001 behavior the
    /// product uses. Absent addresses NACK.
    #[derive(Default)]
    pub struct FakeBus {
        pub tmp102: bool,
        pub bh1750: bool,
        pub opt3001: bool,
        /// Raw TMP102 temperature register.
        pub tmp102_raw: [u8; 2],
        pub tmp102_config: [u8; 2],
        pub bh1750_raw: u16,
        pub opt3001_result: u16,
        pub opt3001_config: u16,
        pub fail_reads: bool,
        pub log: Vec<(u8, Vec<u8>)>,
        pointer: u8,
    }

    impl FakeBus {
        pub fn with(tmp102: bool, bh1750: bool, opt3001: bool) -> Self {
            Self {
                tmp102,
                bh1750,
                opt3001,
                tmp102_config: [0x60, 0xA0],
                ..Self::default()
            }
        }

        fn present(&self, address: u8) -> bool {
            match address {
                0x48 => self.tmp102,
                0x23 => self.bh1750,
                0x44 => self.opt3001,
                _ => false,
            }
        }

        pub fn writes_to(&self, address: u8) -> Vec<Vec<u8>> {
            self.log
                .iter()
                .filter(|(a, _)| *a == address)
                .map(|(_, bytes)| bytes.clone())
                .collect()
        }
    }

    impl ErrorType for FakeBus {
        type Error = ErrorKind;
    }

    impl I2c for FakeBus {
        fn transaction(
            &mut self,
            address: u8,
            operations: &mut [Operation<'_>],
        ) -> Result<(), Self::Error> {
            if !self.present(address) {
                return Err(ErrorKind::NoAcknowledge(NoAcknowledgeSource::Address));
            }
            for operation in operations {
                match operation {
                    Operation::Write(bytes) => {
                        self.log.push((address, bytes.to_vec()));
                        match address {
                            0x48 => {
                                self.pointer = bytes[0];
                                if bytes.len() == 3 && bytes[0] == 0x01 {
                                    self.tmp102_config = [bytes[1], bytes[2]];
                                }
                            }
                            0x44 => {
                                self.pointer = bytes[0];
                                if bytes.len() == 3 && bytes[0] == 0x01 {
                                    self.opt3001_config = u16::from_be_bytes([bytes[1], bytes[2]]);
                                }
                            }
                            _ => {}
                        }
                    }
                    Operation::Read(buffer) => {
                        if self.fail_reads {
                            return Err(ErrorKind::Bus);
                        }
                        let value: [u8; 2] = match (address, self.pointer) {
                            (0x48, 0x00) => self.tmp102_raw,
                            (0x48, 0x01) => self.tmp102_config,
                            (0x23, _) => self.bh1750_raw.to_be_bytes(),
                            (0x44, 0x00) => self.opt3001_result.to_be_bytes(),
                            (0x44, 0x01) => self.opt3001_config.to_be_bytes(),
                            (0x44, 0x7E) => 0x5449u16.to_be_bytes(),
                            (0x44, 0x7F) => 0x3001u16.to_be_bytes(),
                            _ => [0, 0],
                        };
                        buffer.copy_from_slice(&value[..buffer.len()]);
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::fake_bus::FakeBus;
    use super::*;

    const COMBINATIONS: [DetectedSensors; 8] = {
        let mut all = [DetectedSensors::NONE; 8];
        let mut bits = 0;
        while bits < 8 {
            all[bits as usize] = match DetectedSensors::from_bits(bits) {
                Some(sensors) => sensors,
                None => panic!(),
            };
            bits += 1;
        }
        all
    };

    #[test]
    fn bits_round_trip_and_reject_unknown_bits() {
        for sensors in COMBINATIONS {
            assert_eq!(DetectedSensors::from_bits(sensors.bits()), Some(sensors));
        }
        assert_eq!(DetectedSensors::from_bits(0x08), None);
        assert_eq!(DetectedSensors::from_bits(0xFF), None);
    }

    #[test]
    fn source_selection() {
        let none = DetectedSensors::NONE;
        assert_eq!(none.temperature_source(), TemperatureSource::DieTemperature);
        assert_eq!(none.light_sensor(), None);
        let all = DetectedSensors {
            tmp102: true,
            bh1750: true,
            opt3001: true,
        };
        assert_eq!(all.temperature_source(), TemperatureSource::Tmp102);
        assert_eq!(all.light_sensor(), Some(LightSensor::Opt3001));
        let bh = DetectedSensors {
            bh1750: true,
            ..DetectedSensors::NONE
        };
        assert_eq!(bh.light_sensor(), Some(LightSensor::Bh1750));
        assert!(bh.has_light_sensor());
    }

    #[test]
    fn detect_reports_exactly_the_fitted_sensors_and_powers_them_down() {
        for expected in COMBINATIONS {
            let mut bus = FakeBus::with(expected.tmp102, expected.bh1750, expected.opt3001);
            assert_eq!(detect(&mut bus), expected);
            if expected.tmp102 {
                // Shutdown bit set in the config written back.
                assert_eq!(bus.tmp102_config[0] & 0x01, 0x01);
            }
            if expected.bh1750 {
                assert_eq!(bus.writes_to(0x23), [[0x00]]);
            }
            if expected.opt3001 {
                assert_eq!(bus.opt3001_config & 0x0600, 0);
            }
        }
    }

    #[test]
    fn opt3001_with_a_wrong_id_is_not_detected() {
        // Address 0x44 acknowledges but the ID registers read zero.
        struct WrongIdBus(FakeBus);
        impl embedded_hal::i2c::ErrorType for WrongIdBus {
            type Error = embedded_hal::i2c::ErrorKind;
        }
        impl I2c for WrongIdBus {
            fn transaction(
                &mut self,
                address: u8,
                operations: &mut [embedded_hal::i2c::Operation<'_>],
            ) -> Result<(), Self::Error> {
                self.0.transaction(address, operations)?;
                if address == 0x44 {
                    for operation in operations {
                        if let embedded_hal::i2c::Operation::Read(buffer) = operation {
                            buffer.fill(0);
                        }
                    }
                }
                Ok(())
            }
        }
        let mut bus = WrongIdBus(FakeBus::with(false, false, true));
        assert_eq!(detect(&mut bus), DetectedSensors::NONE);
    }

    #[test]
    fn tag_round_trips_every_combination() {
        let mut tags = std::vec::Vec::new();
        for sensors in COMBINATIONS {
            let tag = encode_tag(sensors);
            assert_eq!(tag >> 8, 0xA5);
            assert_eq!(decode_tag(tag), Some(sensors));
            tags.push(tag);
        }
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), 8);
        assert_eq!(encode_tag(DetectedSensors::NONE), 0xA570);
    }

    #[test]
    fn foreign_and_corrupt_tags_are_rejected() {
        let good = encode_tag(DetectedSensors {
            tmp102: true,
            ..DetectedSensors::NONE
        });
        assert!(decode_tag(good).is_some());
        // Untagged records, other products, flipped bits.
        for tag in [
            0xFFFF,
            0x0000,
            0xA5FF,
            0x5A61,
            good ^ 0x0001,
            good ^ 0x0010,
            good | 0x0080,
        ] {
            assert_eq!(decode_tag(tag), None, "{tag:#06x}");
        }
        // A consistent complement over unknown bit 3 is still rejected.
        assert_eq!(decode_tag(0xA508 | (0x7 << 4)), None);
        // Every one-bit corruption of every valid tag is detected.
        for sensors in COMBINATIONS {
            let tag = encode_tag(sensors);
            for bit in 0..16 {
                assert_eq!(decode_tag(tag ^ (1 << bit)), None, "{tag:#06x} bit {bit}");
            }
        }
    }

    #[test]
    fn commissioned_boot_reuses_the_tag_without_probing() {
        for persisted in COMBINATIONS {
            let resolved = resolve(Some(encode_tag(persisted)), true, || {
                panic!("a commissioned boot must not probe the bus")
            });
            assert_eq!(resolved, (persisted, DetectionOrigin::Persisted));
        }
    }

    #[test]
    fn factory_new_or_untagged_boots_probe() {
        let probed = DetectedSensors {
            bh1750: true,
            ..DetectedSensors::NONE
        };
        let stale = encode_tag(DetectedSensors {
            tmp102: true,
            ..DetectedSensors::NONE
        });
        // Factory-new (after leave the tag is still there, but stale).
        assert_eq!(
            resolve(Some(stale), false, || probed),
            (probed, DetectionOrigin::Detected)
        );
        assert_eq!(
            resolve(None, false, || probed),
            (probed, DetectionOrigin::Detected)
        );
        // Commissioned without a valid tag.
        assert_eq!(
            resolve(Some(0xFFFF), true, || probed),
            (probed, DetectionOrigin::Detected)
        );
        assert_eq!(
            resolve(None, true, || probed),
            (probed, DetectionOrigin::Detected)
        );
    }
}
