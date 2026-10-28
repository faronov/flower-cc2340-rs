//! Product policy for the CC2340R5 "flower" soil-moisture sensor.
//!
//! The board crate (`flower-cc2340r5`) owns physical wiring. This crate owns
//! the Zigbee identity, the soil-probe calibration (cargo feature
//! `koptserg` or `diyzi`), detection and persistence of the optional I2C
//! sensors, the endpoint profile built from that detection result, the
//! measurement cadence, the lifecycle policy, the flash partitions on the
//! shared layout (`flower-layout`), and the OTA channel policy.

#![no_std]

pub mod battery;
pub mod boot;
pub mod calibration;
pub mod detection;
pub mod measurement;
pub mod ota;
pub mod policy;
pub mod profile;
pub mod storage;

pub const MANUFACTURER: &str = "zigbee-rs";
pub const MODEL: &str = "CC2340-Flower";
pub const DATE_CODE: &str = "20260415";
/// The package version, which is also the MCUboot image version and the
/// source of the OTA file version ([`ota::file_version`]).
pub const SW_BUILD: &str = env!("CARGO_PKG_VERSION");
pub const ENDPOINT: u8 = 1;

#[cfg(all(feature = "koptserg", feature = "diyzi"))]
compile_error!("select exactly one soil calibration: `koptserg` or `diyzi`");
#[cfg(not(any(feature = "koptserg", feature = "diyzi")))]
compile_error!("select a soil calibration feature: `koptserg` or `diyzi`");
