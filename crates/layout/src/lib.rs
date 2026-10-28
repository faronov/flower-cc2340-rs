//! Flash map of the flower product, shared by the application, its
//! bootloader and the image tooling.
//!
//! The map is koptserg's MCUboot layout
//! (`mcuboot_flower_CC2340R5_RGE/mcuboot.syscfg`), so a board running his
//! bootloader can install this firmware over the air and keep running it:
//!
//! ```text
//! 0x00000..0x04000  bootloader (koptserg MCUboot, or bootloader/ here)
//!                   0x03FE0..0x04000  LoaderInfo record (our loader only)
//! 0x04000..0x41800  primary slot: 0x100 MCUboot header, application at
//!                   0x04100, TLVs, trailer in the last 2-KiB sector
//! 0x41800..0x7F000  secondary slot: OTA download area
//! 0x7F000..0x80000  persistent data: two 2-KiB security-journal sectors
//! ```
//!
//! The CC2340R5 CCFG (a separate flash bank) is never written; its default
//! `pAppVtor = 0` starts whichever bootloader sits at `0x0`.

#![no_std]

use mcuboot_image::Layout;

include!(concat!(env!("OUT_DIR"), "/keys.rs"));

pub const FLASH_SIZE: u32 = 0x8_0000;
/// Main-flash erase sector.
pub const SECTOR_SIZE: u32 = 0x800;

pub const LOADER_START: u32 = 0x0;
pub const LOADER_SIZE: u32 = 0x4000;
/// [`mcuboot_image::LoaderInfo`] (32 bytes) at the end of the loader
/// region. koptserg's MCUboot leaves this area erased.
pub const LOADER_INFO_ADDR: u32 = LOADER_START + LOADER_SIZE - 32;
/// Version stamped into our loader's `LoaderInfo`.
pub const LOADER_VERSION: u32 = 1;

pub const PRIMARY_SLOT: u32 = 0x4000;
pub const SECONDARY_SLOT: u32 = 0x4_1800;
pub const SLOT_SIZE: u32 = 0x3_D800;

pub const NV_START: u32 = 0x7_F000;
pub const NV_SIZE: u32 = 0x1000;

/// `imgtool sign --header-size`.
pub const IMAGE_HEADER_SIZE: u32 = 0x100;
/// Application vector table.
pub const APP_START: u32 = PRIMARY_SLOT + IMAGE_HEADER_SIZE;
/// Room kept after the application for the TLV area (SHA-256, key hash and
/// ECDSA signature need about 152 bytes).
pub const TLV_RESERVE: u32 = 0x300;
/// Largest linked application (`FLASH` length in `memory.x`).
pub const APP_MAX_LEN: u32 = MCUBOOT.max_image_len() - IMAGE_HEADER_SIZE - TLV_RESERVE;

/// SRAM bounds for the bootloader's stack-pointer check.
pub const RAM: (u32, u32) = (0x2000_0000, 0x2000_9000);

pub const MCUBOOT: Layout = Layout {
    primary: PRIMARY_SLOT,
    secondary: SECONDARY_SLOT,
    slot_size: SLOT_SIZE,
    sector_size: SECTOR_SIZE,
};

const _: () = {
    assert!(LOADER_START + LOADER_SIZE == PRIMARY_SLOT);
    assert!(PRIMARY_SLOT + SLOT_SIZE == SECONDARY_SLOT);
    assert!(SECONDARY_SLOT + SLOT_SIZE == NV_START);
    assert!(NV_START + NV_SIZE == FLASH_SIZE);
    assert!(NV_SIZE == 2 * SECTOR_SIZE);
    assert!(PRIMARY_SLOT.is_multiple_of(SECTOR_SIZE));
    assert!(SECONDARY_SLOT.is_multiple_of(SECTOR_SIZE));
    assert!(SLOT_SIZE.is_multiple_of(SECTOR_SIZE));
    // VTOR needs 256-byte alignment (Cortex-M0+ with < 64 vectors: 128).
    assert!(APP_START.is_multiple_of(0x100));
    assert!(APP_MAX_LEN == 0x3_CC00);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_koptserg_mcuboot() {
        // mcuboot.syscfg / flash_map_backend.h of the reference project.
        assert_eq!((PRIMARY_SLOT, SLOT_SIZE), (0x4000, 0x3D800));
        assert_eq!(SECONDARY_SLOT, 0x41800);
        assert_eq!(SECONDARY_SLOT + SLOT_SIZE, 0x7F000);
        assert_eq!(MCUBOOT.max_image_len(), 0x3D000);
        assert_eq!(APP_START + APP_MAX_LEN + TLV_RESERVE, 0x41000);
    }

    #[test]
    fn keys_are_distinct_points() {
        assert_ne!(TI_KEY_XY, OWN_KEY_XY);
        assert_ne!(TI_KEY_XY, [0; 64]);
        assert!(mcuboot_image::p256::VerifyingKey::from_xy(&TI_KEY_XY).is_some());
        assert!(mcuboot_image::p256::VerifyingKey::from_xy(&OWN_KEY_XY).is_some());
    }

    /// The linker scripts restate the map; keep them in sync.
    #[test]
    fn linker_scripts_match() {
        fn squash(script: &str) -> std::string::String {
            script.chars().filter(|c| !c.is_whitespace()).collect()
        }
        extern crate std;
        let app = squash(include_str!("../../product/link/memory.x"));
        let expect = |script: &str, needle: std::string::String| {
            assert!(script.contains(&needle), "missing {needle}");
        };
        expect(
            &app,
            std::format!("ORIGIN=0x{APP_START:08X},LENGTH=0x{APP_MAX_LEN:X}"),
        );
        expect(
            &app,
            std::format!("_primary_slot_start=0x{PRIMARY_SLOT:08X};"),
        );
        expect(
            &app,
            std::format!("_secondary_slot_start=0x{SECONDARY_SLOT:08X};"),
        );
        expect(&app, std::format!("_nv_start=0x{NV_START:08X};"));
        let loader = squash(include_str!("../../../bootloader/memory.x"));
        expect(
            &loader,
            std::format!(
                "FLASH:ORIGIN=0x{LOADER_START:08X},LENGTH=0x{:X}",
                LOADER_INFO_ADDR - LOADER_START
            ),
        );
        expect(
            &loader,
            std::format!("LOADER_INFO:ORIGIN=0x{LOADER_INFO_ADDR:08X},LENGTH=32"),
        );
    }
}
