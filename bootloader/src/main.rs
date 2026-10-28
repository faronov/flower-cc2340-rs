//! Bootloader for the flower board: koptserg's MCUboot flash layout and
//! image format, overwrite-only, with this project's own signing key.
//!
//! Each reset it installs a pending OTA image from the secondary slot (power
//! fail safe), validates the primary image (SHA-256 and ECDSA P-256 over the
//! `imgtool` TLVs, downgrade prevention) and starts it at `0x4100`. The
//! green LED blinks while an image is copied; with nothing bootable the red
//! LED blinks ten times and the chip enters SHUTDOWN until SW1 is pressed.
//!
//! The 32-byte [`LOADER_INFO`] record at `0x3FE0` tells the application
//! that it runs under this loader and which key it trusts, which selects
//! the application's OTA channel.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

/// LoaderInfo record ("ZRSBOOT1", loader version, first 8 bytes of the
/// trusted key's X coordinate).
#[cfg_attr(target_os = "none", unsafe(link_section = ".loader_info"))]
#[used]
pub static LOADER_INFO: [u8; 32] = loader_info();

const fn loader_info() -> [u8; 32] {
    #[cfg(target_os = "none")]
    {
        cc2340r5_boot::loader_info(flower_layout::LOADER_VERSION, &flower_layout::OWN_KEY_XY)
    }
    #[cfg(not(target_os = "none"))]
    {
        [0; 32]
    }
}

#[cfg(target_os = "none")]
mod target {
    use cc2340r5_boot::{Config, Indicator, TrustedKey};
    use flower_cc2340r5::pins::{GreenLed, RedLed};
    use flower_layout::{MCUBOOT, OWN_KEY_XY, RAM};
    use panic_halt as _;

    static CONFIG: Config = Config {
        layout: MCUBOOT,
        key: TrustedKey::new(OWN_KEY_XY),
        ram: RAM,
    };

    struct Leds {
        green: GreenLed,
        red: RedLed,
    }

    impl Indicator for Leds {
        fn installing(&mut self, on: bool) {
            self.green.set(on);
        }

        fn fault(&mut self, on: bool) {
            self.red.set(on);
        }

        fn off(&mut self) {
            self.green.off();
            self.red.off();
        }
    }

    #[cortex_m_rt::entry]
    fn main() -> ! {
        let Some(board) = flower_cc2340r5::take_boot() else {
            loop {
                cortex_m::asm::wfi();
            }
        };
        // Keep the record even if nothing else references it.
        // SAFETY: plain read of an initialized static.
        let _ = unsafe { core::ptr::read_volatile(&super::LOADER_INFO[0]) };
        let mut leds = Leds {
            green: board.green_led,
            red: board.red_led,
        };
        let mut button = board.button;
        cc2340r5_boot::run(board.flash, &CONFIG, &mut leds, move || {
            button.enable_shutdown_wake()
        })
    }
}

#[cfg(not(target_os = "none"))]
fn main() {}
