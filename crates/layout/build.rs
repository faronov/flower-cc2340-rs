//! Embed the bootloader trust anchors as raw P-256 `X || Y` constants.
//!
//! - `keys/ti-root-ec-p256.xy.hex`: MCUboot's public sample key
//!   `root-ec-p256.pem`, which TI's SDK and koptserg's MCUboot trust. Its
//!   private half is public too: the `migrate` channel offers no
//!   authenticity beyond what koptserg's bootloader already enforces.
//! - `keys/own-ec-p256.xy.hex`: the public half of this project's own
//!   signing key, trusted by `bootloader/`. Set `FLOWER_OWN_KEY_XY` to the
//!   path of another hex file to build for a different key (CI does this
//!   with an ephemeral key). The private key is never in the repository.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn read_xy(path: &Path) -> [u8; 64] {
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(
        digits.len(),
        128,
        "{} must hold 64 hex-encoded bytes (P-256 X || Y)",
        path.display()
    );
    let mut xy = [0u8; 64];
    for (index, byte) in xy.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * index..2 * index + 2], 16)
            .unwrap_or_else(|_| panic!("{} is not hex", path.display()));
    }
    xy
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let keys = manifest.join("../../keys");
    let ti = keys.join("ti-root-ec-p256.xy.hex");
    let own = env::var_os("FLOWER_OWN_KEY_XY")
        .map(PathBuf::from)
        .unwrap_or_else(|| keys.join("own-ec-p256.xy.hex"));

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("keys.rs");
    fs::write(
        &out,
        format!(
            "/// MCUboot sample key `root-ec-p256.pem` (TI SDK, koptserg MCUboot).\n\
             pub const TI_KEY_XY: [u8; 64] = {:?};\n\
             /// This project's own signing key (public half).\n\
             pub const OWN_KEY_XY: [u8; 64] = {:?};\n",
            read_xy(&ti),
            read_xy(&own)
        ),
    )
    .expect("write keys.rs");

    println!("cargo:rerun-if-env-changed=FLOWER_OWN_KEY_XY");
    println!("cargo:rerun-if-changed={}", ti.display());
    println!("cargo:rerun-if-changed={}", own.display());
}
