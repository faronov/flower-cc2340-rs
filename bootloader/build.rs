//! Put the bootloader's `memory.x` on the linker search path.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let script = manifest_dir.join("memory.x");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::copy(&script, out.join("memory.x")).expect("copy memory.x to OUT_DIR");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        println!("cargo:rustc-link-search={}", out.display());
        println!("cargo:rustc-link-arg=-Tlink.x");
    }
    println!("cargo:rerun-if-changed={}", script.display());
}
