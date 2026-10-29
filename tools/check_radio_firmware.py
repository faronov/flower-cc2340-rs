#!/usr/bin/env python3
"""Check that a firmware ELF embeds the CC2340R5 radio images of a TI SDK.

The release builds compile log strings out, so the image content itself is
the marker: 32 words of the PBE, MCE and RFE arrays from
`source/ti/devices/cc23x0r5/rf_patches`, as little-endian bytes. The first
word (the image header) is skipped: the compiler may emit it apart from the
rest of the array.
"""

import argparse
import re
import struct
import sys
from pathlib import Path

IMAGES = {
    "lrf_pbe_binary_ieee_cc23x0r5.c": "LRF_PBE_binary_ieee",
    "lrf_mce_binary_ieee_cc23x0r5.c": "LRF_MCE_binary_ieee",
    "lrf_rfe_binary_ieee_cc23x0r5.c": "LRF_RFE_binary_ieee",
}
PREFIX_WORDS = 32


def image_prefix(source: str, symbol: str) -> bytes:
    start = source.index(symbol)
    body = source[source.index("{", start) + 1 : source.index("}", start)]
    words = [int(word, 16) for word in re.findall(r"0[xX]([0-9A-Fa-f]+)", body)]
    words = words[1 : 1 + PREFIX_WORDS]
    return struct.pack(f"<{len(words)}I", *words)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdk_dir", type=Path)
    parser.add_argument("elf", type=Path, nargs="+")
    args = parser.parse_args()

    patches = args.sdk_dir / "source/ti/devices/cc23x0r5/rf_patches"
    prefixes = {
        symbol: image_prefix((patches / name).read_text(), symbol)
        for name, symbol in IMAGES.items()
    }
    failed = False
    for elf in args.elf:
        data = elf.read_bytes()
        missing = [symbol for symbol, prefix in prefixes.items() if prefix not in data]
        if missing:
            print(f"{elf}: missing SDK radio images {', '.join(missing)}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
