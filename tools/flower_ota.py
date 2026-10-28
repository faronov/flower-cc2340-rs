#!/usr/bin/env python3
"""Release tooling for the flower firmware: MCUboot signing, Zigbee OTA
files, and full-flash images.

Subcommands
-----------
release   firmware ELF/binary -> signed MCUboot images and .zigbee files
          for the selected OTA channels, plus a loader+application Intel
          HEX for the `own` channel.
ota-file  Wrap one signed MCUboot image into a Zigbee OTA Upgrade file.
check     Parse and validate .zigbee files (header, element, MCUboot
          header, SHA-256 TLV, request magic, channel rules).
hex       Combine a loader binary and a signed image into an Intel HEX.

Channels (see crates/product/src/ota.rs):

  migrate  koptserg's MCUboot. Signed with MCUboot's public sample key
           root-ec-p256.pem (TI SDK), padded with the upgrade request magic
           like koptserg's own releases, manufacturer 0xBEBE (koptserg
           build) or 0xBABA (DIYZi build), image type 0x2340.
  own      bootloader/ of this repository. Signed with the project's own
           key (never committed), unpadded, manufacturer 0x1234, image type
           0x2341 (koptserg build) or 0x2342 (DIYZi build).

Needs only the Python standard library, plus `imgtool` (MCUboot's signing
tool, `pip install imgtool`) and `rust-objcopy` for `release`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# crates/layout/src/lib.rs
LOADER_SIZE = 0x4000
LOADER_INFO_ADDR = 0x3FE0
PRIMARY_SLOT = 0x4000
SLOT_SIZE = 0x3D800
SECTOR_SIZE = 0x800
IMAGE_HEADER_SIZE = 0x100
MAX_IMAGE_LEN = SLOT_SIZE - SECTOR_SIZE  # the last sector holds the trailer

# crates/product/src/ota.rs
OWN_MANUFACTURER = 0x1234
MANUFACTURERS = {"koptserg": 0xBEBE, "diyzi": 0xBABA}
MIGRATE_IMAGE_TYPE = 0x2340
OWN_IMAGE_TYPES = {"koptserg": 0x2341, "diyzi": 0x2342}
FILE_VERSION_PREFIX = 0x25
KOPTSERG_LATEST = {"koptserg": 0x24000013, "diyzi": 0x24100013}

# Zigbee OTA Upgrade file (ZCL OTA Upgrade cluster specification, 11.4).
OTA_MAGIC = 0x0BEEF11E
OTA_HEADER_VERSION = 0x0100
OTA_HEADER_LEN = 56
OTA_HEADER_FORMAT = "<IHHHHHIH32sI"
OTA_STACK_ZIGBEE_PRO = 0x0002
OTA_TAG_UPGRADE_IMAGE = 0x0000

# MCUboot image format (bootutil/image.h, bootutil_priv.h).
IMAGE_MAGIC = 0x96F3B83D
TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908
TLV_SHA256 = 0x10
TLV_ECDSA_SIG = 0x22
BOOT_MAGIC = bytes.fromhex("77c295f360d2ef7f3552500f2cb67980")
LOADER_INFO_MAGIC = b"ZRSBOOT1"


class ToolError(Exception):
    pass


# ── Versions ────────────────────────────────────────────────────────────


def package_version(manifest: Path = REPO / "Cargo.toml") -> tuple[int, int, int]:
    """The workspace version, which is the firmware version."""
    text = tomllib.loads(manifest.read_text())["workspace"]["package"]["version"]
    parts = tuple(int(part) for part in text.split("-")[0].split("."))
    if len(parts) != 3 or not all(0 <= part <= 0xFF for part in parts):
        raise ToolError(f"version {text} must be MAJOR.MINOR.PATCH with byte-sized parts")
    return parts  # type: ignore[return-value]


def file_version(major: int, minor: int, patch: int) -> int:
    """`0x25MMmmpp`: newer than every koptserg release (`0x240x00yy`)."""
    return FILE_VERSION_PREFIX << 24 | major << 16 | minor << 8 | patch


# ── Zigbee OTA file ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class OtaHeader:
    manufacturer: int
    image_type: int
    file_version: int
    total_size: int
    header_string: bytes = b""
    stack_version: int = OTA_STACK_ZIGBEE_PRO
    field_control: int = 0

    def encode(self) -> bytes:
        if self.field_control != 0:
            raise ToolError("optional OTA header fields are not supported")
        if len(self.header_string) > 32:
            raise ToolError("OTA header string longer than 32 bytes")
        return struct.pack(
            OTA_HEADER_FORMAT,
            OTA_MAGIC,
            OTA_HEADER_VERSION,
            OTA_HEADER_LEN,
            self.field_control,
            self.manufacturer,
            self.image_type,
            self.file_version,
            self.stack_version,
            self.header_string.ljust(32, b"\0"),
            self.total_size,
        )

    @classmethod
    def decode(cls, data: bytes) -> "OtaHeader":
        if len(data) < OTA_HEADER_LEN:
            raise ToolError("file shorter than an OTA header")
        (magic, version, length, control, manufacturer, image_type, fversion, stack,
         string, total) = struct.unpack_from(OTA_HEADER_FORMAT, data)
        if magic != OTA_MAGIC:
            raise ToolError(f"bad OTA magic 0x{magic:08X}")
        if version != OTA_HEADER_VERSION:
            raise ToolError(f"unsupported OTA header version 0x{version:04X}")
        if control != 0 or length != OTA_HEADER_LEN:
            raise ToolError(
                f"optional OTA header fields (control 0x{control:04X}, length {length}) "
                "are not produced by this tool"
            )
        return cls(manufacturer, image_type, fversion, total, string.rstrip(b"\0"), stack,
                   control)


def ota_file(image: bytes, manufacturer: int, image_type: int, version: int,
             header_string: bytes = b"") -> bytes:
    """A file with a single Upgrade Image (tag 0) element holding `image`."""
    element = struct.pack("<HI", OTA_TAG_UPGRADE_IMAGE, len(image)) + image
    header = OtaHeader(manufacturer, image_type, version, OTA_HEADER_LEN + len(element),
                       header_string)
    return header.encode() + element


def parse_ota_file(data: bytes) -> tuple[OtaHeader, bytes]:
    """The header and the Upgrade Image payload."""
    header = OtaHeader.decode(data)
    if header.total_size != len(data):
        raise ToolError(f"total size {header.total_size} != file size {len(data)}")
    offset = OTA_HEADER_LEN
    image = None
    while offset < len(data):
        if offset + 6 > len(data):
            raise ToolError("truncated sub-element header")
        tag, length = struct.unpack_from("<HI", data, offset)
        offset += 6
        if offset + length > len(data):
            raise ToolError(f"sub-element 0x{tag:04X} overruns the file")
        if tag == OTA_TAG_UPGRADE_IMAGE:
            if image is not None:
                raise ToolError("more than one Upgrade Image element")
            image = data[offset:offset + length]
        offset += length
    if image is None:
        raise ToolError("no Upgrade Image element")
    return header, image


# ── MCUboot image ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class McubootImage:
    hdr_size: int
    img_size: int
    version: tuple[int, int, int, int]
    sha256_ok: bool
    has_signature: bool
    end: int
    padded: bool


def parse_mcuboot(image: bytes) -> McubootImage:
    """Structure and SHA-256 check (signatures are checked by the Rust
    tests and on the device; here only their presence)."""
    if len(image) < 32:
        raise ToolError("image shorter than an MCUboot header")
    magic, _load, hdr_size, protect, img_size, _flags, major, minor, rev, build = \
        struct.unpack_from("<IIHHIIBBHI", image)
    if magic != IMAGE_MAGIC:
        raise ToolError(f"bad MCUboot magic 0x{magic:08X}")
    offset = hdr_size + img_size
    if offset + 4 > len(image):
        raise ToolError("image body overruns the payload")
    if protect:
        info_magic, info_len = struct.unpack_from("<HH", image, offset)
        if info_magic != TLV_PROT_INFO_MAGIC or info_len != protect:
            raise ToolError("bad protected TLV area")
        offset += protect
    hashed = image[:offset]
    info_magic, info_len = struct.unpack_from("<HH", image, offset)
    if info_magic != TLV_INFO_MAGIC:
        raise ToolError(f"bad TLV info magic 0x{info_magic:04X}")
    end = offset + info_len
    if end > len(image):
        raise ToolError("TLV area overruns the payload")
    cursor = offset + 4
    digest = None
    signature = False
    while cursor + 4 <= end:
        tlv_type, tlv_len = struct.unpack_from("<BxH", image, cursor)
        value = image[cursor + 4:cursor + 4 + tlv_len]
        if tlv_type == TLV_SHA256:
            digest = value
        elif tlv_type == TLV_ECDSA_SIG:
            signature = True
        cursor += 4 + tlv_len
    if digest is None:
        raise ToolError("no SHA-256 TLV")
    padded = len(image) == SLOT_SIZE and image[-len(BOOT_MAGIC):] == BOOT_MAGIC
    return McubootImage(hdr_size, img_size, (major, minor, rev, build),
                        hashlib.sha256(hashed).digest() == digest, signature, end, padded)


def check(data: bytes, expect_variant: str | None = None) -> str:
    """Validate a .zigbee file; returns a one-line summary."""
    header, image = parse_ota_file(data)
    mcuboot = parse_mcuboot(image)
    if not mcuboot.sha256_ok:
        raise ToolError("SHA-256 TLV does not match the image")
    if not mcuboot.has_signature:
        raise ToolError("image carries no ECDSA P-256 signature")
    if mcuboot.hdr_size != IMAGE_HEADER_SIZE:
        raise ToolError(f"header size 0x{mcuboot.hdr_size:X} != 0x{IMAGE_HEADER_SIZE:X}")
    if len(image) > SLOT_SIZE or mcuboot.end > MAX_IMAGE_LEN:
        raise ToolError("image does not fit the slot")

    if header.image_type == MIGRATE_IMAGE_TYPE:
        channel = "migrate"
        variants = [v for v, m in MANUFACTURERS.items() if m == header.manufacturer]
        if not variants:
            raise ToolError(f"migrate image with manufacturer 0x{header.manufacturer:04X}")
        variant = variants[0]
        if header.file_version <= KOPTSERG_LATEST[variant]:
            raise ToolError(
                f"file version 0x{header.file_version:08X} is not newer than koptserg's "
                f"0x{KOPTSERG_LATEST[variant]:08X}"
            )
        if not mcuboot.padded:
            raise ToolError("migrate images must be padded: koptserg's OTA client "
                            "writes no upgrade request magic of its own")
    else:
        channel = "own"
        variants = [v for v, t in OWN_IMAGE_TYPES.items() if t == header.image_type]
        if header.manufacturer != OWN_MANUFACTURER or not variants:
            raise ToolError(
                f"unknown identity 0x{header.manufacturer:04X}/0x{header.image_type:04X}"
            )
        variant = variants[0]
    if expect_variant is not None and variant != expect_variant:
        raise ToolError(f"{variant} image, expected {expect_variant}")
    major, minor, rev, _build = mcuboot.version
    if rev > 0xFF or file_version(major, minor, rev) != header.file_version:
        raise ToolError("OTA file version does not match the MCUboot image version")
    return (
        f"{channel}/{variant}: manufacturer 0x{header.manufacturer:04X} image type "
        f"0x{header.image_type:04X} file version 0x{header.file_version:08X} image "
        f"{major}.{minor}.{rev} {len(image)} B{' padded' if mcuboot.padded else ''}"
    )


# ── Intel HEX ───────────────────────────────────────────────────────────


def intel_hex(segments: list[tuple[int, bytes]]) -> str:
    lines = []

    def record(kind: int, address: int, payload: bytes) -> None:
        raw = bytes([len(payload), address >> 8 & 0xFF, address & 0xFF, kind]) + payload
        lines.append(":" + (raw + bytes([-sum(raw) & 0xFF])).hex().upper())

    upper = None
    for base, data in sorted(segments):
        for offset in range(0, len(data), 16):
            address = base + offset
            chunk = data[offset:offset + 16]
            if address >> 16 != (address + len(chunk) - 1) >> 16:
                raise ToolError("segments must be 16-byte aligned")
            if address >> 16 != upper:
                upper = address >> 16
                record(4, 0, struct.pack(">H", upper))
            record(0, address & 0xFFFF, chunk)
    record(1, 0, b"")
    return "\n".join(lines) + "\n"


def parse_intel_hex(text: str) -> dict[int, int]:
    memory: dict[int, int] = {}
    upper = 0
    for line in text.splitlines():
        raw = bytes.fromhex(line[1:])
        if not line.startswith(":") or sum(raw) & 0xFF or raw[0] + 5 != len(raw):
            raise ToolError(f"bad HEX record {line}")
        length, kind = raw[0], raw[3]
        address = raw[1] << 8 | raw[2]
        payload = raw[4:4 + length]
        if kind == 0:
            for index, byte in enumerate(payload):
                memory[(upper << 16) + address + index] = byte
        elif kind == 4:
            upper = struct.unpack(">H", payload)[0]
        elif kind == 1:
            break
    return memory


def loader_key_id(loader: bytes) -> bytes:
    """First 8 bytes of the trusted key's X (mcuboot-image LoaderInfo)."""
    return loader[LOADER_INFO_ADDR + 16:LOADER_INFO_ADDR + 24]


def full_flash_hex(loader: bytes, signed_app: bytes) -> str:
    """Loader at 0x0 plus a signed image in the primary slot. The secondary
    slot, persistent data and CCFG are left untouched."""
    if len(loader) != LOADER_SIZE:
        raise ToolError(f"loader binary is {len(loader)} B, expected {LOADER_SIZE}")
    if loader[LOADER_INFO_ADDR:LOADER_INFO_ADDR + 8] != LOADER_INFO_MAGIC:
        raise ToolError(f"loader binary carries no LoaderInfo record at 0x{LOADER_INFO_ADDR:X}")
    image = parse_mcuboot(signed_app)
    if image.padded or image.end > MAX_IMAGE_LEN:
        raise ToolError("full-flash images must be unpadded and fit the primary slot")
    return intel_hex([(0, loader), (PRIMARY_SLOT, signed_app[:image.end])])


# ── External tools ──────────────────────────────────────────────────────


def find_tool(name: str, override: str | None) -> str:
    path = override or shutil.which(name)
    if not path:
        raise ToolError(f"{name} not found (pass --{name.split('-')[-1]})")
    return path


def elf_to_bin(objcopy: str, elf: Path, out: Path) -> bytes:
    subprocess.run([objcopy, "--gap-fill", "0xff", "-O", "binary", str(elf), str(out)],
                   check=True)
    return out.read_bytes()


def imgtool_sign(imgtool: str, key: Path, version: str, payload: Path, out: Path,
                 pad: bool) -> bytes:
    command = [
        imgtool, "sign",
        "--header-size", hex(IMAGE_HEADER_SIZE), "--pad-header",
        "--align", "4",
        "--slot-size", hex(SLOT_SIZE),
        "--version", version,
        "--key", str(key),
    ]
    if pad:
        command.append("--pad")
    subprocess.run(command + [str(payload), str(out)], check=True,
                   stdout=subprocess.DEVNULL)
    return out.read_bytes()


def imgtool_public_xy(imgtool: str, key: Path) -> bytes:
    """Raw X || Y of `key`. `imgtool getpub --encoding raw` prints the DER
    SubjectPublicKeyInfo, which ends with the uncompressed point."""
    result = subprocess.run([imgtool, "getpub", "--key", str(key), "--encoding", "raw"],
                            check=True, capture_output=True)
    der = result.stdout
    if len(der) != 91 or der[-65] != 0x04:
        raise ToolError(f"{key} is not a P-256 key ({len(der)}-byte public key)")
    return der[-64:]


# ── Commands ────────────────────────────────────────────────────────────


def default_ti_key() -> Path | None:
    candidates = [os.environ.get("FLOWER_TI_KEY")]
    if os.environ.get("CC2340_SDK_DIR"):
        candidates.append(os.path.join(os.environ["CC2340_SDK_DIR"],
                                       "source/third_party/mcuboot/root-ec-p256.pem"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def cmd_release(args: argparse.Namespace) -> None:
    imgtool = find_tool("imgtool", args.imgtool)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    major, minor, patch = package_version()
    version = f"{major}.{minor}.{patch}"
    fversion = file_version(major, minor, patch)
    variant = args.variant
    stem = f"flower-{variant}-{version}"

    with tempfile.TemporaryDirectory() as scratch:
        if args.app_bin:
            payload = Path(args.app_bin)
        else:
            payload = Path(scratch) / "app.bin"
            elf_to_bin(find_tool("rust-objcopy", args.objcopy), Path(args.app_elf), payload)
        unsigned = payload.read_bytes()
        if IMAGE_HEADER_SIZE + len(unsigned) > MAX_IMAGE_LEN:
            raise ToolError("application binary does not fit the slot")
        (out / f"{stem}-unsigned.bin").write_bytes(unsigned)

        for channel in args.channels.split(","):
            if channel == "migrate":
                key = Path(args.ti_key) if args.ti_key else default_ti_key()
                if key is None:
                    raise ToolError("migrate: pass --ti-key or set CC2340_SDK_DIR")
                manufacturer, image_type, pad = MANUFACTURERS[variant], MIGRATE_IMAGE_TYPE, True
            elif channel == "own":
                if not args.own_key:
                    raise ToolError("own: pass --own-key or set FLOWER_OWN_KEY")
                key = Path(args.own_key)
                manufacturer, image_type, pad = OWN_MANUFACTURER, OWN_IMAGE_TYPES[variant], False
                if args.loader_bin and (loader_key_id(Path(args.loader_bin).read_bytes())
                                        != imgtool_public_xy(imgtool, key)[:8]):
                    raise ToolError("the loader binary trusts another key than --own-key")
            else:
                raise ToolError(f"unknown channel {channel}")
            signed = imgtool_sign(imgtool, key, version, payload,
                                  out / f"{stem}-{channel}-signed.bin", pad)
            name = f"{manufacturer:04X}-{image_type:04X}-{fversion:08X}-{stem}-{channel}.zigbee"
            data = ota_file(signed, manufacturer, image_type, fversion,
                            f"flower {variant} {channel} {version}".encode())
            (out / name).write_bytes(data)
            print(f"{name}: {check(data, variant)}")

            if channel == "own" and args.loader_bin:
                loader = Path(args.loader_bin).read_bytes()
                hex_name = f"{stem}-own-full.hex"
                (out / hex_name).write_text(full_flash_hex(loader, signed))
                print(f"{hex_name}: loader at 0x0, signed image at 0x{PRIMARY_SLOT:X}")


def cmd_ota_file(args: argparse.Namespace) -> None:
    data = ota_file(Path(args.input).read_bytes(), int(args.manufacturer, 0),
                    int(args.image_type, 0), int(args.file_version, 0),
                    args.header_string.encode())
    Path(args.output).write_bytes(data)
    print(f"{args.output}: {len(data)} B")


def cmd_check(args: argparse.Namespace) -> None:
    failed = False
    for name in args.files:
        try:
            print(f"{name}: {check(Path(name).read_bytes(), args.variant)}")
        except ToolError as error:
            print(f"{name}: INVALID: {error}", file=sys.stderr)
            failed = True
    if failed:
        sys.exit(1)


def cmd_hex(args: argparse.Namespace) -> None:
    Path(args.output).write_text(
        full_flash_hex(Path(args.loader).read_bytes(), Path(args.app).read_bytes())
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Sign, package and check flower firmware images.")
    sub = parser.add_subparsers(dest="command", required=True)

    release = sub.add_parser("release", help="sign and package one calibration variant")
    source = release.add_mutually_exclusive_group(required=True)
    source.add_argument("--app-elf", help="firmware ELF (converted with rust-objcopy)")
    source.add_argument("--app-bin", help="firmware binary starting at 0x4100")
    release.add_argument("--variant", choices=sorted(MANUFACTURERS), required=True)
    release.add_argument("--channels", default="migrate,own")
    release.add_argument("--ti-key", help="root-ec-p256.pem (default: $FLOWER_TI_KEY or "
                         "$CC2340_SDK_DIR/source/third_party/mcuboot/root-ec-p256.pem)")
    release.add_argument("--own-key", default=os.environ.get("FLOWER_OWN_KEY"),
                         help="private key of the own channel (default: $FLOWER_OWN_KEY)")
    release.add_argument("--loader-bin",
                         help="bootloader binary (rust-objcopy --gap-fill 0xff -O binary) "
                              "for the full-flash HEX")
    release.add_argument("--imgtool")
    release.add_argument("--objcopy")
    release.add_argument("--out", default="dist")
    release.set_defaults(func=cmd_release)

    ota = sub.add_parser("ota-file", help="wrap a signed image into a .zigbee file")
    ota.add_argument("input")
    ota.add_argument("output")
    ota.add_argument("--manufacturer", required=True)
    ota.add_argument("--image-type", required=True)
    ota.add_argument("--file-version", required=True)
    ota.add_argument("--header-string", default="")
    ota.set_defaults(func=cmd_ota_file)

    checker = sub.add_parser("check", help="validate .zigbee files")
    checker.add_argument("files", nargs="+")
    checker.add_argument("--variant", choices=sorted(MANUFACTURERS))
    checker.set_defaults(func=cmd_check)

    combined = sub.add_parser("hex", help="loader + signed image as Intel HEX")
    combined.add_argument("--loader", required=True)
    combined.add_argument("--app", required=True)
    combined.add_argument("--output", required=True)
    combined.set_defaults(func=cmd_hex)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (ToolError, subprocess.CalledProcessError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
