"""Host tests for tools/flower_ota.py (`python3 -m unittest discover tools`)."""

import re
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import flower_ota as ota  # noqa: E402

VECTORS = Path(__file__).resolve().parent.parent / "crates/product/tests/vectors"

# First 62 bytes (OTA header + Upgrade Image tag/length) of koptserg's
# BEBE-2340-24000013.zigbee and BABA-2340-24100013.zigbee, written by TI's
# zOTAfileGen.
KOPTSERG_24000013 = bytes.fromhex(
    "1ef1ee0b000138000000bebe4023130000240200000000000000000000000000"
    "00000000000000000000000000000000000000003ed80300000000d80300"
)
DIYZI_24100013 = bytes.fromhex(
    "1ef1ee0b000138000000baba4023130010240200000000000000000000000000"
    "00000000000000000000000000000000000000003ed80300000000d80300"
)


def padded(image: bytes) -> bytes:
    """What `imgtool sign --pad` adds: erased fill and the request magic."""
    return image.ljust(ota.SLOT_SIZE - 16, b"\xff") + ota.BOOT_MAGIC


class OtaFileTest(unittest.TestCase):
    def test_header_matches_zotafilegen(self):
        for prefix, manufacturer, version in (
            (KOPTSERG_24000013, 0xBEBE, 0x24000013),
            (DIYZI_24100013, 0xBABA, 0x24100013),
        ):
            image = b"\0" * ota.SLOT_SIZE
            data = ota.ota_file(image, manufacturer, ota.MIGRATE_IMAGE_TYPE, version)
            self.assertEqual(data[:62], prefix)
            self.assertEqual(len(data), 251_966)

    def test_round_trip(self):
        data = ota.ota_file(b"payload", 0x1234, 0x2341, 0x25020000, b"flower")
        header, image = ota.parse_ota_file(data)
        self.assertEqual(image, b"payload")
        self.assertEqual(
            header,
            ota.OtaHeader(0x1234, 0x2341, 0x25020000, len(data), b"flower"),
        )
        self.assertEqual(header.encode(), data[:ota.OTA_HEADER_LEN])

    def test_parse_rejects_damage(self):
        data = ota.ota_file(b"payload", 0x1234, 0x2341, 0x25020000)
        with self.assertRaisesRegex(ota.ToolError, "total size"):
            ota.parse_ota_file(data[:-1])
        with self.assertRaisesRegex(ota.ToolError, "magic"):
            ota.parse_ota_file(b"\0" + data[1:])
        no_image = struct.pack("<HI", 0x0001, 3) + b"abc"
        header = ota.OtaHeader(1, 2, 3, ota.OTA_HEADER_LEN + len(no_image)).encode()
        with self.assertRaisesRegex(ota.ToolError, "no Upgrade Image"):
            ota.parse_ota_file(header + no_image)
        with self.assertRaisesRegex(ota.ToolError, "32 bytes"):
            ota.ota_file(b"", 1, 2, 3, b"x" * 33)

    def test_file_version_is_newer_than_koptserg(self):
        self.assertEqual(ota.file_version(2, 0, 0), 0x25020000)
        self.assertEqual(ota.file_version(*ota.package_version()) >> 24, 0x25)
        for release in ota.KOPTSERG_LATEST.values():
            self.assertGreater(ota.file_version(0, 0, 0), release)


class ConstantsTest(unittest.TestCase):
    """The tool restates Rust constants; keep the two in sync."""

    @staticmethod
    def rust_constants(path: str) -> dict[str, int]:
        source = (Path(__file__).resolve().parent.parent / path).read_text()
        found = re.findall(r"^pub const ([A-Z_]+): u(?:8|16|32) = (0x[0-9A-Fa-f_]+);",
                           source, re.MULTILINE)
        return {name: int(value.replace("_", ""), 16) for name, value in found}

    def test_layout(self):
        layout = self.rust_constants("crates/layout/src/lib.rs")
        self.assertEqual(layout["LOADER_SIZE"], ota.LOADER_SIZE)
        self.assertEqual(layout["LOADER_SIZE"] - 32, ota.LOADER_INFO_ADDR)
        self.assertEqual(layout["PRIMARY_SLOT"], ota.PRIMARY_SLOT)
        self.assertEqual(layout["SLOT_SIZE"], ota.SLOT_SIZE)
        self.assertEqual(layout["SECTOR_SIZE"], ota.SECTOR_SIZE)
        self.assertEqual(layout["IMAGE_HEADER_SIZE"], ota.IMAGE_HEADER_SIZE)

    def test_identity(self):
        product = self.rust_constants("crates/product/src/ota.rs")
        self.assertEqual(product["OWN_MANUFACTURER_CODE"], ota.OWN_MANUFACTURER)
        self.assertEqual(product["KOPTSERG_MANUFACTURER_CODE"], ota.MANUFACTURERS["koptserg"])
        self.assertEqual(product["DIYZI_MANUFACTURER_CODE"], ota.MANUFACTURERS["diyzi"])
        self.assertEqual(product["MIGRATE_IMAGE_TYPE"], ota.MIGRATE_IMAGE_TYPE)
        self.assertEqual(product["OWN_IMAGE_TYPE_KOPTSERG"], ota.OWN_IMAGE_TYPES["koptserg"])
        self.assertEqual(product["OWN_IMAGE_TYPE_DIYZI"], ota.OWN_IMAGE_TYPES["diyzi"])
        self.assertEqual(product["FILE_VERSION_PREFIX"], ota.FILE_VERSION_PREFIX)


class McubootTest(unittest.TestCase):
    def test_vectors(self):
        image = (VECTORS / "test-v2.1.bin").read_bytes()
        parsed = ota.parse_mcuboot(image)
        self.assertTrue(parsed.sha256_ok)
        self.assertTrue(parsed.has_signature)
        self.assertEqual(parsed.version, (2, 1, 0, 0))
        self.assertEqual((parsed.hdr_size, parsed.img_size), (0x100, 2000))
        self.assertFalse(parsed.padded)
        self.assertTrue(ota.parse_mcuboot(padded(image)).padded)

        damaged = bytearray(image)
        damaged[0x180] ^= 1
        self.assertFalse(ota.parse_mcuboot(bytes(damaged)).sha256_ok)

    def test_check_channel_rules(self):
        own = (VECTORS / "test-v2.1.bin").read_bytes()
        ti = padded((VECTORS / "ti-v2.1.bin").read_bytes())
        version = ota.file_version(2, 1, 0)

        summary = ota.check(ota.ota_file(own, 0x1234, 0x2342, version), "diyzi")
        self.assertTrue(summary.startswith("own/diyzi"))
        summary = ota.check(ota.ota_file(ti, 0xBEBE, 0x2340, version))
        self.assertTrue(summary.startswith("migrate/koptserg"))

        cases = [
            # koptserg's MCUboot needs the magic in the image itself.
            (ota.ota_file(own, 0xBEBE, 0x2340, version), "padded"),
            (ota.ota_file(ti, 0xBEBE, 0x2340, 0x24000013), "not newer"),
            (ota.ota_file(ti, 0x1111, 0x2340, version), "manufacturer"),
            (ota.ota_file(own, 0x1234, 0x2399, version), "unknown identity"),
            (ota.ota_file(own, 0x1234, 0x2342, ota.file_version(2, 0, 0)), "does not match"),
            (ota.ota_file(own, 0x1234, 0x2341, version), "expected diyzi"),
        ]
        for data, message in cases:
            with self.subTest(message):
                with self.assertRaisesRegex(ota.ToolError, message):
                    ota.check(data, "diyzi")


class HexTest(unittest.TestCase):
    def loader(self) -> bytes:
        loader = bytearray(b"\xa5" * ota.LOADER_SIZE)
        loader[ota.LOADER_INFO_ADDR:ota.LOADER_INFO_ADDR + 8] = ota.LOADER_INFO_MAGIC
        return bytes(loader)

    def test_full_flash_round_trip(self):
        image = (VECTORS / "test-v2.bin").read_bytes()
        text = ota.full_flash_hex(self.loader(), image)
        memory = ota.parse_intel_hex(text)
        end = ota.parse_mcuboot(image).end
        self.assertEqual(len(memory), ota.LOADER_SIZE + end)
        self.assertEqual(bytes(memory[a] for a in range(ota.LOADER_SIZE)), self.loader())
        self.assertEqual(
            bytes(memory[ota.PRIMARY_SLOT + a] for a in range(end)), image[:end]
        )
        self.assertNotIn(ota.SLOT_SIZE + ota.PRIMARY_SLOT, memory)

    def test_crosses_64k_with_extended_address(self):
        data = bytes(range(256)) * 2
        memory = ota.parse_intel_hex(ota.intel_hex([(0xFF00, data)]))
        self.assertEqual(bytes(memory[0xFF00 + i] for i in range(len(data))), data)
        self.assertIn(":020000040001F9", ota.intel_hex([(0xFF00, data)]))

    def test_rejects_wrong_inputs(self):
        image = (VECTORS / "test-v2.bin").read_bytes()
        with self.assertRaisesRegex(ota.ToolError, "LoaderInfo"):
            ota.full_flash_hex(b"\xff" * ota.LOADER_SIZE, image)
        with self.assertRaisesRegex(ota.ToolError, "expected"):
            ota.full_flash_hex(self.loader()[:-1], image)
        with self.assertRaisesRegex(ota.ToolError, "unpadded"):
            ota.full_flash_hex(self.loader(), padded(image))


if __name__ == "__main__":
    unittest.main()
