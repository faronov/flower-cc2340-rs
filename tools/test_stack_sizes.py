"""Host tests for tools/stack_sizes.py (`python3 -m unittest discover tools`)."""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import stack_sizes as ss  # noqa: E402


def tiny_elf(symbols: list[tuple[str, int, int]], records: list[tuple[int, int]]) -> bytes:
    """A minimal 32-bit LE ELF with .symtab/.strtab/.stack_sizes sections.

    `symbols` are (name, value, type) entries; `records` are (address,
    frame) pairs encoded as `.stack_sizes` does (u32 + ULEB128).
    """
    strtab = b"\0"
    symtab = b"\0" * 16
    for name, value, kind in symbols:
        offset = len(strtab)
        strtab += name.encode() + b"\0"
        symtab += struct.pack("<IIIBBH", offset, value, 0, kind, 0, 1)
    sizes = b""
    for address, frame in records:
        sizes += struct.pack("<I", address)
        while True:
            byte = frame & 0x7F
            frame >>= 7
            sizes += bytes([byte | (0x80 if frame else 0)])
            if not frame:
                break
    names = [b"", b".symtab", b".strtab", b".stack_sizes", b".shstrtab"]
    shstrtab = b"\0".join(names) + b"\0"
    name_offsets = []
    cursor = 0
    for name in names:
        name_offsets.append(cursor)
        cursor += len(name) + 1
    bodies = [b"", symtab, strtab, sizes, shstrtab]
    offset = 0x34
    layout = []
    blob = b""
    for body in bodies:
        layout.append((offset + len(blob), len(body)))
        blob += body
    shoff = 0x34 + len(blob)
    header = b"\x7fELF" + bytes([1, 1, 1]) + b"\0" * 9
    header += struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, 0, 0, shoff, 0, 0x34, 0, 0, 40, 5, 4)
    sections = b""
    kinds = [0, 2, 3, 1, 3]
    for index, (start, size) in enumerate(layout):
        link = 2 if index == 1 else 0
        entsize = 16 if index == 1 else 0
        sections += struct.pack(
            "<IIIIIIIIII", name_offsets[index], kinds[index], 0, 0, start, size, link, 0, 1, entsize
        )
    return header + blob + sections


class ParserTest(unittest.TestCase):
    def test_reads_frames_symbols_and_stack_region(self):
        main = "_RNCNvCsib7oOTT1u4j_13cc2340_flower21_____embassy_main_task0B3_"
        data = tiny_elf(
            [
                (main, 0x4101, 2),
                ("_ZN4core3fmt5write17h0123456789abcdefE", 0x4201, 2),
                ("_stack_start", 0x20009000, 0),
                ("_stack_end", 0x20004B44, 0),
            ],
            [(0x4101, 840), (0x4201, 200)],
        )
        self.assertEqual(ss.stack_sizes(data), [(0x4100, 840), (0x4200, 200)])
        names = ss.function_symbols(data)
        self.assertEqual(ss.demangle(names[0x4100][0]), "cc2340_flower::____embassy_main_task")
        self.assertEqual(ss.demangle(names[0x4200][0]), "core::fmt::write")
        self.assertEqual(ss.stack_region(data), 0x9000 - 0x4B44)

        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "fw.elf"
            elf.write_bytes(data)
            frames, main_frame = ss.report(elf, 0)
        self.assertEqual(main_frame, 840)
        self.assertEqual(len(frames), 2)

    def test_multi_byte_uleb128(self):
        data = tiny_elf([("f", 0x101, 2)], [(0x101, 10_776)])
        self.assertEqual(ss.stack_sizes(data), [(0x100, 10_776)])

    def test_rejects_build_without_stack_sizes(self):
        data = tiny_elf([("f", 0x101, 2)], [])
        stripped = data.replace(b".stack_sizes", b".other_sizes")
        with self.assertRaises(ss.ElfError):
            ss.stack_sizes(stripped)

    def test_v0_identifiers_skip_hashes_backrefs_and_consts(self):
        name = (
            "_RNvMs0_NtCsfBvXfw2GEHr_14zigbee_runtime16security_journal"
            "INtB5_20SecurityStateJournalINtNtCsiwMYmzj0MnT_21cc2340_flower_product"
            "7storage11FlashWindowKm7f000_Kj1000_EKj800_E19ensure_replay_cache"
        )
        self.assertEqual(
            ss.demangle(name),
            "zigbee_runtime::security_journal::SecurityStateJournal::"
            "cc2340_flower_product::storage::FlashWindow::ensure_replay_cache",
        )


class ChainTest(unittest.TestCase):
    GRAPH = {1: {2, 3}, 2: {4}, 3: {4, 1}, 4: set(), 5: {6}, 6: set()}
    FRAMES = {1: 100, 2: 500, 3: 50, 4: 1000, 5: 10, 6: 10}

    def test_deepest_chain_follows_the_largest_sum_and_cuts_recursion(self):
        self.assertEqual(ss.deepest_chain(1, self.GRAPH, self.FRAMES), (1600, [1, 2, 4]))

    def test_through_restricts_to_chains_reaching_a_function(self):
        self.assertEqual(ss.deepest_chain(1, self.GRAPH, self.FRAMES, {3}), (1150, [1, 3, 4]))
        self.assertEqual(ss.deepest_chain(1, self.GRAPH, self.FRAMES, {6})[0], -1)


if __name__ == "__main__":
    unittest.main()
