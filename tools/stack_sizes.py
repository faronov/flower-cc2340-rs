#!/usr/bin/env python3
"""Report and gate per-function stack frames of the flower firmware.

Build the firmware with LLVM's stack-size section, then run this on the
ELF:

    cd firmware
    RUSTFLAGS="-Z emit-stack-sizes" cargo build --release --locked \\
        --target-dir ../target/stack-sizes
    python3 ../tools/stack_sizes.py \\
        ../target/stack-sizes/thumbv6m-none-eabi/release/cc2340-flower \\
        --max-main-frame 1536

`.stack_sizes` holds one (function address, frame bytes) pair per function
(32-bit address, ULEB128 size). These are *frame* sizes, not call-chain
depths: the worst-case stack is the sum along the deepest call chain,
which this tool does not compute. The gate exists because the Embassy
main task's poll frame sits at the bottom of every call chain, so
temporaries that the compiler keeps there are paid on every path (a
10.7 KB frame overflowed the stack into .bss during the first join).

Only the Python standard library is used (no pyelftools).
"""

from __future__ import annotations

import argparse
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

# The Embassy main task's poll function (`#[embassy_executor::main]`).
MAIN_TASK_PATTERN = "embassy_main_task"


class ElfError(Exception):
    pass


def _sections(data: bytes) -> dict[str, tuple[int, int, int, int, int]]:
    """Section name -> (type, offset, size, link, entsize) of a 32-bit LE ELF."""
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ElfError("not a 32-bit little-endian ELF")
    (shoff,) = struct.unpack_from("<I", data, 0x20)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    headers = []
    for index in range(shnum):
        name, kind, _flags, _addr, offset, size, link, _info, _align, entsize = (
            struct.unpack_from("<IIIIIIIIII", data, shoff + index * shentsize)
        )
        headers.append((name, kind, offset, size, link, entsize))
    strtab_offset = headers[shstrndx][2]
    result = {}
    for name, kind, offset, size, link, entsize in headers:
        end = data.index(b"\0", strtab_offset + name)
        label = data[strtab_offset + name : end].decode()
        result.setdefault(label, (kind, offset, size, link, entsize))
    return result


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, offset


def function_symbols(data: bytes) -> dict[int, list[str]]:
    """Thumb function address (bit 0 cleared) -> symbol names."""
    sections = _sections(data)
    if ".symtab" not in sections or ".strtab" not in sections:
        raise ElfError("no symbol table (stripped ELF?)")
    _, sym_offset, sym_size, _, sym_entsize = sections[".symtab"]
    _, str_offset, _, _, _ = sections[".strtab"]
    names: dict[int, list[str]] = {}
    for entry in range(sym_offset, sym_offset + sym_size, sym_entsize or 16):
        name, value, _size, info, _other, _shndx = struct.unpack_from("<IIIBBH", data, entry)
        if info & 0xF != 2:  # STT_FUNC
            continue
        end = data.index(b"\0", str_offset + name)
        label = data[str_offset + name : end].decode(errors="replace")
        names.setdefault(value & ~1, []).append(label)
    return names


def stack_sizes(data: bytes) -> list[tuple[int, int]]:
    """(function address, frame bytes) records from `.stack_sizes`."""
    sections = _sections(data)
    if ".stack_sizes" not in sections:
        raise ElfError('no .stack_sizes section: build with RUSTFLAGS="-Z emit-stack-sizes"')
    _, offset, size, _, _ = sections[".stack_sizes"]
    records = []
    cursor = offset
    while cursor < offset + size:
        (address,) = struct.unpack_from("<I", data, cursor)
        frame, cursor = _uleb128(data, cursor + 4)
        records.append((address & ~1, frame))
    return records


def _v0_identifiers(name: str) -> list[str]:
    """Identifiers of a v0 (`_R…`) Rust symbol, in order.

    Not a full demangler: it walks the mangled string, consumes each
    length-prefixed identifier whole, and skips crate hashes (`Cs…_`),
    disambiguators (`s…_`), back references (`B…_`) and const generics
    (`K…_`). Good enough to label a frame report.
    """
    out = []
    cursor = 2
    while cursor < len(name):
        char = name[cursor]
        if char.isdigit():
            end = cursor
            while end < len(name) and name[end].isdigit():
                end += 1
            length = int(name[cursor:end])
            if end < len(name) and name[end] == "_":
                end += 1
            if length:
                out.append(name[end : end + length])
            cursor = end + length
        elif char in "sB":
            cursor = name.find("_", cursor) + 1 or len(name)
        elif char == "K":
            cursor = (cursor + 2) if name[cursor + 1 : cursor + 2] == "p" else (
                name.find("_", cursor) + 1 or len(name)
            )
        else:
            cursor += 1
    return out


def demangle(name: str) -> str:
    """Readable label for a Rust symbol (legacy `_ZN…E` or v0 `_R…`)."""
    if name.startswith("_R"):
        return "::".join(_v0_identifiers(name))
    if not name.startswith("_ZN") or not name.endswith("E"):
        return name
    parts = []
    cursor = 3
    body = name[:-1]
    while cursor < len(body) and body[cursor].isdigit():
        end = cursor
        while body[end].isdigit():
            end += 1
        length = int(body[cursor:end])
        parts.append(body[end : end + length])
        cursor = end + length
    if parts and parts[-1].startswith("h") and len(parts[-1]) == 17:
        parts.pop()
    return "::".join(parts)


def stack_region(data: bytes) -> int | None:
    """Bytes between the end of static RAM and the initial stack pointer."""
    sections = _sections(data)
    _, sym_offset, sym_size, _, sym_entsize = sections[".symtab"]
    _, str_offset, _, _, _ = sections[".strtab"]
    values = {}
    for entry in range(sym_offset, sym_offset + sym_size, sym_entsize or 16):
        name, value = struct.unpack_from("<II", data, entry)
        end = data.index(b"\0", str_offset + name)
        label = data[str_offset + name : end]
        if label in (b"_stack_start", b"_stack_end"):
            values[label] = value
    if len(values) != 2:
        return None
    return values[b"_stack_start"] - values[b"_stack_end"]


_FUNCTION = re.compile(r"^([0-9a-f]+) <(.+)>:$")
_CALL = re.compile(r"^\s*([0-9a-f]+):\s+bl\s+0x([0-9a-f]+)\b")


def call_graph(path: Path, objdump: str) -> dict[int, set[int]]:
    """Function address -> direct `bl` targets, from the disassembly."""
    output = subprocess.run(
        [objdump, "-d", "--no-show-raw-insn", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    graph: dict[int, set[int]] = {}
    current = None
    for line in output.splitlines():
        if match := _FUNCTION.match(line):
            current = int(match.group(1), 16)
            graph.setdefault(current, set())
        elif current is not None and (match := _CALL.match(line)):
            graph[current].add(int(match.group(2), 16))
    return graph


def deepest_chain(
    root: int,
    graph: dict[int, set[int]],
    frames: dict[int, int],
    through: set[int] | None = None,
) -> tuple[int, list[int]]:
    """Largest sum of frames along direct calls from `root`.

    Recursion is cut at the first repeated function. Indirect calls
    (function pointers, trait objects, wakers) are not followed, so this
    is an estimate of the synchronous direct-call depth, not a proof.
    With `through`, only chains that pass one of those functions count;
    the result is (-1, []) when none is reachable.
    """
    sys.setrecursionlimit(max(10_000, sys.getrecursionlimit()))
    memo: dict[tuple[int, bool], tuple[int, list[int]]] = {}
    active: set[int] = set()

    def visit(node: int, constrained: bool) -> tuple[int, list[int]]:
        if constrained and node in through:
            constrained = False
        key = (node, constrained)
        if key in memo:
            return memo[key]
        active.add(node)
        deepest = (-1, []) if constrained else (0, [])
        for callee in graph.get(node, ()):
            if callee in active:
                continue
            candidate = visit(callee, constrained)
            if candidate[0] > deepest[0]:
                deepest = candidate
        active.discard(node)
        if deepest[0] < 0:
            result = (-1, [])
        else:
            result = (frames.get(node, 0) + deepest[0], [node, *deepest[1]])
        memo[key] = result
        return result

    return visit(root, bool(through))


def report(path: Path, top: int, width: int = 160) -> tuple[list[tuple[int, str]], int | None]:
    data = path.read_bytes()
    names = function_symbols(data)
    frames = []
    for address, frame in stack_sizes(data):
        label = " / ".join(demangle(n) for n in names.get(address, [f"0x{address:08x}"]))
        frames.append((frame, label))
    frames.sort(reverse=True)
    main_frames = [frame for frame, label in frames if MAIN_TASK_PATTERN in label]
    main = max(main_frames) if main_frames else None
    for frame, label in frames[:top]:
        print(f"{frame:7d}  {label[:width]}")
    return frames, main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("elf", type=Path)
    parser.add_argument("--top", type=int, default=20, help="largest frames to list")
    parser.add_argument("--width", type=int, default=160, help="label width in the listing")
    parser.add_argument(
        "--max-main-frame",
        type=int,
        help="fail if the Embassy main task's poll frame exceeds this many bytes",
    )
    parser.add_argument(
        "--chain",
        action="store_true",
        help="also estimate the deepest direct-call chain under the main task "
        "(needs llvm-objdump or rust-objdump)",
    )
    parser.add_argument(
        "--through",
        action="append",
        default=[],
        metavar="PATTERN",
        help="with --chain, also report the deepest chain through functions "
        "whose name contains PATTERN (repeatable)",
    )
    parser.add_argument(
        "--min-headroom",
        type=int,
        help="with --chain, fail unless the stack region exceeds the deepest "
        "chain by this many bytes",
    )
    parser.add_argument("--objdump", help="objdump to disassemble with")
    args = parser.parse_args()
    try:
        _, main_frame = report(args.elf, args.top, args.width)
    except ElfError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if main_frame is None:
        print(f"error: no function matching {MAIN_TASK_PATTERN!r}", file=sys.stderr)
        return 2
    print(f"main task frame: {main_frame} B")
    if args.chain:
        objdump = args.objdump or next(
            (tool for tool in ("rust-objdump", "llvm-objdump") if shutil.which(tool)), None
        )
        if objdump is None:
            print("error: no rust-objdump/llvm-objdump for --chain", file=sys.stderr)
            return 2
        data = args.elf.read_bytes()
        names = function_symbols(data)
        frames = dict(stack_sizes(data))
        roots = [
            address
            for address, labels in names.items()
            if any(MAIN_TASK_PATTERN in demangle(label) for label in labels)
            and frames.get(address, 0) == main_frame
        ]
        graph = call_graph(args.elf, objdump)
        stack = stack_region(data)

        def show(title: str, through: set[int] | None) -> int:
            total, chain = deepest_chain(roots[0], graph, frames, through)
            if total < 0:
                print(f"{title}: not reached")
                return 0
            print(f"{title}: {total} B")
            for address in chain:
                label = demangle(names.get(address, [f"0x{address:08x}"])[0])
                print(f"{frames.get(address, 0):7d}  {label[: args.width]}")
            return total

        for pattern in args.through:
            matches = {
                address
                for address, labels in names.items()
                if any(pattern in demangle(label) for label in labels)
            }
            show(f"deepest chain through {pattern!r}", matches)
        total = show("deepest direct-call chain from the main task", None)
        if stack is not None:
            print(f"stack region: {stack} B, headroom over that chain: {stack - total} B")
            if args.min_headroom is not None and stack - total < args.min_headroom:
                print(
                    f"error: stack headroom {stack - total} B is below {args.min_headroom} B",
                    file=sys.stderr,
                )
                return 1
    if args.max_main_frame is not None and main_frame > args.max_main_frame:
        print(
            f"error: main task frame {main_frame} B exceeds {args.max_main_frame} B",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
