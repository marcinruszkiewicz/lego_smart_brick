#!/usr/bin/env python3
"""
Search for Identity (0xA7E24ED1) and Item (0x0BBDA113) magic constants in
extracted firmware and disassembly, to confirm them from the binary.

Usage:
  python3 find_magic_constants.py [version]
  python3 find_magic_constants.py fw_v1.119.0
"""

import struct
import sys
from pathlib import Path

EXTRACTED = Path(__file__).parent / "extracted"
DISASM = Path(__file__).parent / "disassembly"
FLASH_BASE = 0x306000

IDENTITY = 0xA7E24ED1  # Identity tag event magic
ITEM = 0x0BBDA113     # Item tag event magic


def search_binary(data: bytes) -> dict:
    """Search for 4-byte magic (LE and BE) and 16-bit halves."""
    out = {"identity_le": [], "identity_be": [], "item_le": [], "item_be": []}
    # LE
    for val, key in [(IDENTITY, "identity_le"), (ITEM, "item_le")]:
        blob = struct.pack("<I", val)
        i = 0
        while True:
            i = data.find(blob, i)
            if i < 0:
                break
            out[key].append(i)
            i += 1
    # BE
    for val, key in [(IDENTITY, "identity_be"), (ITEM, "item_be")]:
        blob = struct.pack(">I", val)
        i = 0
        while True:
            i = data.find(blob, i)
            if i < 0:
                break
            out[key].append(i)
            i += 1
    return out


def search_disasm(text: str) -> dict:
    """
    Search disassembly for 32-bit constant or 16-bit halves.
    ARC may emit: mov_s r0, 0xa7e24ed1 (one line) or two mov_s with 0x4ed1 and 0xa7e2.
    """
    lines = text.splitlines()
    out = {
        "identity_32": [],   # line containing a7e24ed1 as constant
        "identity_lo": [],   # 0x4ed1
        "identity_hi": [],   # 0xa7e2
        "item_32": [],
        "item_lo": [],       # 0xa113
        "item_hi": [],       # 0x0bbd
    }
    for i, line in enumerate(lines):
        lower = line.lower()
        # Full 32-bit (allow space: a7e2 4ed1)
        if "a7e24ed1" in lower or ("a7e2" in lower and "4ed1" in lower):
            out["identity_32"].append((i + 1, line.strip()[:100]))
        if "0bbda113" in lower or ("0bbd" in lower and "a113" in lower):
            out["item_32"].append((i + 1, line.strip()[:100]))
        # 16-bit halves - only in mov/ld/cmp context to avoid opcode false positives
        if "mov" in lower or "ld" in lower or "cmp" in lower or "st " in lower:
            if "0x4ed1" in lower or "0037 4ed1" in lower:
                out["identity_lo"].append((i + 1, line.strip()[:100]))
            if "0xa7e2" in lower or "0037 a7e2" in lower:
                out["identity_hi"].append((i + 1, line.strip()[:100]))
            if "0xa113" in lower:
                out["item_lo"].append((i + 1, line.strip()[:100]))
            if "0x0bbd" in lower:
                out["item_hi"].append((i + 1, line.strip()[:100]))
    return out


def main():
    version = sys.argv[1] if len(sys.argv) > 1 else None
    if not version:
        for d in sorted(EXTRACTED.iterdir()):
            if d.is_dir() and (d / "code.bin").exists():
                version = d.name
                break
    if not version:
        print("Pass version e.g. fw_v1.119.0")
        return 1

    code_path = EXTRACTED / version / "code.bin"
    disasm_path = DISASM / version / "disasm.txt"
    if not code_path.exists():
        print(f"Missing {code_path}")
        return 1

    data = code_path.read_bytes()
    bin_result = search_binary(data)
    asm_result = {"identity_32": [], "item_32": []}
    play_result = None
    play_path = EXTRACTED / version / "rofs_files" / "play"
    if play_path.exists():
        play_data = play_path.read_bytes()
        play_result = search_binary(play_data)

    print(f"=== Magic constant search: {version} ===\n")
    print("1. code.bin (4-byte literal)")
    print(f"   Identity 0xA7E24ED1 LE: {bin_result['identity_le'] or 'not found'}")
    print(f"   Identity 0xA7E24ED1 BE: {bin_result['identity_be'] or 'not found'}")
    print(f"   Item 0x0BBDA113 LE:     {bin_result['item_le'] or 'not found'}")
    print(f"   Item 0x0BBDA113 BE:     {bin_result['item_be'] or 'not found'}")

    if play_result is not None:
        print("\n1b. rofs_files/play (4-byte literal)")
        print(f"   Identity 0xA7E24ED1 LE: {play_result['identity_le'] or 'not found'}")
        print(f"   Identity 0xA7E24ED1 BE: {play_result['identity_be'] or 'not found'}")
        print(f"   Item 0x0BBDA113 LE:     {play_result['item_le'] or 'not found'}")
        print(f"   Item 0x0BBDA113 BE:     {play_result['item_be'] or 'not found'}")

    if disasm_path.exists():
        text = disasm_path.read_text()
        asm_result = search_disasm(text)
        print("\n2. disasm.txt (immediate in instruction)")
        print(f"   Identity 32-bit or a7e2+4ed1: {len(asm_result['identity_32'])} hit(s)")
        for line_no, snippet in asm_result["identity_32"][:5]:
            print(f"      L{line_no}: {snippet}")
        print(f"   Identity lo 0x4ed1 (mov/ld/cmp): {len(asm_result['identity_lo'])} hit(s)")
        for line_no, snippet in asm_result["identity_lo"][:3]:
            print(f"      L{line_no}: {snippet}")
        print(f"   Identity hi 0xa7e2 (mov/ld/cmp): {len(asm_result['identity_hi'])} hit(s)")
        for line_no, snippet in asm_result["identity_hi"][:3]:
            print(f"      L{line_no}: {snippet}")
        print(f"   Item 32-bit or 0bbd+a113: {len(asm_result['item_32'])} hit(s)")
        print(f"   Item lo 0xa113: {len(asm_result['item_lo'])} hit(s)")
        print(f"   Item hi 0x0bbd: {len(asm_result['item_hi'])} hit(s)")

    print("\n3. Conclusion")
    found = bin_result["identity_le"] or bin_result["item_le"]
    if play_result is not None:
        found = found or play_result["identity_le"] or play_result["item_le"]
    if disasm_path.exists():
        found = found or asm_result["identity_32"] or asm_result["item_32"]
    if found:
        if play_result and (play_result["identity_le"] or play_result["item_le"]):
            print("   Magic constants found in ROFS play file.")
        else:
            print("   Magic constants found in firmware.")
    else:
        print("   Magic constants were NOT found as 4-byte literals or as 32-bit")
        print("   immediates in the disassembly. They may be:")
        print("   - in a data table (e.g. in ROFS or another segment not in code.bin),")
        print("   - computed at runtime (e.g. from type_id), or")
        print("   - loaded from a different encoding (e.g. two 16-bit loads).")
        print("   The TLV layout (type_id @ 0, content_len @ 2, value @ 4) is confirmed")
        print("   in 0xfe14; the exact values 0xA7E24ED1 / 0x0BBDA113 remain from docs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
