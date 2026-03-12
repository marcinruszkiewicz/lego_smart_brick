#!/usr/bin/env python3
"""
Dump the tag data processing path for manual TLV analysis.

Finds:
  1. Flash address of "tag_message_parser" in code.bin
  2. Xrefs to that string in disasm (who references the parser)
  3. Function at 0x25718 (tag data processing) and all its bl/bl.d callees
  4. First N lines of each callee so you can search for offset-0/2/4 loads and magic constants

Usage:
  python3 analyze_tag_path.py [version]
  python3 analyze_tag_path.py fw_v1.119.0

If version is omitted, uses the first extracted version that has tag_message_parser.
"""

import re
import sys
from pathlib import Path

EXTRACTED = Path(__file__).parent / "extracted"
DISASM = Path(__file__).parent / "disassembly"
FLASH_BASE = 0x306000
TAG_DATA_FUNC = 0x25718  # main tag data processing (from DISASM_TRACE_FINDINGS.md)


def find_parser_flash_addr(code_bin: bytes) -> int | None:
    idx = code_bin.find(b"tag_message_parser")
    if idx < 0:
        return None
    return FLASH_BASE + idx


def find_line_for_addr(disasm_lines: list, addr: int) -> int | None:
    """Return line index where the given address appears as a label (e.g. '  25718:')."""
    addr_hex = f"{addr:x}"
    for i, line in enumerate(disasm_lines):
        if re.match(rf"\s+{addr_hex}:", line):
            return i
    return None


def find_function_end(disasm_lines: list, start: int, max_lines: int = 500) -> int:
    """Return line index of the last line of the function (leave_s or next enter_s)."""
    for i in range(start + 2, min(start + max_lines, len(disasm_lines))):
        line = disasm_lines[i]
        if "leave_s" in line or "j_s.d\t[blink]" in line or "j_s\t[blink]" in line:
            return i
        if "enter_s" in line:
            # Next function
            return i - 1
    return start + max_lines


def extract_call_targets(disasm_lines: list, start: int, end: int) -> list[int]:
    """Extract bl/bl.d target addresses from the given line range."""
    targets = []
    for i in range(start, min(end + 1, len(disasm_lines))):
        line = disasm_lines[i]
        if "\tbl" not in line:
            continue
        # objdump format: "bl.d	112720	;410fc" or "bl	4600	;21918"
        m = re.search(r";\s*([0-9a-f]+)\s*", line)
        if m:
            targets.append(int(m.group(1), 16))
    return targets


def main():
    version = (sys.argv[1] if len(sys.argv) > 1 else None)
    if not version:
        for d in sorted(EXTRACTED.iterdir()):
            if not d.is_dir():
                continue
            code_bin = d / "code.bin"
            if code_bin.exists() and code_bin.read_bytes().find(b"tag_message_parser") >= 0:
                version = d.name
                break
    if not version:
        print("No version with tag_message_parser found. Pass e.g. fw_v1.119.0")
        return 1

    code_path = EXTRACTED / version / "code.bin"
    disasm_path = DISASM / version / "disasm.txt"
    if not code_path.exists():
        print(f"Missing {code_path}")
        return 1
    if not disasm_path.exists():
        print(f"Missing {disasm_path}")
        return 1

    code_bin = code_path.read_bytes()
    disasm_lines = disasm_path.read_text().splitlines()

    flash_parser = find_parser_flash_addr(code_bin)
    if flash_parser is None:
        print("tag_message_parser not in code.bin")
        return 1

    print(f"=== Tag path analysis: {version} ===\n")
    print(f"1. tag_message_parser string at flash 0x{flash_parser:x} (code.bin offset 0x{flash_parser - FLASH_BASE:x})\n")

    # Xrefs to parser string (search for flash addr in various forms)
    patterns = [
        f"{flash_parser:x}",
        f"{flash_parser:06x}",
        f"{flash_parser >> 16:04x} {flash_parser & 0xFFFF:04x}",
        f"0037 {flash_parser & 0xFFFF:04x}" if flash_parser >> 16 == 0x37 else None,
    ]
    print("2. Xrefs to tag_message_parser (grep for this address in disasm):")
    for p in patterns:
        if p is None:
            continue
        matches = [i for i, l in enumerate(disasm_lines) if p in l.lower()]
        if matches:
            print(f"   Pattern '{p}': {len(matches)} hit(s), first at line {matches[0] + 1}")
            for idx in matches[:5]:
                print(f"      L{idx + 1}: {disasm_lines[idx].strip()[:90]}")
            if len(matches) > 5:
                print(f"      ... and {len(matches) - 5} more")
    print()

    # Function at TAG_DATA_FUNC
    func_line = find_line_for_addr(disasm_lines, TAG_DATA_FUNC)
    if func_line is None:
        print(f"3. Function at 0x{TAG_DATA_FUNC:x} not found in disasm")
        return 0

    func_end = find_function_end(disasm_lines, func_line)
    call_targets = extract_call_targets(disasm_lines, func_line, func_end)

    print(f"3. Tag data processing function 0x{TAG_DATA_FUNC:x}")
    print(f"   Disasm lines {func_line + 1}--{func_end + 1} ({func_end - func_line + 1} lines)")
    print(f"   Call targets (bl/bl.d): {[hex(t) for t in call_targets]}\n")

    # Dump first 60 lines of the function
    print("   --- First 60 lines of 0x25718 ---")
    for i in range(func_line, min(func_line + 60, len(disasm_lines))):
        print(f"   {i + 1:6}: {disasm_lines[i]}")
    print()

    # For each callee, find and dump first 40 lines
    print("4. Callees (first 40 lines each) — look for ldh/ld at offset 0, 2, 4 and cmp with 0xa7e24ed1 / 0x0bbda113")
    seen = set()
    for target in call_targets[:12]:
        if target in seen:
            continue
        seen.add(target)
        line_idx = find_line_for_addr(disasm_lines, target)
        if line_idx is None:
            # Address might be from a different base; try as label
            target_hex = f"{target:x}"
            for i, l in enumerate(disasm_lines):
                if re.match(r"\s+" + target_hex + r":", l):
                    line_idx = i
                    break
        if line_idx is None:
            print(f"   --- 0x{target:x}: (label not found, search by hand) ---")
            continue
        end_idx = find_function_end(disasm_lines, line_idx, max_lines=45)
        print(f"   --- 0x{target:x} (lines {line_idx + 1}--{end_idx + 1}) ---")
        for i in range(line_idx, min(line_idx + 40, len(disasm_lines))):
            print(f"   {i + 1:6}: {disasm_lines[i]}")
        print()

    print("Next: Open disasm.txt at the line numbers above and search for:")
    print("  - ldh / ld_s from [rN,0], [rN,2], [rN,4] (type_id, content_len, magic)")
    print("  - mov_s + cmp with 0xa7e24ed1 or 0x0bbda113 (event type check)")
    print("See ANALYZE_TAG_TLV.md for the full procedure.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
