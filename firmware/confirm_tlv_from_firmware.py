#!/usr/bin/env python3
"""
Search extracted firmware (code.bin + disasm.txt) for evidence of the TLV format
expected after AES-CCM decryption.

Expected layout (from docs/encryption-analysis.md):
  Bytes 0-1:  Type ID (12-bit type + 2-bit block_type in bits 12-13), LE
  Bytes 2-3:  Content length (uint16 LE)
  Bytes 4-7:  Event type magic:
                Identity: 0xA7E24ED1 (LE: D1 4E E2 A7)
                Item:     0x0BBDA113 (LE: 13 A1 BD 0B)

Run from firmware/ with extracted/ and disassembly/ present (e.g. fw_v1.119.0).
"""

from pathlib import Path

EXTRACTED = Path(__file__).parent / "extracted"
DISASM = Path(__file__).parent / "disassembly"
FLASH_BASE = 0x306000

# Magic 4-byte sequences (little-endian)
IDENTITY_MAGIC = bytes([0xD1, 0x4E, 0xE2, 0xA7])  # 0xA7E24ED1
ITEM_MAGIC = bytes([0x13, 0xA1, 0xBD, 0x0B])      # 0x0BBDA113


def search_code_bin(code_bin: bytes) -> dict:
    """Search code.bin for magic bytes and tag_message_parser."""
    out = {"magic_identity": [], "magic_item": [], "tag_message_parser": None}
    i = 0
    while True:
        i = code_bin.find(IDENTITY_MAGIC, i)
        if i < 0:
            break
        out["magic_identity"].append(i)
        i += 1
    i = 0
    while True:
        i = code_bin.find(ITEM_MAGIC, i)
        if i < 0:
            break
        out["magic_item"].append(i)
        i += 1
    idx = code_bin.find(b"tag_message_parser")
    if idx >= 0:
        out["tag_message_parser"] = idx
    return out


def search_disasm_for_constants(disasm_path: Path) -> dict:
    """Search disassembly for 32-bit constants that could be the magic values."""
    text = disasm_path.read_text()
    out = {"a7e24ed1": [], "0bbda113": [], "identity_hex": [], "item_hex": []}
    for line in text.splitlines():
        if "a7e24ed1" in line.lower() or "a7e2 4ed1" in line.lower():
            out["a7e24ed1"].append(line.strip())
        if "0bbda113" in line.lower() or "0bbd a113" in line.lower():
            out["0bbda113"].append(line.strip())
        if "4ed1" in line.lower() and "e2" in line.lower():
            out["identity_hex"].append(line.strip()[:80])
        if "a113" in line.lower() and "bd" in line.lower():
            out["item_hex"].append(line.strip()[:80])
    return out


def main():
    versions = sorted(EXTRACTED.iterdir()) if EXTRACTED.exists() else []
    if not versions:
        print("No extracted firmware found in", EXTRACTED)
        return

    print("=== TLV evidence search (extracted firmware) ===\n")

    for ver_dir in versions:
        if not ver_dir.is_dir():
            continue
        name = ver_dir.name
        code_bin = ver_dir / "code.bin"
        if not code_bin.exists():
            continue
        data = code_bin.read_bytes()
        bin_result = search_code_bin(data)
        print(f"--- {name} (code.bin) ---")
        print(f"  Identity magic D14EE2A7: {bin_result['magic_identity'] or 'not found'}")
        print(f"  Item magic 13A1BD0B:     {bin_result['magic_item'] or 'not found'}")
        print(f"  tag_message_parser:      {hex(bin_result['tag_message_parser']) if bin_result['tag_message_parser'] is not None else 'not found'}")

        disasm_dir = DISASM / name if DISASM.exists() else None
        disasm_file = disasm_dir / "disasm.txt" if disasm_dir and disasm_dir.exists() else None
        if disasm_file and disasm_file.exists():
            asm_result = search_disasm_for_constants(disasm_file)
            if asm_result["a7e24ed1"] or asm_result["0bbda113"]:
                print(f"  Disasm: Identity constant refs: {len(asm_result['a7e24ed1'])}, Item: {len(asm_result['0bbda113'])}")
        print()

    print("Conclusion:")
    print("  - If magic bytes appear in code.bin, they may be literal constants for comparison.")
    print("  - tag_message_parser.c exists in firmware (string present) → parser logic exists.")
    print("  - For manual analysis: run analyze_tag_path.py <version> to dump 0x25718 and xrefs;")
    print("    see ANALYZE_TAG_TLV.md for step-by-step TLV confirmation.")


if __name__ == "__main__":
    main()
