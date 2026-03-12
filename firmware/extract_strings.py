#!/usr/bin/env python3
"""
Extract all printable ASCII strings from extracted firmware code.bin files.

Scans firmware/extracted/<version>/code.bin for each version, finds runs of
printable ASCII (0x20-0x7E), and writes offset + string to per-version text
files and an optional combined JSON.

Usage:
  python extract_strings.py                    # default min_len=4, writes to firmware/strings/
  python extract_strings.py --min-len 6       # longer strings only
  python extract_strings.py --json            # also write data/firmware_strings.json
"""

import argparse
import json
from pathlib import Path
from typing import List, Tuple

FW_DIR = Path(__file__).parent / "extracted"
STRINGS_DIR = Path(__file__).parent / "strings"
JSON_OUTPUT = Path(__file__).parent.parent / "data" / "firmware_strings.json"


def find_strings(data: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    """Find all printable ASCII strings (0x20-0x7E) of length >= min_len."""
    result = []
    current = b""
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not current:
                start = i
            current += bytes([b])
        else:
            if len(current) >= min_len:
                result.append((start, current.decode("ascii")))
            current = b""
    if len(current) >= min_len:
        result.append((start, current.decode("ascii")))
    return result


def main():
    parser = argparse.ArgumentParser(description="Extract all strings from firmware code.bin")
    parser.add_argument(
        "--min-len",
        type=int,
        default=4,
        help="Minimum string length (default: 4)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also write combined data/firmware_strings.json",
    )
    args = parser.parse_args()

    version_dirs = sorted(FW_DIR.iterdir()) if FW_DIR.exists() else []
    if not version_dirs:
        print("No firmware versions found under", FW_DIR)
        return

    STRINGS_DIR.mkdir(parents=True, exist_ok=True)
    all_versions_data = {}

    for vdir in version_dirs:
        if not vdir.is_dir():
            continue
        code_path = vdir / "code.bin"
        if not code_path.exists():
            print("Skip", vdir.name, "(no code.bin)")
            continue

        version = vdir.name
        data = code_path.read_bytes()
        strings = find_strings(data, min_len=args.min_len)

        # Per-version .txt: offset_hex \t string
        txt_path = STRINGS_DIR / f"{version}.txt"
        with open(txt_path, "w", encoding="utf-8", errors="replace") as f:
            for offset, s in strings:
                f.write(f"0x{offset:06x}\t{s}\n")
        print(f"{version}: {len(strings)} strings -> {txt_path}")

        if args.json:
            all_versions_data[version] = [
                {"offset": off, "hex": f"0x{off:06x}", "string": s}
                for off, s in strings
            ]

    if args.json and all_versions_data:
        JSON_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        with open(JSON_OUTPUT, "w", encoding="utf-8") as f:
            json.dump(
                {"min_len": args.min_len, "versions": all_versions_data},
                f,
                indent=2,
            )
        print(f"Combined JSON -> {JSON_OUTPUT}")


if __name__ == "__main__":
    main()
