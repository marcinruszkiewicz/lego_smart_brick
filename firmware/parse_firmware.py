#!/usr/bin/env python3
"""
Parse LEGO Smart Brick ~P11 firmware containers.

Extracts the code segment (ARC EM machine code) and the ROFS filesystem
(zlib-compressed, containing play.bin, audio.bin, animation.bin, version.txt).

Usage:
    python3 parse_firmware.py <firmware.bin> [output_dir]
    python3 parse_firmware.py --all                     # process all in binaries/
"""

import sys
import os
import struct
import zlib
import re
import hashlib
from pathlib import Path

MAGIC_P11 = b"\x7eP11"
MAGIC_SUB = b"\x7fP11"
MAGIC_ROFS = b"ROFS"


def parse_p11_container(data: bytes) -> dict:
    """Parse a ~P11 firmware container and extract all segments."""
    if data[:4] != MAGIC_P11:
        raise ValueError("Not a ~P11 container")

    container_version = struct.unpack_from("<I", data, 4)[0]
    flags = struct.unpack_from("<I", data, 8)[0]
    total_length = struct.unpack_from("<I", data, 12)[0]
    ecdsa_sig = data[16:64]

    code_file_offset = struct.unpack_from("<I", data, 0x8C)[0]
    code_size = struct.unpack_from("<I", data, 0x90)[0]
    flash_addr = struct.unpack_from("<I", data, 0x94)[0]

    rofs_marker = data[0xA0:0xA4]
    rofs_file_offset = struct.unpack_from("<I", data, 0xA8)[0]
    rofs_compressed_size = struct.unpack_from("<I", data, 0xAC)[0]
    rofs_decompressed_size = struct.unpack_from("<I", data, 0xB4)[0]

    assert rofs_marker == MAGIC_ROFS, f"Expected ROFS at 0xA0, got {rofs_marker!r}"
    assert code_file_offset + code_size == rofs_file_offset, "Code/ROFS boundary mismatch"

    sub_header = data[code_file_offset:code_file_offset + 64]
    assert sub_header[:4] == MAGIC_SUB, f"Expected \\x7fP11 sub-header at 0x{code_file_offset:X}"

    code_start = code_file_offset + 64  # skip 64-byte sub-header
    code_data = data[code_start:code_start + code_size - 64]

    rofs_compressed = data[rofs_file_offset:rofs_file_offset + rofs_compressed_size]
    rofs_decompressed = zlib.decompress(rofs_compressed)
    assert len(rofs_decompressed) == rofs_decompressed_size, \
        f"ROFS size mismatch: got {len(rofs_decompressed)}, expected {rofs_decompressed_size}"

    fw_version = "unknown"
    for m in re.finditer(rb"P11_audiobrick_EM-v([\d.]+)", data):
        fw_version = m.group(1).decode()
        break

    content_version = "unknown"
    # version.txt is at the end of ROFS, small plaintext
    ver_match = re.search(rb"\n(\d+\.\d+\.\d+)\n", rofs_decompressed)
    if not ver_match:
        ver_match = re.search(rb"^(\d+\.\d+\.\d+)", rofs_decompressed[-200:])
    if ver_match:
        content_version = ver_match.group(1).decode()

    return {
        "container_version": container_version,
        "flags": flags,
        "total_length": total_length,
        "ecdsa_signature": ecdsa_sig,
        "fw_version": fw_version,
        "content_version": content_version,
        "code": {
            "file_offset": code_file_offset,
            "sub_header": sub_header,
            "size": code_size,
            "actual_code_size": len(code_data),
            "flash_address": flash_addr,
            "data": code_data,
        },
        "rofs": {
            "file_offset": rofs_file_offset,
            "compressed_size": rofs_compressed_size,
            "decompressed_size": rofs_decompressed_size,
            "data": rofs_decompressed,
        },
    }


def parse_rofs(rofs_data: bytes) -> list:
    """Parse the ROFS filesystem and return file entries."""
    if rofs_data[:4] != MAGIC_ROFS:
        raise ValueError("Not ROFS data")

    version = struct.unpack_from("<I", rofs_data, 4)[0]
    crc32 = struct.unpack_from("<I", rofs_data, 8)[0]
    first_entry_offset = struct.unpack_from("<I", rofs_data, 12)[0]
    hash_val = rofs_data[16:24].hex()
    content_size = struct.unpack_from("<I", rofs_data, 24)[0]
    num_files = struct.unpack_from("<I", rofs_data, 28)[0]

    files = []
    file_table_offset = 0x20  # 32 bytes into ROFS header

    for i in range(num_files):
        entry_off = file_table_offset + i * 12
        entry_crc = struct.unpack_from("<I", rofs_data, entry_off)[0]
        entry_offset = struct.unpack_from("<I", rofs_data, entry_off + 4)[0]
        entry_size = struct.unpack_from("<I", rofs_data, entry_off + 8)[0]

        # Per-file header is 80 bytes: 8 metadata + 64 filename + 8 hash
        file_header = rofs_data[entry_offset:entry_offset + 80]
        filename_raw = file_header[8:72]
        filename = filename_raw.split(b"\x00")[0].decode("ascii", errors="replace")

        content_start = entry_offset + 80
        content_data = rofs_data[content_start:entry_offset + entry_size]

        files.append({
            "index": i,
            "crc32": entry_crc,
            "offset": entry_offset,
            "total_size": entry_size,
            "filename": filename,
            "content_size": len(content_data),
            "data": content_data,
        })

    return {
        "version": version,
        "crc32": crc32,
        "first_entry_offset": first_entry_offset,
        "hash": hash_val,
        "content_size": content_size,
        "num_files": num_files,
        "files": files,
    }


def process_firmware(fw_path: Path, output_base: Path):
    """Process a single firmware binary and extract all components."""
    print(f"\n{'='*70}")
    print(f"Processing: {fw_path.name}")
    print(f"{'='*70}")

    data = fw_path.read_bytes()
    print(f"  File size: {len(data):,} bytes")

    result = parse_p11_container(data)
    fw_ver = result["fw_version"]
    content_ver = result["content_version"]

    print(f"  Firmware build: v{fw_ver}")
    print(f"  Content version: {content_ver}")
    print(f"  Container version: {result['container_version']}, Flags: 0x{result['flags']:08X}")
    print(f"  Code: {result['code']['actual_code_size']:,} bytes at flash 0x{result['code']['flash_address']:X}")
    print(f"  ROFS: {result['rofs']['compressed_size']:,} compressed -> {result['rofs']['decompressed_size']:,} decompressed")

    out_dir = output_base / f"fw_v{fw_ver}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write code segment
    code_path = out_dir / "code.bin"
    code_path.write_bytes(result["code"]["data"])
    print(f"  Wrote code: {code_path} ({result['code']['actual_code_size']:,} bytes)")

    # Write sub-header
    (out_dir / "sub_header.bin").write_bytes(result["code"]["sub_header"])

    # Write ROFS raw
    rofs_path = out_dir / "rofs.bin"
    rofs_path.write_bytes(result["rofs"]["data"])
    print(f"  Wrote ROFS: {rofs_path} ({result['rofs']['decompressed_size']:,} bytes)")

    # Parse and extract ROFS files
    rofs = parse_rofs(result["rofs"]["data"])
    print(f"  ROFS: {rofs['num_files']} files, version {rofs['version']}, CRC 0x{rofs['crc32']:08X}")

    rofs_dir = out_dir / "rofs_files"
    rofs_dir.mkdir(exist_ok=True)

    for f in rofs["files"]:
        fpath = rofs_dir / f["filename"]
        fpath.write_bytes(f["data"])
        magic = f["data"][:4].hex() if len(f["data"]) >= 4 else "n/a"
        print(f"    {f['filename']:<20} {f['content_size']:>8,} bytes  CRC: 0x{f['crc32']:08X}  magic: {magic}")

    # Write a summary JSON
    import json
    summary = {
        "source_file": fw_path.name,
        "fw_version": fw_ver,
        "content_version": content_ver,
        "container_version": result["container_version"],
        "flags": result["flags"],
        "total_length": result["total_length"],
        "code_size": result["code"]["actual_code_size"],
        "code_sha256": hashlib.sha256(result["code"]["data"]).hexdigest(),
        "flash_address": f"0x{result['code']['flash_address']:X}",
        "rofs_compressed_size": result["rofs"]["compressed_size"],
        "rofs_decompressed_size": result["rofs"]["decompressed_size"],
        "rofs_files": [
            {"name": f["filename"], "size": f["content_size"], "crc32": f"0x{f['crc32']:08X}"}
            for f in rofs["files"]
        ],
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 parse_firmware.py <firmware.bin> [output_dir]")
        print("       python3 parse_firmware.py --all")
        sys.exit(1)

    if sys.argv[1] == "--all":
        bindir = Path(__file__).parent / "binaries"
        outdir = Path(__file__).parent / "extracted"
        for f in sorted(bindir.glob("*.bin")):
            try:
                process_firmware(f, outdir)
            except Exception as e:
                print(f"  ERROR: {e}")
    else:
        fw_path = Path(sys.argv[1])
        outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).parent / "extracted"
        process_firmware(fw_path, outdir)

    print("\nDone!")


if __name__ == "__main__":
    main()
