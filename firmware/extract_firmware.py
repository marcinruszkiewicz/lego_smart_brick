#!/usr/bin/env python3
"""
Extract LEGO Smart Brick firmware binaries from Unity Addressable assets.

Scans Unity SerializedFile bundles for assets containing the ~P11 (0x7E503131)
firmware container magic. Extracts matching binaries and prints header info.
"""

import sys
import os
import struct
from pathlib import Path

import UnityPy

MAGIC_P11 = b"\x7eP11"
ASSET_DIR = Path(__file__).parent / "apk" / "unity_assets" / "assets" / "bin" / "Data"
OUTPUT_DIR = Path(__file__).parent / "binaries"


def parse_wdx_header(data: bytes) -> dict:
    """Parse the 104-byte WDX firmware container header."""
    if len(data) < 104:
        return {}
    magic = data[0:4]
    if magic != MAGIC_P11:
        return {}
    fields = struct.unpack_from("<III", data, 4)
    version, flags, total_len = fields
    product_id = struct.unpack_from("<I", data, 80)[0]
    hw_version = struct.unpack_from("<I", data, 84)[0]
    upgrade_version = struct.unpack_from("<I", data, 88)[0]
    seg_table_off = struct.unpack_from("<I", data, 92)[0]
    seg_count = struct.unpack_from("<I", data, 96)[0]
    product_names = {0: "AudioBrick", 1: "PanelCharger"}
    return {
        "version": version,
        "flags": flags,
        "total_length": total_len,
        "ecdsa_signature": data[16:64].hex(),
        "product_id": product_id,
        "product_name": product_names.get(product_id, f"Unknown({product_id})"),
        "hw_version": hw_version,
        "upgrade_version": upgrade_version,
        "seg_table_offset": seg_table_off,
        "seg_count": seg_count,
    }


def scan_raw_bytes(data: bytes, source_name: str) -> list:
    """Scan raw bytes for ~P11 magic at any offset."""
    results = []
    offset = 0
    while True:
        idx = data.find(MAGIC_P11, offset)
        if idx == -1:
            break
        header = parse_wdx_header(data[idx:])
        if header and header["total_length"] > 104:
            end = idx + header["total_length"]
            fw_data = data[idx:end] if end <= len(data) else data[idx:]
            results.append((idx, header, fw_data))
        offset = idx + 1
    return results


def extract_from_unity_assets(asset_dir: Path) -> list:
    """Load all Unity assets and extract firmware binaries."""
    found = []
    asset_files = sorted(asset_dir.iterdir())
    total = len(asset_files)

    for i, asset_file in enumerate(asset_files):
        if asset_file.name.startswith(".") or asset_file.suffix == ".resource":
            continue
        try:
            env = UnityPy.load(str(asset_file))
        except Exception:
            continue

        for obj in env.objects:
            try:
                type_name = obj.type.name
            except Exception:
                continue

            raw = None
            name = f"unknown_{obj.path_id}"

            if type_name == "TextAsset":
                try:
                    data = obj.read()
                    raw = data.m_Script if isinstance(data.m_Script, bytes) else data.m_Script.encode("latin-1")
                    name = data.m_Name
                except Exception:
                    try:
                        raw = obj.get_raw_data()
                        name = f"raw_{obj.path_id}"
                    except Exception:
                        continue
            else:
                try:
                    raw = obj.get_raw_data()
                    name = f"{type_name}_{obj.path_id}"
                except Exception:
                    continue

            if raw and MAGIC_P11 in raw:
                hits = scan_raw_bytes(raw, name)
                for offset, header, fw_data in hits:
                    found.append({
                        "source_file": asset_file.name,
                        "asset_name": name,
                        "asset_type": type_name,
                        "offset_in_asset": offset,
                        "header": header,
                        "data": fw_data,
                    })

        if (i + 1) % 50 == 0 or i == total - 1:
            print(f"  Scanned {i + 1}/{total} asset files, found {len(found)} firmware(s) so far...")

    return found


def extract_raw_scan(asset_dir: Path) -> list:
    """Scan all files in asset_dir for ~P11 magic bytes."""
    found = []
    files = sorted(f for f in asset_dir.iterdir() if not f.name.startswith("."))
    for f in files:
        raw = f.read_bytes()
        hits = scan_raw_bytes(raw, f.name)
        for offset, header, fw_data in hits:
            found.append({
                "source_file": f.name,
                "asset_name": f.name,
                "asset_type": "RawFile",
                "offset_in_asset": offset,
                "header": header,
                "data": fw_data,
            })
    return found


def try_extract_version_string(fw_data: bytes) -> str:
    """Try to find a version string like 'v0.72.1' in the firmware data."""
    import re
    # Look near the end of the binary for a version.txt-like string
    # ROFS version file is usually small plaintext
    for match in re.finditer(rb"(\d+\.\d+\.\d+)", fw_data):
        ver = match.group(1).decode("ascii")
        # Filter out unlikely versions
        parts = ver.split(".")
        if int(parts[0]) < 10 and int(parts[1]) < 100:
            return ver
    return "unknown"


def main():
    asset_dir = ASSET_DIR
    output_dir = OUTPUT_DIR

    if len(sys.argv) > 1:
        asset_dir = Path(sys.argv[1])
    if len(sys.argv) > 2:
        output_dir = Path(sys.argv[2])

    if not asset_dir.exists():
        print(f"Asset directory not found: {asset_dir}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Scanning Unity assets in: {asset_dir}")
    print(f"Output directory: {output_dir}")
    print()

    # Try UnityPy object parsing first
    print("Phase 1: UnityPy object parsing...")
    firmwares = extract_from_unity_assets(asset_dir)

    if not firmwares:
        print("\nPhase 2: Raw binary scan (UnityPy found nothing)...")
        firmwares = extract_raw_scan(asset_dir)

    print(f"\n{'='*60}")
    print(f"Found {len(firmwares)} firmware binary(ies)")
    print(f"{'='*60}\n")

    import hashlib
    seen_hashes = set()
    written = 0
    for i, fw in enumerate(firmwares):
        h = fw["header"]
        sha256 = hashlib.sha256(fw["data"]).hexdigest()[:16]

        if sha256 in seen_hashes:
            print(f"[{i}] DUPLICATE (sha256 prefix: {sha256}) -- skipping")
            continue
        seen_hashes.add(sha256)

        ver = try_extract_version_string(fw["data"])
        product = h["product_name"]
        hw = h["hw_version"]
        upg = h["upgrade_version"]
        filename = f"firmware_{product}_hw{hw}_v{ver}_{sha256}.bin"
        outpath = output_dir / filename

        outpath.write_bytes(fw["data"])
        written += 1

        print(f"[{i}] {filename}")
        print(f"    Source: {fw['source_file']}")
        print(f"    Offset in asset: 0x{fw['offset_in_asset']:X}")
        print(f"    Product: {product} (id={h['product_id']})")
        print(f"    HW version: {hw}, Upgrade version: {upg}")
        print(f"    Container version: {h['version']}, Flags: 0x{h['flags']:08X}")
        print(f"    Total length: {h['total_length']:,} bytes")
        print(f"    Segments: {h['seg_count']}")
        print(f"    ECDSA sig (first 16B): {h['ecdsa_signature'][:32]}...")
        print(f"    Firmware version (detected): {ver}")
        print(f"    SHA256 prefix: {sha256}")
        print(f"    Written to: {outpath}")
        print()

    print(f"Wrote {written} unique firmware binaries to {output_dir}")


if __name__ == "__main__":
    main()
