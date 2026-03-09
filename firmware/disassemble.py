#!/usr/bin/env python3
"""
Disassemble LEGO Smart Brick firmware code segments using the ARC GNU toolchain via Docker.

Creates ELF wrapper from raw binary and disassembles with arc-elf32-objdump.

Usage:
    python3 disassemble.py <extracted_dir>        # single version
    python3 disassemble.py --all                   # all extracted versions
    python3 disassemble.py --latest                # just the newest version
"""

import sys
import os
import subprocess
from pathlib import Path

EXTRACTED_DIR = Path(__file__).parent / "extracted"
DISASM_DIR = Path(__file__).parent / "disassembly"
DOCKER_IMAGE = "arc-toolchain"


def check_docker():
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", DOCKER_IMAGE],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"Docker image '{DOCKER_IMAGE}' not found. Build it first:")
            print(f"  cd firmware && docker build --platform linux/amd64 -t {DOCKER_IMAGE} .")
            return False
        return True
    except FileNotFoundError:
        print("Docker not found. Install Docker Desktop first.")
        return False


def disassemble_version(version_dir: Path, output_dir: Path):
    """Disassemble a single firmware version's code segment."""
    code_bin = version_dir / "code.bin"
    if not code_bin.exists():
        print(f"  No code.bin found in {version_dir}")
        return False

    version_name = version_dir.name
    out_dir = output_dir / version_name
    out_dir.mkdir(parents=True, exist_ok=True)

    disasm_file = out_dir / "disasm.txt"
    elf_file = out_dir / "fw.elf"

    if disasm_file.exists() and disasm_file.stat().st_size > 0:
        lines = sum(1 for _ in open(disasm_file))
        print(f"  Already disassembled: {disasm_file} ({lines:,} lines)")
        return True

    code_size = code_bin.stat().st_size
    print(f"  Code size: {code_size:,} bytes")

    # Mount parent extracted dir into Docker and run objcopy + objdump
    abs_extracted = version_dir.resolve()
    abs_output = out_dir.resolve()

    cmd = [
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "-v", f"{abs_extracted}:/input:ro",
        "-v", f"{abs_output}:/output",
        DOCKER_IMAGE,
        "sh", "-c",
        "arc-elf32-objcopy -I binary -O elf32-littlearc -B EM "
        "--rename-section .data=.text /input/code.bin /output/fw.elf && "
        "arc-elf32-objdump -d -m EM /output/fw.elf > /output/disasm.txt && "
        "echo DONE"
    ]

    print(f"  Running disassembly via Docker...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if result.returncode != 0:
        print(f"  ERROR: {result.stderr.strip()}")
        return False

    if disasm_file.exists():
        size = disasm_file.stat().st_size
        lines = sum(1 for _ in open(disasm_file))
        print(f"  Disassembly: {disasm_file} ({size:,} bytes, {lines:,} lines)")
        return True
    else:
        print(f"  ERROR: disasm.txt not created")
        return False


def main():
    if not check_docker():
        sys.exit(1)

    DISASM_DIR.mkdir(parents=True, exist_ok=True)

    if len(sys.argv) < 2:
        print("Usage: python3 disassemble.py <extracted_dir> | --all | --latest")
        sys.exit(1)

    if sys.argv[1] == "--all":
        versions = sorted(EXTRACTED_DIR.iterdir())
    elif sys.argv[1] == "--latest":
        versions = sorted(EXTRACTED_DIR.iterdir())
        versions = [versions[-1]] if versions else []
    else:
        versions = [Path(sys.argv[1])]

    success = 0
    for v in versions:
        if not v.is_dir():
            continue
        print(f"\n{'='*60}")
        print(f"Disassembling: {v.name}")
        print(f"{'='*60}")
        if disassemble_version(v, DISASM_DIR):
            success += 1

    print(f"\nDone: {success}/{len(versions)} versions disassembled")


if __name__ == "__main__":
    main()
