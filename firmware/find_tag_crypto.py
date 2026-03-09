#!/usr/bin/env python3
"""
Analyze firmware binary to find tag crypto routines by tracing
string references and AES-CCM related code.

Uses Capstone for ARC disassembly to find cross-references to known strings.
Also searches for potential hardcoded keys and interesting byte patterns.
"""

import struct
import re
from pathlib import Path

FW_DIR = Path(__file__).parent / "extracted"


def find_strings(data: bytes, min_len=6):
    """Find all printable ASCII strings and their offsets."""
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
                result.append((start, current.decode('ascii')))
            current = b""
    if len(current) >= min_len:
        result.append((start, current.decode('ascii')))
    return result


def find_tag_related_strings(data: bytes):
    """Find all tag and crypto related strings."""
    all_strings = find_strings(data, min_len=4)
    keywords = [
        'tag', 'Tag', 'TAG', 'nfc', 'NFC',
        'aes', 'AES', 'ccm', 'CCM', 'crypt', 'Crypt',
        'key', 'Key', 'KEY', 'mac', 'MAC',
        'verify', 'Verify', 'sign', 'Sign',
        'decrypt', 'Decrypt', 'encrypt', 'Encrypt',
        'security', 'Security',
        'payload', 'Payload',
        'content', 'Content',
        'identity', 'Identity',
        'item', 'Item',
        'parse', 'Parse',
    ]
    results = []
    for offset, s in all_strings:
        if any(k in s for k in keywords):
            results.append((offset, s))
    return results


def analyze_data_region(data: bytes, strings_start: int):
    """Look for potential key material near the string data region.
    
    AES-128 keys are 16 bytes, AES-256 are 32 bytes.
    Look for non-zero, high-entropy 16/32 byte sequences near crypto code.
    """
    print("\n=== Potential Key Material Search ===")
    print(f"Searching around crypto string region (0x{strings_start:X})...")

    # Search a broader region before the strings for initialized data
    # Crypto keys are often stored in .rodata adjacent to the code that uses them
    search_start = max(0, strings_start - 0x10000)
    search_end = min(len(data), strings_start + 0x10000)

    # Look for sequences that could be AES keys:
    # - 16 or 32 consecutive non-zero, non-ASCII bytes
    # - High byte value entropy
    candidates = []
    region = data[search_start:search_end]

    for i in range(0, len(region) - 16, 4):
        block16 = region[i:i+16]
        # Skip if all zeros or all same byte
        if block16 == b'\x00' * 16 or len(set(block16)) == 1:
            continue
        # Skip if it looks like ASCII text
        if all(0x20 <= b < 0x7F for b in block16):
            continue
        # Skip if it looks like code (lots of small values typical of ARC instructions)
        # Count unique byte values - keys should have high entropy
        unique = len(set(block16))
        if unique < 10:
            continue
        # Skip if it contains null bytes (keys rarely have nulls in the middle)
        if b'\x00\x00\x00\x00' in block16:
            continue
        
        abs_offset = search_start + i
        candidates.append((abs_offset, block16, unique))

    # Sort by uniqueness (entropy proxy)
    candidates.sort(key=lambda x: -x[2])

    print(f"Found {len(candidates)} high-entropy 16-byte sequences")
    for offset, block, unique in candidates[:20]:
        hex_str = block.hex()
        print(f"  0x{offset:06X}: {hex_str}  (unique bytes: {unique})")


def find_function_boundaries(data: bytes, target_offset: int, window=2048):
    """Find the likely function containing a given offset by looking for
    ARC function prologue/epilogue patterns near the target."""
    
    # ARC EM function prologues typically start with:
    # enter_s (0xC0E0-0xC3FF range) or push_s/st.a [sp, ...] patterns
    # Let's look backwards from target for enter_s (2-byte: 0xC0Ex-0xC3Fx)
    start = max(0, target_offset - window)
    region = data[start:target_offset]
    
    prologues = []
    for i in range(0, len(region) - 1, 2):
        word = struct.unpack_from('<H', region, i)[0]
        if 0xC0E0 <= word <= 0xC3FF:  # enter_s encoding range
            prologues.append(start + i)
    
    if prologues:
        return prologues[-1]  # Nearest prologue before target
    return None


def main():
    versions = ["fw_v1.119.0"]  # Start with richest version
    
    for version in versions:
        code_path = FW_DIR / version / "code.bin"
        if not code_path.exists():
            print(f"Skipping {version}: no code.bin")
            continue
            
        data = code_path.read_bytes()
        print(f"\n{'='*70}")
        print(f"Analyzing: {version} ({len(data):,} bytes)")
        print(f"{'='*70}")
        
        # 1. Find all tag/crypto related strings
        tag_strings = find_tag_related_strings(data)
        
        print(f"\n=== Tag/Crypto Related Strings ({len(tag_strings)} found) ===")
        for offset, s in sorted(tag_strings):
            print(f"  0x{offset:06X}: {s}")
        
        # 2. Search for specific security-related patterns
        print("\n=== Security Format Parsing Clues ===")
        
        # The firmware mentions "tag security format" -- let's find format version bytes
        # that might indicate what kind of crypto is used
        security_strings = [
            (s, o) for o, s in tag_strings 
            if 'security' in s.lower() or 'format' in s.lower()
        ]
        for s, o in security_strings:
            print(f"  0x{o:06X}: {s}")
        
        # 3. Look for AES S-box (a fingerprint for AES implementation)
        # The first 16 bytes of the AES S-box are: 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
        aes_sbox_start = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                                0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])
        
        idx = data.find(aes_sbox_start)
        if idx >= 0:
            print(f"\n=== AES S-box Found at 0x{idx:06X}! ===")
            print(f"  This confirms a software AES implementation")
            print(f"  Full S-box at: 0x{idx:06X} - 0x{idx+256:06X}")
            
            # Look for key schedule tables nearby
            # The inverse S-box starts with: 52 09 6a d5 30 36 a5 38
            inv_sbox = bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38])
            inv_idx = data.find(inv_sbox, idx, idx + 1024)
            if inv_idx >= 0:
                print(f"  Inverse S-box at: 0x{inv_idx:06X}")
        else:
            print("\n=== No AES S-box Found ===")
            print("  AES may be hardware-accelerated or use a different implementation")
        
        # 4. Look for potential hardcoded keys near crypto functions
        # Find the earliest crypto string offset
        crypto_offsets = [o for o, s in tag_strings if 'AES' in s or 'CCM' in s or 'key' in s.lower() or 'crypt' in s.lower()]
        if crypto_offsets:
            earliest = min(crypto_offsets)
            analyze_data_region(data, earliest)
        
        # 5. Look for the tag data structure format
        print("\n=== Tag Data Format Clues ===")
        # Search for format version constants near tag strings
        tag_offsets = [o for o, s in tag_strings if 'tag' in s.lower()]
        if tag_offsets:
            earliest_tag = min(tag_offsets)
            # Look for small constants (1, 2, 3) used as format identifiers near tag code
            print(f"  Earliest tag string at: 0x{earliest_tag:06X}")
            print(f"  Tag strings region: 0x{min(tag_offsets):06X} - 0x{max(tag_offsets):06X}")
        
        # 6. Search for the "RKEy" string which appeared in all versions
        rkey_idx = data.find(b'RKEy')
        if rkey_idx >= 0:
            print(f"\n=== 'RKEy' marker found at 0x{rkey_idx:06X} ===")
            context = data[rkey_idx-16:rkey_idx+32]
            print(f"  Context: {context.hex()}")
            print(f"  ASCII: {context}")

        # 7. Search for 0x010C pattern (tag header) in code
        print("\n=== Tag Header Constants (0x010C = 268 total size) ===")
        count = 0
        offset = 0
        while count < 10:
            idx = data.find(b'\x0c\x01', offset)  # little-endian 0x010C
            if idx < 0 or idx > 0x60000:  # Only search code region, not string data
                break
            # Check if this is in an instruction context
            print(f"  0x{idx:06X}: ...{data[idx-4:idx+8].hex()}...")
            count += 1
            offset = idx + 1


if __name__ == "__main__":
    main()
