#!/usr/bin/env python3
"""
Analyze NFC tag payloads to identify structure and security format.

Firmware strings tell us:
- "Tag security format" (versioned, can be "unsupported")  
- "Tag security info" (has expected length, checked first)
- "Invalid tag content length"
- "Invalid tag security format length"
- AES-CCM for decrypt + MAC verify
- CRC check
- Tags are Identity or Item type
"""

import json
import sys
from pathlib import Path
from collections import Counter


def load_tags(path):
    tags = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                tags.append(json.loads(line))
    return tags


def parse_tag(tag):
    """Parse a tag's blocks into raw payload bytes."""
    blocks = tag["blocks"]
    # Block 0 is header: [payload_len_hi, payload_len_lo, 0x01, 0x0C]
    header = bytes.fromhex(blocks[0])
    payload_len = (header[0] << 8) | header[1]
    
    # Collect payload bytes from block 1 onwards
    raw = b""
    for b in blocks[1:]:
        if b in ("0001",):  # filler sentinel
            break
        raw += bytes.fromhex(b)
    
    # Trim to declared payload length (minus 4 for header block)
    # Actually payload_len is the total data bytes after header (blocks 1..N)
    # But we need to figure out if payload_len includes header or not
    # From the doc: Vader 169 bytes payload, 43 data blocks = 172 bytes, 3 padding
    # So payload is blocks 0 through 42 (43 blocks), but payload_len=169 counts from block 0 byte 0?
    # No: 43 blocks * 4 = 172, 172 - 169 = 3 padding. So payload starts at block 0.
    # Total "payload" = header block + data blocks
    # payload_len counts all bytes including the 4-byte header? Let's check:
    # Vader: payload_len=169, blocks 0-42 = 43*4=172, 172-169=3 padding
    # Actually payload_len=0xA9=169 is the number of payload bytes INCLUDING the header
    # 43 blocks = 172 bytes, minus 3 trailing zeros = 169 data bytes
    # So: full tag data = blocks[0..42], first payload_len bytes are meaningful
    
    # Let's just take all non-zero blocks and trim
    full_data = bytes.fromhex(blocks[0])
    for b in blocks[1:]:
        if b in ("0001",):
            break
        full_data += bytes.fromhex(b)
    
    payload = full_data[:payload_len]
    return {
        "item": tag.get("item", "unknown"),
        "uid": tag["uid"],
        "payload_len": payload_len,
        "header": header,
        "payload": payload,
        "full_data": full_data,
    }


def analyze_payload_structure(parsed):
    """Look at first bytes of payload (after 4-byte header) for structure."""
    p = parsed["payload"]
    # Skip the 4-byte header (block 0)
    data = p[4:]
    
    print(f"\n{'='*60}")
    print(f"Tag: {parsed['item']}")
    print(f"UID: {parsed['uid']}")
    print(f"Payload length: {parsed['payload_len']} bytes")
    print(f"Data length (excl header): {len(data)} bytes")
    print(f"Header: {parsed['header'].hex()}")
    print(f"First 32 bytes of data:")
    print(f"  {data[:16].hex()}")
    print(f"  {data[16:32].hex()}")
    print(f"Last 16 bytes of data:")
    print(f"  {data[-16:].hex()}")
    
    # Byte 0 of data (block 1 byte 0)
    print(f"\nFirst byte of data: 0x{data[0]:02X} ({data[0]})")
    print(f"Second byte of data: 0x{data[1]:02X} ({data[1]})")
    print(f"Bytes 0-3: {data[:4].hex()}")
    
    return data


def main():
    data_dir = Path(__file__).parent.parent / "data"
    
    all_tags = []
    for f in sorted(data_dir.glob("*.jsonl")):
        tags = load_tags(f)
        all_tags.extend(tags)
        print(f"Loaded {len(tags)} tags from {f.name}")
    
    print(f"\nTotal: {len(all_tags)} tags")
    
    # Parse and deduplicate by content
    seen_payloads = {}
    parsed_tags = []
    for tag in all_tags:
        p = parse_tag(tag)
        payload_hex = p["payload"].hex()
        if payload_hex not in seen_payloads:
            seen_payloads[payload_hex] = p
            parsed_tags.append(p)
        else:
            # Note duplicate
            existing = seen_payloads[payload_hex]
            if p["uid"] != existing["uid"]:
                print(f"  Duplicate payload: {p['item']} (UID {p['uid']}) == {existing['item']} (UID {existing['uid']})")
    
    print(f"Unique payloads: {len(parsed_tags)}")
    
    # Analyze each unique payload
    all_data = []
    for p in parsed_tags:
        data = analyze_payload_structure(p)
        all_data.append((p, data))
    
    # Compare first bytes across all tags
    print(f"\n{'='*60}")
    print("CROSS-TAG COMPARISON")
    print(f"{'='*60}")
    
    print("\nFirst 4 bytes of data (block 1) across all tags:")
    for p, data in all_data:
        print(f"  {p['item'][:30]:<30s}  {data[:4].hex()}  (payload_len={p['payload_len']})")
    
    # Check if byte 0 is consistent (could be format/version)
    byte0s = Counter(data[0] for _, data in all_data)
    print(f"\nByte 0 distribution: {dict(byte0s)}")
    
    byte1s = Counter(data[1] for _, data in all_data)
    print(f"Byte 1 distribution: {dict(byte1s)}")
    
    # Check byte 2-3 patterns
    byte23 = Counter(data[2:4].hex() for _, data in all_data)
    print(f"Bytes 2-3 distribution: {dict(byte23)}")
    
    # Look for common bytes at the end (MAC/tag)
    print("\nLast 8 bytes of each payload:")
    for p, data in all_data:
        print(f"  {p['item'][:30]:<30s}  ...{data[-8:].hex()}")
    
    # Look for structure: is there a fixed-length prefix before the variable content?
    print("\n=== Structure Hypothesis ===")
    print("Firmware tells us:")
    print("  1. 'Tag security format' byte (versioned)")
    print("  2. 'Tag security info' (nonce/IV for AES-CCM)")
    print("  3. Encrypted content")
    print("  4. MAC (authentication tag)")
    print()
    
    # AES-CCM typically has:
    # - Nonce: 7-13 bytes (commonly 13 for CCM)
    # - MAC: 4-16 bytes (commonly 4, 8, or 16)
    # The first few bytes might be: [format_byte, ...nonce..., ...ciphertext..., ...mac...]
    
    # Let's check if all tags start with 0x01
    if all(data[0] == 0x01 for _, data in all_data):
        print("All tags start with 0x01 -- likely security format version 1")
    
    # Byte 1 varies -- could be part of the nonce or a type indicator
    print(f"\nByte 1 values (hex): {[f'0x{data[1]:02X}' for _, data in all_data]}")
    
    # Check if same-type tags share any prefix bytes
    print("\nComparing Identity tags:")
    identity_tags = [(p, d) for p, d in all_data if 'Identity' in p['item'] or 'identity' in p['item']]
    if len(identity_tags) >= 2:
        for i in range(min(20, min(len(d) for _, d in identity_tags))):
            vals = set(d[i] for _, d in identity_tags)
            if len(vals) == 1:
                print(f"  Byte {i}: ALL same = 0x{list(vals)[0]:02X}")
            elif len(vals) < len(identity_tags):
                print(f"  Byte {i}: partially shared = {[f'0x{v:02X}' for v in sorted(vals)]}")
    
    print("\nComparing Item tags:")
    item_tags = [(p, d) for p, d in all_data if 'Item' in p['item'] or 'item' in p['item']]
    if len(item_tags) >= 2:
        for i in range(min(20, min(len(d) for _, d in item_tags))):
            vals = set(d[i] for _, d in item_tags)
            if len(vals) == 1:
                print(f"  Byte {i}: ALL same = 0x{list(vals)[0]:02X}")
            elif len(vals) < len(item_tags):
                print(f"  Byte {i}: partially shared = {[f'0x{v:02X}' for v in sorted(vals)]}")

    # Entropy analysis
    print("\n=== Entropy by position ===")
    max_len = max(len(d) for _, d in all_data)
    for pos in range(min(20, max_len)):
        vals = [d[pos] for _, d in all_data if pos < len(d)]
        unique = len(set(vals))
        print(f"  Byte {pos:2d}: {unique:2d} unique out of {len(vals)} tags  vals={[f'{v:02X}' for v in vals]}")


if __name__ == "__main__":
    main()
