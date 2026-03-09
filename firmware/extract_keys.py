#!/usr/bin/env python3
"""
Extract candidate AES keys from all firmware versions and cross-reference them.

Strategy:
1. Find high-entropy 16-byte aligned sequences in data regions
2. Focus on the RKEy marker vicinity and key_store region
3. Cross-reference across firmware versions to find constants (likely keys)
4. Output a JSON file consumable by the Elixir AES-CCM decryptor
"""

import json
import math
import struct
from pathlib import Path
from collections import Counter, defaultdict

FW_DIR = Path(__file__).parent / "extracted"
OUTPUT = Path(__file__).parent.parent / "data" / "candidate_keys.json"


def entropy(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def find_strings(data: bytes, min_len=6):
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


def find_key_store_region(data: bytes):
    """Find the key_store.c string and surrounding data region."""
    idx = data.find(b'key_store.c')
    if idx >= 0:
        return idx
    return None


def find_rkey_marker(data: bytes):
    idx = data.find(b'RKEy')
    if idx >= 0:
        return idx
    return None


def find_crypto_strings(data: bytes):
    """Find offsets of AES-CCM related strings."""
    markers = [
        b'AES-CCM', b'AES_CCM', b'DecryptAndMAC',
        b'tag_security', b'Tag security',
        b'key_store', b'BAD_SESSION_KEY',
        b'Tag Verify', b'Tag Payload verify',
    ]
    offsets = []
    for m in markers:
        idx = 0
        while True:
            idx = data.find(m, idx)
            if idx < 0:
                break
            offsets.append(idx)
            idx += 1
    return sorted(offsets)


def is_likely_code(block: bytes) -> bool:
    """Heuristic: ARC EM instructions tend to have specific patterns."""
    if len(block) < 16:
        return False
    small_bytes = sum(1 for b in block if b < 0x10)
    return small_bytes > 8


def extract_candidates(data: bytes, regions=None, alignment=4):
    """Extract high-entropy 16-byte candidate key sequences."""
    candidates = []

    if regions is None:
        regions = [(0, len(data))]

    for start, end in regions:
        for i in range(start, min(end, len(data) - 16), alignment):
            block = data[i:i+16]

            if block == b'\x00' * 16 or block == b'\xff' * 16:
                continue
            if len(set(block)) == 1:
                continue
            # Skip if all ASCII printable
            if all(0x20 <= b < 0x7F for b in block):
                continue
            if b'\x00\x00\x00\x00' in block:
                continue

            unique = len(set(block))
            if unique < 10:
                continue

            ent = entropy(block)
            if ent < 3.0:
                continue

            candidates.append({
                'offset': i,
                'hex': block.hex(),
                'unique_bytes': unique,
                'entropy': round(ent, 3),
            })

    candidates.sort(key=lambda x: -x['entropy'])
    return candidates


def cross_reference_keys(all_versions: dict):
    """Find 16-byte sequences that appear in multiple firmware versions."""
    hex_to_versions = defaultdict(list)

    for version, candidates in all_versions.items():
        for c in candidates:
            hex_to_versions[c['hex']].append({
                'version': version,
                'offset': c['offset'],
            })

    shared = {}
    for hex_key, appearances in hex_to_versions.items():
        if len(appearances) >= 2:
            shared[hex_key] = {
                'count': len(appearances),
                'versions': appearances,
            }

    return shared


def main():
    versions = sorted(FW_DIR.iterdir())
    if not versions:
        print("No firmware versions found")
        return

    all_version_data = {}
    all_version_candidates = {}
    rkey_contexts = {}

    for vdir in versions:
        code_path = vdir / "code.bin"
        if not code_path.exists():
            continue

        version = vdir.name
        data = code_path.read_bytes()
        print(f"\n{'='*60}")
        print(f"Analyzing: {version} ({len(data):,} bytes)")

        # Find key regions of interest
        rkey_off = find_rkey_marker(data)
        ks_off = find_key_store_region(data)
        crypto_offs = find_crypto_strings(data)

        if rkey_off is not None:
            print(f"  RKEy marker at: 0x{rkey_off:06X}")
            ctx = data[max(0, rkey_off-64):rkey_off+64]
            rkey_contexts[version] = {
                'offset': rkey_off,
                'context_hex': ctx.hex(),
            }

        if ks_off is not None:
            print(f"  key_store.c at: 0x{ks_off:06X}")

        if crypto_offs:
            print(f"  Crypto strings: {len(crypto_offs)} matches")
            print(f"    range: 0x{min(crypto_offs):06X} - 0x{max(crypto_offs):06X}")

        # Build regions of interest:
        # 1. Around RKEy marker (+/- 0x1000)
        # 2. Around key_store.c string (+/- 0x2000)
        # 3. Around crypto strings (+/- 0x2000)
        # 4. The last ~20% of the binary (typically .rodata)
        regions = []
        if rkey_off is not None:
            regions.append((max(0, rkey_off - 0x1000), min(len(data), rkey_off + 0x1000)))
        if ks_off is not None:
            regions.append((max(0, ks_off - 0x2000), min(len(data), ks_off + 0x2000)))
        if crypto_offs:
            earliest = min(crypto_offs)
            latest = max(crypto_offs)
            regions.append((max(0, earliest - 0x4000), min(len(data), latest + 0x2000)))
        # rodata region (typically the last portion)
        rodata_start = int(len(data) * 0.8)
        regions.append((rodata_start, len(data)))
        # Also scan the full binary with wider alignment for completeness
        regions.append((0, len(data)))

        candidates = extract_candidates(data, regions, alignment=4)
        # Dedupe by hex
        seen = set()
        deduped = []
        for c in candidates:
            if c['hex'] not in seen:
                seen.add(c['hex'])
                deduped.append(c)
        candidates = deduped

        print(f"  Found {len(candidates)} unique candidate key sequences")
        all_version_candidates[version] = candidates
        all_version_data[version] = data

    # Cross-reference across versions
    print(f"\n{'='*60}")
    print("CROSS-VERSION ANALYSIS")
    print(f"{'='*60}")

    shared = cross_reference_keys(all_version_candidates)
    n_versions = len(all_version_candidates)
    print(f"\nSequences shared across multiple versions: {len(shared)}")

    # Filter to sequences present in ALL or nearly all versions
    universal = {k: v for k, v in shared.items() if v['count'] >= n_versions - 1}
    print(f"Present in {n_versions-1}+ versions: {len(universal)}")

    # RKEy context comparison
    print(f"\n--- RKEy marker comparison ---")
    rkey_hexes = set()
    for version, ctx in rkey_contexts.items():
        rkey_hexes.add(ctx['context_hex'])
        print(f"  {version}: offset=0x{ctx['offset']:06X}")

    if len(rkey_hexes) == 1:
        print("  RKEy context is IDENTICAL across all versions")
    else:
        print(f"  RKEy context has {len(rkey_hexes)} unique variants")

    # Extract the bytes around RKEy that look like key material
    rkey_candidates = []
    if rkey_contexts:
        first_version = list(rkey_contexts.keys())[0]
        first_data = all_version_data[first_version]
        rkey_off = rkey_contexts[first_version]['offset']
        # Check 16-byte aligned blocks around RKEy
        for offset in range(max(0, rkey_off - 256), min(len(first_data) - 16, rkey_off + 256), 4):
            block = first_data[offset:offset+16]
            ent = entropy(block)
            unique = len(set(block))
            if ent > 3.0 and unique >= 8 and b'\x00\x00\x00\x00' not in block:
                rkey_candidates.append({
                    'offset': offset,
                    'hex': block.hex(),
                    'entropy': round(ent, 3),
                    'unique_bytes': unique,
                    'source': 'rkey_vicinity',
                })

    print(f"\n  High-entropy blocks near RKEy: {len(rkey_candidates)}")
    for c in rkey_candidates[:10]:
        print(f"    0x{c['offset']:06X}: {c['hex']} (ent={c['entropy']}, uniq={c['unique_bytes']})")

    # Build the final output with prioritized candidates
    # Filter universal keys to only 16-byte-aligned ones with high entropy
    # (real keys are typically stored at aligned addresses)
    aligned_universal = {}
    for hex_key, info in universal.items():
        offsets = [a['offset'] for a in info['versions']]
        if any(o % 16 == 0 for o in offsets):
            # Check entropy of this key
            key_bytes = bytes.fromhex(hex_key)
            ent = entropy(key_bytes)
            if ent >= 3.5 and len(set(key_bytes)) >= 12:
                aligned_universal[hex_key] = {**info, 'entropy': ent}

    # Further filter: require entropy >= 3.8 and unique >= 14 for truly key-like data
    best_universal = {k: v for k, v in aligned_universal.items()
                      if v['entropy'] >= 3.8}
    # Also keep anything with all 16 unique bytes regardless of alignment
    for hex_key, info in universal.items():
        key_bytes = bytes.fromhex(hex_key)
        if len(set(key_bytes)) == 16:
            ent = entropy(key_bytes)
            best_universal[hex_key] = {**info, 'entropy': ent}

    # Cap at 500
    sorted_univ = sorted(best_universal.items(), key=lambda x: (-x[1]['count'], -x[1]['entropy']))
    capped_universal = dict(sorted_univ[:500])
    print(f"\n16-byte-aligned universal keys with entropy >= 3.8: {len(best_universal)}")
    print(f"After capping to 500: {len(capped_universal)}")

    output = {
        'metadata': {
            'versions_analyzed': list(all_version_candidates.keys()),
            'total_universal': len(universal),
            'filtered_universal': len(aligned_universal),
        },
        'universal_keys': [],
        'rkey_vicinity_keys': [],
        'top_entropy_keys': [],
        'special_candidates': [],
        'uid_derived_note': 'Also try SHA-256(UID)[:16] for per-tag keying',
    }

    # Best universal keys (high entropy, present in most versions, capped)
    for hex_key, info in sorted(capped_universal.items(),
                                 key=lambda x: (-x[1]['count'], -x[1]['entropy'])):
        output['universal_keys'].append({
            'hex': hex_key,
            'versions_present': info['count'],
            'entropy': round(info['entropy'], 3),
        })

    # RKEy vicinity
    output['rkey_vicinity_keys'] = rkey_candidates[:50]

    # Top entropy keys from each version (16-byte aligned, deduplicated)
    top_set = set()
    for version in sorted(all_version_candidates.keys()):
        for c in all_version_candidates[version]:
            if c['offset'] % 16 == 0 and c['entropy'] >= 3.5 and c['hex'] not in top_set:
                top_set.add(c['hex'])
                output['top_entropy_keys'].append(c)
            if len(output['top_entropy_keys']) >= 500:
                break

    # Specific candidate keys based on firmware knowledge
    import hashlib
    string_candidates = [
        "LEGO", "EM", "SmartTag", "DA000001", "P11_audiobrick",
        "LtcaxE", "ExactL", "LEGOSmartPlay", "SmartBrick",
        "audiobrick", "EM9305", "DNP6G", "SmartPlay",
        "P11_audio", "LEGO Smart", "LEGOSmart", "005f",
        "kcirboidua_11P", "EMmicroelec", "ICODE", "SL2S",
        "20043-014", "DNP6G-010", "1055X", "810300",
        "RKEy", "key_store", "tag_asic", "P11", "Bilbo",
    ]
    for s in string_candidates:
        # Padded to 16 bytes
        padded = s.encode('ascii').ljust(16, b'\x00')[:16]
        output['special_candidates'].append({'hex': padded.hex(), 'note': f'padded "{s}"'})
        # SHA-256 derived
        h = hashlib.sha256(s.encode('ascii')).digest()[:16]
        output['special_candidates'].append({'hex': h.hex(), 'note': f'sha256("{s}")[:16]'})

    # Fixed patterns
    for val, note in [(0x00, 'zeros'), (0x01, 'ones'), (0xFF, '0xFF'), (0x0C, '0x0C')]:
        output['special_candidates'].append({'hex': bytes([val]*16).hex(), 'note': note})

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\nOutput written to: {OUTPUT}")
    n_total = (len(output['universal_keys']) + len(output['rkey_vicinity_keys'])
               + len(output['top_entropy_keys']) + len(output['special_candidates']))
    print(f"Total candidate keys: {n_total}")


if __name__ == "__main__":
    main()
