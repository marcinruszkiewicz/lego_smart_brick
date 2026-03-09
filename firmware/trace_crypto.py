#!/usr/bin/env python3
"""
Trace AES-CCM and tag crypto code paths in the ARC disassembly.

Since AES is hardware-accelerated (no S-box), we trace from:
1. Known string addresses (AES_CCM_*, key_store.c, Tag security*, etc.)
2. Find what code references those string addresses
3. Identify function boundaries and key loading patterns
4. Look for constants that could be key material addresses

ARC EM addressing: strings are loaded via mov instructions with immediate addresses.
"""

import re
import struct
from pathlib import Path
from collections import defaultdict

FW_DIR = Path(__file__).parent / "extracted"
DISASM_DIR = Path(__file__).parent / "disassembly"
VERSION = "fw_v1.119.0"
FLASH_BASE = 0x306000  # from summary.json


def find_string_offsets(code_bin: bytes):
    """Find offsets of key strings in the firmware binary."""
    strings_to_find = {
        'AES-CCM context create failed': None,
        'AES_CCM_DecryptAndMAC failed': None,
        'AES_CCM_GetMAC failed': None,
        'AES_CCM MAC verification failed': None,
        'Tag security verification passed': None,
        'Tag security information not present': None,
        'Invalid tag security format': None,
        'Invalid tag security info length': None,
        'Unsupported tag security format': None,
        'key_store.c': None,
        'BAD_SESSION_KEY': None,
        'RKEy': None,
        'tag_asic.c': None,
        'tag_message_parser.c': None,
        'Tag Verify Fail': None,
        'Tag Payload verify failed': None,
        'Tag is claimed': None,
        'encrypted_telemetry.c': None,
    }

    for s in strings_to_find:
        idx = code_bin.find(s.encode('ascii'))
        if idx >= 0:
            strings_to_find[s] = idx

    return strings_to_find


def find_address_references(disasm_lines: list, target_addr: int, window=20):
    """Find disassembly lines that reference a given address.

    ARC loads addresses via: mov_s rN, 0xADDRESS
    We look for the hex representation of the address.
    """
    addr_hex = f"0x{target_addr:x}"
    addr_hex_padded = f"0x{target_addr:06x}"
    results = []

    for i, line in enumerate(disasm_lines):
        if addr_hex in line.lower() or addr_hex_padded in line.lower():
            context_start = max(0, i - window)
            context_end = min(len(disasm_lines), i + window + 1)
            results.append({
                'line_num': i,
                'line': line.rstrip(),
                'context': [l.rstrip() for l in disasm_lines[context_start:context_end]],
            })

    return results


def find_function_at(disasm_lines: list, target_line: int):
    """Find the function containing a given line by searching backwards for enter_s."""
    for i in range(target_line, max(0, target_line - 500), -1):
        line = disasm_lines[i]
        if 'enter_s' in line or 'push_s' in line:
            # Extract address from the line
            match = re.match(r'\s*([0-9a-f]+):', line)
            if match:
                return int(match.group(1), 16), i
    return None, None


def extract_constants_from_context(context_lines: list):
    """Extract hex constants from nearby instructions that could be addresses or key material."""
    constants = []
    for line in context_lines:
        # Match mov_s rN, 0xHEX patterns
        for match in re.finditer(r'(?:mov|ld|add)\S*\s+\S+,\s*0x([0-9a-fA-F]{4,8})', line):
            val = int(match.group(1), 16)
            constants.append(val)
        # Match immediate values in instructions
        for match in re.finditer(r'0x([0-9a-fA-F]{6,8})', line):
            val = int(match.group(1), 16)
            if 0x1000 <= val <= 0x100000:
                constants.append(val)
    return list(set(constants))


def analyze_key_store_region(code_bin: bytes, disasm_lines: list, ks_offset: int):
    """Deep analysis of the key_store.c region."""
    print(f"\n{'='*60}")
    print(f"KEY STORE ANALYSIS (key_store.c at 0x{ks_offset:06X})")
    print(f"{'='*60}")

    refs = find_address_references(disasm_lines, ks_offset)
    print(f"\nReferences to key_store.c string: {len(refs)}")
    for ref in refs[:5]:
        func_addr, func_line = find_function_at(disasm_lines, ref['line_num'])
        print(f"\n  Reference at line {ref['line_num']}:")
        print(f"  Instruction: {ref['line']}")
        if func_addr is not None:
            print(f"  In function at: 0x{func_addr:06X}")

        # Look for key-related constants in the context
        constants = extract_constants_from_context(ref['context'])
        if constants:
            print(f"  Nearby constants: {[f'0x{c:06X}' for c in constants]}")
            for c in constants:
                bin_off = c - FLASH_BASE if c >= FLASH_BASE else c
                if 0 < bin_off < len(code_bin) - 16:
                    data = code_bin[bin_off:bin_off+16]
                    if len(set(data)) > 8 and not all(0x20 <= b < 0x7F for b in data):
                        print(f"    Data at 0x{c:06X} (bin 0x{bin_off:06X}): {data.hex()}")


def analyze_aes_ccm_functions(code_bin: bytes, disasm_lines: list, string_offsets: dict):
    """Trace AES-CCM function calls to find key loading."""
    print(f"\n{'='*60}")
    print("AES-CCM FUNCTION TRACE")
    print(f"{'='*60}")

    ccm_strings = {s: o for s, o in string_offsets.items()
                   if o is not None and ('AES' in s or 'CCM' in s)}

    for string, offset in sorted(ccm_strings.items(), key=lambda x: x[1]):
        print(f"\n--- '{string}' at 0x{offset:06X} ---")
        refs = find_address_references(disasm_lines, offset)
        print(f"  Referenced {len(refs)} time(s) in code")

        for ref in refs[:3]:
            func_addr, func_line = find_function_at(disasm_lines, ref['line_num'])
            if func_addr is not None:
                print(f"\n  Function at 0x{func_addr:06X}:")
                # Show the function's first 40 lines
                func_end = min(len(disasm_lines), func_line + 60)
                func_lines = disasm_lines[func_line:func_end]

                # Look for bl (branch-link) instructions = function calls
                calls = []
                key_loads = []
                for fl in func_lines:
                    fl_stripped = fl.strip()
                    # Function calls
                    if '\tbl' in fl_stripped and ';' in fl_stripped:
                        calls.append(fl_stripped)
                    # Look for mov with addresses that could be key pointers
                    if 'mov' in fl_stripped:
                        for m in re.finditer(r'0x([0-9a-fA-F]{5,8})', fl_stripped):
                            addr = int(m.group(1), 16)
                            if 0 < addr < len(code_bin):
                                key_loads.append((fl_stripped, addr))

                if calls:
                    print(f"  Function calls:")
                    for c in calls[:10]:
                        print(f"    {c}")

                if key_loads:
                    print(f"  Address loads (potential key pointers):")
                    for instr, addr in key_loads[:10]:
                        # Convert flash address to binary offset
                        bin_off = addr - FLASH_BASE if addr >= FLASH_BASE else addr
                        if 0 <= bin_off < len(code_bin) - 16:
                            data = code_bin[bin_off:bin_off+16]
                            print(f"    {instr}")
                            print(f"      → data at 0x{addr:06X} (bin 0x{bin_off:06X}): {data.hex()}")


def analyze_tag_security_flow(code_bin: bytes, disasm_lines: list, string_offsets: dict):
    """Trace the tag security verification flow."""
    print(f"\n{'='*60}")
    print("TAG SECURITY VERIFICATION FLOW")
    print(f"{'='*60}")

    flow_strings = [
        'Tag security information not present',
        'Invalid tag security info length',
        'Invalid tag security format length',
        'Unsupported tag security format',
        'AES-CCM context create failed',
        'AES_CCM_DecryptAndMAC failed',
        'AES_CCM_GetMAC failed',
        'AES_CCM MAC verification failed',
        'Tag security verification passed',
        'Tag Verify Fail',
        'Tag Payload verify failed',
    ]

    # Find which functions contain these strings (they should be in the same function)
    func_counts = defaultdict(list)
    for s in flow_strings:
        offset = string_offsets.get(s)
        if offset is None:
            continue
        refs = find_address_references(disasm_lines, offset)
        for ref in refs:
            func_addr, _ = find_function_at(disasm_lines, ref['line_num'])
            if func_addr is not None:
                func_counts[func_addr].append(s)

    print(f"\nFunctions containing tag security strings:")
    for func_addr, strings in sorted(func_counts.items(), key=lambda x: -len(x[1])):
        print(f"\n  Function 0x{func_addr:06X} ({len(strings)} security strings):")
        for s in strings:
            print(f"    - {s}")

    # The function with the most strings is likely the main tag verification function
    if func_counts:
        main_func = max(func_counts.keys(), key=lambda k: len(func_counts[k]))
        print(f"\n  === MAIN TAG VERIFICATION FUNCTION: 0x{main_func:06X} ===")

        # Find this function in the disassembly and analyze it
        for i, line in enumerate(disasm_lines):
            match = re.match(rf'\s*{main_func:x}:', line)
            if match:
                # Dump the full function (up to next enter_s or reasonable limit)
                func_end = i + 1
                for j in range(i + 1, min(len(disasm_lines), i + 500)):
                    if 'enter_s' in disasm_lines[j] and j > i + 5:
                        func_end = j
                        break
                    func_end = j

                func_text = disasm_lines[i:func_end]
                print(f"  Function size: ~{len(func_text)} lines")

                # Find all address references in this function
                all_addrs = []
                for fl in func_text:
                    for m in re.finditer(r'0x([0-9a-fA-F]{5,8})', fl):
                        addr = int(m.group(1), 16)
                        if 0 < addr < len(code_bin):
                            all_addrs.append(addr)

                # Check which of these might be key material
                print(f"\n  Address constants in this function: {len(all_addrs)}")
                print(f"  Checking for key material at referenced addresses:")
                checked = set()
                for addr in all_addrs:
                    if addr in checked:
                        continue
                    checked.add(addr)
                    bin_off = addr - FLASH_BASE if addr >= FLASH_BASE else addr
                    if bin_off < 0 or bin_off >= len(code_bin) - 16:
                        continue
                    data = code_bin[bin_off:bin_off+16]
                    if len(data) < 16:
                        continue
                    unique = len(set(data))
                    is_string = all(0x20 <= b < 0x7F or b == 0 for b in data)
                    if unique >= 10 and not is_string:
                        print(f"    0x{addr:06X} (bin 0x{bin_off:06X}): {data.hex()} (unique={unique})")

                break


def find_functions(disasm_lines):
    """Find all function entry points (enter_s or push_s blink)."""
    functions = []
    for i, line in enumerate(disasm_lines):
        if 'enter_s' in line or ('push_s' in line and 'blink' in line):
            match = re.match(r'\s*([0-9a-f]+):', line)
            if match:
                functions.append({
                    'addr': int(match.group(1), 16),
                    'line': i,
                })
    return functions


def analyze_function_region(disasm_lines, start_line, max_lines=300):
    """Analyze a function region to find what addresses it references."""
    hw_regs = set()     # 0x8xxxxx hardware registers
    flash_addrs = set() # 0x30xxxx-0x37xxxx flash data references
    calls = []
    strings_loaded = []

    for i in range(start_line, min(len(disasm_lines), start_line + max_lines)):
        line = disasm_lines[i]
        # Stop at next function
        if i > start_line + 2 and ('enter_s' in line or ('push_s' in line and 'blink' in line)):
            break

        for m in re.finditer(r'0x([0-9a-fA-F]{5,8})', line):
            val = int(m.group(1), 16)
            if 0x800000 <= val <= 0x80FFFF:
                hw_regs.add(val)
            elif FLASH_BASE <= val <= FLASH_BASE + 0x80000:
                flash_addrs.add(val)

        if '\tbl' in line and ';' in line:
            m = re.search(r';([0-9a-f]+)', line)
            if m:
                calls.append(int(m.group(1), 16))

    return {
        'hw_regs': hw_regs,
        'flash_addrs': flash_addrs,
        'calls': calls,
    }


def deep_function_analysis(code_bin, disasm_lines):
    """Find functions that access both crypto HW registers and flash data."""
    print(f"\n{'='*60}")
    print("DEEP FUNCTION ANALYSIS: Crypto HW + Flash Data")
    print(f"{'='*60}")

    functions = find_functions(disasm_lines)
    print(f"Total functions found: {len(functions)}")

    crypto_hw_range = range(0x808800, 0x808A00)
    interesting = []

    for func in functions:
        info = analyze_function_region(disasm_lines, func['line'])
        crypto_regs = [r for r in info['hw_regs'] if r in crypto_hw_range]
        if crypto_regs and info['flash_addrs']:
            interesting.append({
                'addr': func['addr'],
                'line': func['line'],
                'crypto_regs': sorted(crypto_regs),
                'flash_addrs': sorted(info['flash_addrs']),
                'calls': info['calls'][:5],
            })

    print(f"Functions accessing crypto HW (0x808800+) AND flash data: {len(interesting)}\n")

    for func in interesting:
        print(f"  Function 0x{func['addr']:06X} (line {func['line']}):")
        print(f"    Crypto regs: {[f'0x{r:06X}' for r in func['crypto_regs']]}")
        print(f"    Flash addrs: {[f'0x{a:06X}' for a in func['flash_addrs']]}")
        if func['calls']:
            print(f"    Calls: {[f'0x{c:06X}' for c in func['calls']]}")

        # Check flash data for key-like material
        for addr in func['flash_addrs']:
            bin_off = addr - FLASH_BASE
            if 0 <= bin_off < len(code_bin) - 16:
                data = code_bin[bin_off:bin_off+16]
                unique = len(set(data))
                is_str = all(0x20 <= b < 0x7F or b == 0 for b in data)
                if is_str:
                    s_end = data.find(0)
                    if s_end < 0: s_end = 16
                    print(f"    → 0x{addr:06X}: \"{data[:s_end].decode('ascii')}\"")
                elif unique >= 8:
                    print(f"    → 0x{addr:06X} (bin 0x{bin_off:06X}): {data.hex()} (unique={unique})")
                else:
                    print(f"    → 0x{addr:06X} (bin 0x{bin_off:06X}): {data.hex()}")
        print()

    # Also look for functions that access 0x808904 (appears in tag security code)
    print(f"\n--- Functions accessing 0x808904 ---")
    for func in functions:
        info = analyze_function_region(disasm_lines, func['line'])
        if 0x808904 in info['hw_regs']:
            print(f"  Function 0x{func['addr']:06X}:")
            print(f"    HW regs: {[f'0x{r:06X}' for r in sorted(info['hw_regs'])]}")
            print(f"    Flash: {[f'0x{a:06X}' for a in sorted(info['flash_addrs'])]}")
            for addr in info['flash_addrs']:
                bin_off = addr - FLASH_BASE
                if 0 <= bin_off < len(code_bin) - 16:
                    data = code_bin[bin_off:bin_off+16]
                    unique = len(set(data))
                    is_str = all(0x20 <= b < 0x7F or b == 0 for b in data)
                    if not is_str and unique >= 8:
                        print(f"      → 0x{addr:06X}: {data.hex()} (unique={unique})")

    return interesting


def main():
    code_path = FW_DIR / VERSION / "code.bin"
    disasm_path = DISASM_DIR / VERSION / "disasm.txt"

    if not code_path.exists():
        print(f"Not found: {code_path}")
        return
    if not disasm_path.exists():
        print(f"Not found: {disasm_path}")
        return

    code_bin = code_path.read_bytes()
    disasm_lines = disasm_path.read_text().splitlines()
    print(f"Loaded: {VERSION} ({len(code_bin):,} bytes code, {len(disasm_lines):,} disasm lines)")

    string_offsets = find_string_offsets(code_bin)
    print(f"\nKey string offsets (binary):")
    for s, o in sorted(string_offsets.items(), key=lambda x: x[1] or 0):
        if o is not None:
            flash = o + FLASH_BASE
            ref = flash + 2  # code references are +2 due to prefix
            print(f"  0x{o:06X} (flash 0x{flash:06X}, ref 0x{ref:06X}): {s}")

    # Deep function analysis
    interesting = deep_function_analysis(code_bin, disasm_lines)

    # Find the tag security verification function by searching for
    # the corrected string reference addresses
    print(f"\n{'='*60}")
    print("TAG SECURITY FUNCTION SEARCH (corrected addresses)")
    print(f"{'='*60}")

    tag_sec_refs = {
        'AES-CCM context create': 0x06F090 + FLASH_BASE + 2,
        'AES_CCM_DecryptAndMAC': 0x06F482 + FLASH_BASE + 2,
        'AES_CCM_GetMAC': 0x06F806 + FLASH_BASE + 2,
        'Tag security passed': 0x06FB1A + FLASH_BASE + 2,
        'Tag Payload verify': 0x06F881 + FLASH_BASE + 2,
        'AES_CCM MAC verif': 0x06FACF + FLASH_BASE + 2,
    }

    for name, addr in tag_sec_refs.items():
        refs = find_address_references(disasm_lines, addr, window=5)
        if refs:
            print(f"\n  '{name}' (0x{addr:06X}): {len(refs)} reference(s)")
            for ref in refs[:2]:
                func_addr, func_line = find_function_at(disasm_lines, ref['line_num'])
                if func_addr:
                    print(f"    In function 0x{func_addr:06X} (line {func_line})")

    # Check the RKEy region
    rkey_off = string_offsets.get('RKEy')
    if rkey_off:
        rkey_flash = rkey_off + FLASH_BASE
        print(f"\n{'='*60}")
        print(f"RKEy MARKER (binary 0x{rkey_off:06X}, flash 0x{rkey_flash:06X})")
        print(f"{'='*60}")
        context = code_bin[max(0, rkey_off-32):rkey_off+64]
        print(f"  Context: {context.hex()}")
        # RKEy is likely part of a data structure, not code
        # Look for what references this area
        for offset in range(rkey_off - 32, rkey_off + 32, 4):
            flash_addr = offset + FLASH_BASE
            refs = find_address_references(disasm_lines, flash_addr, window=2)
            if refs:
                print(f"  0x{flash_addr:06X} referenced at: {refs[0]['line']}")


if __name__ == "__main__":
    main()
