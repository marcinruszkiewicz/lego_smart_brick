#!/usr/bin/env python3
"""
Probe LEGO Bilbo backend APIs for firmware updates and service information.

Endpoints discovered from SmartAssist IL2CPP dump:
  - P11 Firmware: https://p11.bilbo.lego.com
  - AUP (Updates): https://aup.bilbo.lego.com
  - ACT (Telemetry): https://act.bilbo.lego.com
  - External Topics: https://external.bilbo.lego.com

Known firmware update flow:
  1. GET {P11}/update/{product}/state?version={version}  → state hash
  2. GET {AUP}/update/{state}/download                   → firmware binary
"""

import json
import sys
import hashlib
from pathlib import Path

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

P11_BASE = "https://p11.bilbo.lego.com"
AUP_BASE = "https://aup.bilbo.lego.com"
ACT_BASE = "https://act.bilbo.lego.com"
EXT_BASE = "https://external.bilbo.lego.com"

PRODUCTS = ["AudioBrick", "PanelCharger"]
KNOWN_VERSIONS = [
    "1.85.0", "1.86.1", "1.92.0", "1.98.5", "1.98.7", "1.98.14", "1.98.15",
    "1.119.0", "1.122.0",
    "2.3.0", "2.18.0", "2.21.0", "2.25.0", "2.28.0", "2.29.0", "2.29.1",
]

HEADERS = {
    "User-Agent": "OpenAPI-Generator/1.0.0/csharp",
    "Accept": "application/json",
}

OUTPUT_DIR = Path(__file__).parent / "bilbo_results"


def probe_firmware_state(product, version, verbose=True):
    """GET /update/{product}/state?version={version}"""
    url = f"{P11_BASE}/update/{product}/state"
    params = {"version": version}
    try:
        r = requests.get(url, params=params, headers=HEADERS, timeout=10)
        if verbose:
            print(f"  [{r.status_code}] {url}?version={version}")
        if r.status_code == 200:
            return r.text.strip().strip('"')
        return None
    except Exception as e:
        if verbose:
            print(f"  [ERROR] {url}: {e}")
        return None


def probe_beta_state(product, version, verbose=True):
    """GET /update/beta/{product}/state?version={version}"""
    url = f"{P11_BASE}/update/beta/{product}/state"
    params = {"version": version}
    try:
        r = requests.get(url, params=params, headers=HEADERS, timeout=10)
        if verbose:
            print(f"  [{r.status_code}] {url}?version={version}")
        if r.status_code == 200:
            return r.text.strip().strip('"')
        return None
    except Exception as e:
        if verbose:
            print(f"  [ERROR] {url}: {e}")
        return None


def download_firmware(state_hash, output_path=None, verbose=True):
    """GET /update/{state}/download → firmware binary"""
    url = f"{AUP_BASE}/update/{state_hash}/download"
    try:
        r = requests.get(url, headers=HEADERS, timeout=30, stream=True)
        if verbose:
            print(f"  [{r.status_code}] {url} → {r.headers.get('content-length', '?')} bytes")
        if r.status_code == 200:
            data = r.content
            if output_path:
                Path(output_path).write_bytes(data)
                if verbose:
                    sha = hashlib.sha256(data).hexdigest()[:16]
                    print(f"  Saved: {output_path} ({len(data)} bytes, sha256={sha}...)")
            return data
        return None
    except Exception as e:
        if verbose:
            print(f"  [ERROR] {url}: {e}")
        return None


def probe_aup_endpoints(verbose=True):
    """Try AUP QA endpoints that might not need auth."""
    endpoints = [
        "/api/products",
        "/api/releases",
        "/api/channels",
        "/health",
        "/",
    ]
    results = {}
    for ep in endpoints:
        url = f"{AUP_BASE}{ep}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            if verbose:
                print(f"  [{r.status_code}] {url}")
            if r.status_code == 200:
                results[ep] = r.text[:500]
        except Exception as e:
            if verbose:
                print(f"  [ERROR] {url}: {e}")
    return results


def probe_enigma_endpoints(verbose=True):
    """Try Enigma (crypto) endpoints — likely need auth but worth checking."""
    base = EXT_BASE
    endpoints = [
        "/api/v1/enigma/publickey",
        "/api/v1/enigma/sharedkey",
    ]
    results = {}
    for ep in endpoints:
        url = f"{base}{ep}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            if verbose:
                print(f"  [{r.status_code}] {url}")
                if r.status_code != 404:
                    print(f"    Response: {r.text[:200]}")
            results[ep] = {'status': r.status_code, 'body': r.text[:500]}
        except Exception as e:
            if verbose:
                print(f"  [ERROR] {url}: {e}")
    return results


def probe_elements_endpoints(verbose=True):
    """Try element management endpoints."""
    base = EXT_BASE
    endpoints = [
        "/api/v1/elements/owned",
        "/api/v1/elements/register",
    ]
    results = {}
    for ep in endpoints:
        url = f"{base}{ep}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            if verbose:
                print(f"  [{r.status_code}] {url}")
                if r.status_code not in (404, 405):
                    print(f"    Response: {r.text[:200]}")
            results[ep] = {'status': r.status_code, 'body': r.text[:500]}
        except Exception as e:
            if verbose:
                print(f"  [ERROR] {url}: {e}")
    return results


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("LEGO Bilbo API Probe")
    print("=" * 60)

    # 1. Probe firmware state for all product/version combinations
    print("\n--- Firmware State Queries ---")
    states = {}
    for product in PRODUCTS:
        print(f"\nProduct: {product}")
        for version in KNOWN_VERSIONS:
            state = probe_firmware_state(product, version)
            if state:
                states[(product, version)] = state
                print(f"    → state: {state[:40]}...")

        # Also try beta channel
        print(f"\n  Beta channel:")
        for version in KNOWN_VERSIONS[-3:]:
            state = probe_beta_state(product, version)
            if state:
                states[("beta_" + product, version)] = state

    print(f"\nTotal state hashes found: {len(states)}")

    # 2. Try to download firmware for discovered states
    if states:
        print("\n--- Firmware Downloads ---")
        unique_states = list(set(states.values()))
        print(f"Unique state hashes: {len(unique_states)}")
        for state in unique_states[:5]:
            output_path = OUTPUT_DIR / f"firmware_{state[:16]}.bin"
            if output_path.exists():
                print(f"  Already have: {output_path.name}")
                continue
            download_firmware(state, output_path)

    # 3. Probe AUP general endpoints
    print("\n--- AUP Discovery ---")
    probe_aup_endpoints()

    # 4. Probe Enigma endpoints
    print("\n--- Enigma (Crypto) Endpoints ---")
    probe_enigma_endpoints()

    # 5. Probe Elements endpoints
    print("\n--- Elements Endpoints ---")
    probe_elements_endpoints()

    # 6. Save summary
    summary = {
        'states': {f"{p}/{v}": s for (p, v), s in states.items()},
    }
    summary_path = OUTPUT_DIR / "probe_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to: {summary_path}")


if __name__ == "__main__":
    main()
