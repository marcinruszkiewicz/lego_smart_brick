# Grain-128A Key Recovery Attack

Prototype implementation of a guess-and-determine attack on Grain-128A (ISO/IEC 29167-13) using 320 bits of known keystream from LEGO smart brick NFC tags.

## Background

We have:
- **4 ship tags** (X-Wing, TIE Fighter, Millennium Falcon, A-Wing) with identical 90-byte plaintext structure
- **10 known plaintext bytes** at offsets 53-69 per tag (from firmware dispatch chain tracing)
- **40 known keystream bytes** total (10 per tag × 4 tags) = **320 bits of constraint** on the 128-bit key
- **Per-tag IVs** extracted from bytes 5-16 of each tag payload

The key is uniquely determined by these constraints (320 bits > 128 bits). The challenge is *inverting* Grain-128A's 256 nonlinear initialization rounds to go from keystream to key.

## Attack landscape

### What's been tried (by node-smartplay)

| Method | Result |
| --- | --- |
| SAT solver (z3) | Timed out on full 256 rounds; worked up to ~64 rounds |
| SAT solver (CryptoMiniSat) | ~90K variables, killed after 2+ hours |
| Brute force (2^128) | Infeasible |

### Published attacks on Grain-128A

| Attack | Complexity | Notes |
| --- | --- | --- |
| Exhaustive key search | 2^128 | Baseline |
| BSW sampling (2014) | 2^105 ops, 2^82.59 memory | Requires multiple IV sessions |
| State bit recovery (2021) | 35-48 state bits recoverable | Fixes 34-54 bits, solves rest |
| Probabilistic algebraic (2014) | Sub-exhaustive | Exploits LFSR/NFSR structure |
| Fast correlation on LFSR (2022) | Sub-exhaustive | Vectorial decoding |
| Conditional differential (2017) | Reduced-round | Full rounds still resistant |
| Side-channel (2025) | Practical (hours) | Requires physical access to ASIC |

### The ISO 29167-13 advantage

ISO 29167-13 Grain-128A does **not** reintroduce the key during initialization (unlike Grain-128AEAD/AEADv2). This means:
- Internal state after 256 init rounds → key recovery is possible by inverting init
- Known keystream → known pre-output bits → system of equations on internal state
- Each keystream bit gives one equation involving LFSR and NFSR bits

## Our approach: guess-and-determine

### Strategy

1. **After initialization**, the internal state is (NFSR[128], LFSR[128]) = 256 bits
2. **Each keystream bit** provides one equation: `z_t = h(NFSR, LFSR) XOR lfsr[93] XOR nfsr[2] XOR nfsr[15] XOR nfsr[36] XOR nfsr[45] XOR nfsr[64] XOR nfsr[73] XOR nfsr[89]`
3. **Guess a portion of the state** (e.g. LFSR[0..63]), then solve for the remainder using the keystream equations and feedback structure
4. **Verify** against the 320-bit constraint — wrong guesses are rejected immediately

### Complexity estimate

- Guessing 64 LFSR bits: 2^64 candidates
- For each guess: ~100 operations to propagate and check against keystream
- Total: ~2^64 × 100 ≈ 2^71 operations
- At 10^9 ops/sec (single core): ~74 years
- At 10^12 ops/sec (GPU cluster): ~27 days
- At 10^13 ops/sec (large GPU cluster): ~2.7 days

### Reducing the guess space

The `h` function involves specific LFSR and NFSR taps. By choosing which bits to guess strategically:
- Guess LFSR bits that appear in `h` and feedback: positions 8, 13, 20, 42, 60, 79, 93, 94, 0, 7, 38, 70, 81, 96
- Each known keystream bit adds one constraint, reducing effective search
- With 320 constraint bits and careful algebraic reduction, the effective search space may be significantly below 2^64

## Files

| File | Description |
| --- | --- |
| `grain128a.c` | Optimized C implementation of Grain-128A with keystream verification |
| `grain128a.h` | Header with state structures and API |
| `attack.c` | Guess-and-determine attack main loop |
| `Makefile` | Build with `make` (requires GCC or Clang) |
| `README.md` | This file |

## Building and running

```bash
make
./grain_attack --verify    # Verify cipher against known test vectors
./grain_attack --benchmark # Benchmark keystream generation speed
./grain_attack --search    # Run guess-and-determine search (long!)
```

## CUDA extension (future)

The inner loop is embarrassingly parallel — each LFSR guess is independent. A CUDA kernel can test ~10^12 candidates/sec on a modern GPU. The `attack.c` code is structured to be easily ported to CUDA:
- `test_lfsr_guess()` is a pure function with no side effects
- State is 256 bits (fits in registers)
- The verification check provides early rejection (first keystream byte mismatch → skip)
