#include "grain128a.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static inline int bit128(uint128_t x, int i) {
    return (int)((x >> i) & 1);
}

static inline uint128_t shift128(uint128_t val, int new_bit) {
    return (val >> 1) | ((uint128_t)(new_bit & 1) << 127);
}

static int h_func(uint128_t nfsr, uint128_t lfsr) {
    int x0 = bit128(nfsr, 12);
    int x1 = bit128(lfsr, 8);
    int x2 = bit128(lfsr, 13);
    int x3 = bit128(lfsr, 20);
    int x4 = bit128(nfsr, 95);
    int x5 = bit128(lfsr, 42);
    int x6 = bit128(lfsr, 60);
    int x7 = bit128(lfsr, 79);
    int x8 = bit128(lfsr, 94);

    return (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8);
}

uint8_t grain_preoutput_bit(const grain_state_t *s) {
    int hv = h_func(s->nfsr, s->lfsr);
    return hv
        ^ bit128(s->lfsr, 93)
        ^ bit128(s->nfsr, 2)
        ^ bit128(s->nfsr, 15)
        ^ bit128(s->nfsr, 36)
        ^ bit128(s->nfsr, 45)
        ^ bit128(s->nfsr, 64)
        ^ bit128(s->nfsr, 73)
        ^ bit128(s->nfsr, 89);
}

static int l_feedback(uint128_t lfsr) {
    return bit128(lfsr, 0) ^ bit128(lfsr, 7)
         ^ bit128(lfsr, 38) ^ bit128(lfsr, 70)
         ^ bit128(lfsr, 81) ^ bit128(lfsr, 96);
}

static int f_feedback(uint128_t nfsr, uint128_t lfsr) {
    int s0 = bit128(lfsr, 0);
    int t0 = bit128(nfsr, 0) ^ bit128(nfsr, 26)
           ^ bit128(nfsr, 56) ^ bit128(nfsr, 91) ^ bit128(nfsr, 96);
    int t1 = bit128(nfsr, 3) & bit128(nfsr, 67);
    int t2 = bit128(nfsr, 11) & bit128(nfsr, 13);
    int t3 = bit128(nfsr, 17) & bit128(nfsr, 18);
    int t4 = bit128(nfsr, 27) & bit128(nfsr, 59);
    int t5 = bit128(nfsr, 40) & bit128(nfsr, 48);
    int t6 = bit128(nfsr, 61) & bit128(nfsr, 65);
    int t7 = bit128(nfsr, 68) & bit128(nfsr, 84);
    int t8 = bit128(nfsr, 22) & bit128(nfsr, 24) & bit128(nfsr, 25);
    int t9 = bit128(nfsr, 70) & bit128(nfsr, 78) & bit128(nfsr, 82);
    int t10 = bit128(nfsr, 88) & bit128(nfsr, 92)
            & bit128(nfsr, 93) & bit128(nfsr, 95);

    return s0 ^ t0 ^ t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7 ^ t8 ^ t9 ^ t10;
}

void grain_clock(grain_state_t *s) {
    int ln = l_feedback(s->lfsr);
    int fn = f_feedback(s->nfsr, s->lfsr);
    s->nfsr = shift128(s->nfsr, fn);
    s->lfsr = shift128(s->lfsr, ln);
}

void grain_clock_init(grain_state_t *s) {
    int y = grain_preoutput_bit(s);
    int ln = l_feedback(s->lfsr) ^ y;
    int fn = f_feedback(s->nfsr, s->lfsr) ^ y;
    s->nfsr = shift128(s->nfsr, fn);
    s->lfsr = shift128(s->lfsr, ln);
}

static uint128_t load_le128(const uint8_t *buf, size_t len) {
    uint128_t val = 0;
    for (size_t i = 0; i < len; i++)
        val |= (uint128_t)buf[i] << (8 * i);
    return val;
}

void grain_init(grain_state_t *s, const uint8_t key[16], const uint8_t iv[12]) {
    s->nfsr = load_le128(key, 16);
    uint128_t iv_val = load_le128(iv, 12);
    s->lfsr = iv_val | (((uint128_t)0x7FFFFFFF) << 96);

    for (int i = 0; i < 256; i++)
        grain_clock_init(s);
}

void grain_keystream(grain_state_t *s, uint8_t *out, size_t num_bytes) {
    memset(out, 0, num_bytes);
    for (size_t i = 0; i < num_bytes; i++) {
        uint8_t byte_val = 0;
        for (int j = 0; j < 8; j++) {
            byte_val |= (grain_preoutput_bit(s) << (7 - j));
            grain_clock(s);
        }
        out[i] = byte_val;
    }
}

bool grain_verify_keystream(const uint8_t key[16], const grain_constraint_t *constraints,
                            size_t num_constraints) {
    for (size_t c = 0; c < num_constraints; c++) {
        grain_state_t s;
        grain_init(&s, key, constraints[c].iv);

        size_t ks_len = constraints[c].ks_len;
        uint8_t ks[256];
        grain_keystream(&s, ks, ks_len);

        if (memcmp(ks, constraints[c].keystream, ks_len) != 0)
            return false;
    }
    return true;
}

void grain_self_test(void) {
    uint8_t key[16], iv[12];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)i;

    grain_state_t s1, s2;
    uint8_t ks1[32], ks2[32];

    grain_init(&s1, key, iv);
    grain_keystream(&s1, ks1, 32);

    grain_init(&s2, key, iv);
    grain_keystream(&s2, ks2, 32);

    if (memcmp(ks1, ks2, 32) != 0) {
        fprintf(stderr, "FAIL: same key+IV produced different keystream\n");
        exit(1);
    }

    uint8_t iv_alt[12];
    for (int i = 0; i < 12; i++) iv_alt[i] = (uint8_t)(i ^ 0xFF);
    grain_state_t s3;
    uint8_t ks3[32];
    grain_init(&s3, key, iv_alt);
    grain_keystream(&s3, ks3, 32);

    if (memcmp(ks1, ks3, 32) == 0) {
        fprintf(stderr, "FAIL: different IV produced same keystream\n");
        exit(1);
    }

    printf("grain_self_test: OK (ks[0..7] = ");
    for (int i = 0; i < 8; i++) printf("%02X", ks1[i]);
    printf(")\n");
}
