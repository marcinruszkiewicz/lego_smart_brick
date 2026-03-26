#include "grain128a_bs.h"
#include "grain128a.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Circular-buffer accessors.
 * L(s,i) = bit i of LFSR for all 64 candidates.
 * N(s,i) = bit i of NFSR for all 64 candidates.
 */
#define L(s, i) ((s)->lfsr[((s)->off + (i)) & 127])
#define N(s, i) ((s)->nfsr[((s)->off + (i)) & 127])

static inline uint64_t bs_h(const bs_grain_t *s) {
    uint64_t x0 = N(s, 12);
    uint64_t x1 = L(s, 8);
    uint64_t x2 = L(s, 13);
    uint64_t x3 = L(s, 20);
    uint64_t x4 = N(s, 95);
    uint64_t x5 = L(s, 42);
    uint64_t x6 = L(s, 60);
    uint64_t x7 = L(s, 79);
    uint64_t x8 = L(s, 94);
    return (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8);
}

static inline uint64_t bs_preoutput(const bs_grain_t *s) {
    return bs_h(s) ^ L(s, 93)
         ^ N(s, 2) ^ N(s, 15) ^ N(s, 36) ^ N(s, 45)
         ^ N(s, 64) ^ N(s, 73) ^ N(s, 89);
}

static inline uint64_t bs_l_feedback(const bs_grain_t *s) {
    return L(s, 0) ^ L(s, 7) ^ L(s, 38) ^ L(s, 70) ^ L(s, 81) ^ L(s, 96);
}

static inline uint64_t bs_f_feedback(const bs_grain_t *s) {
    uint64_t s0 = L(s, 0);
    uint64_t t0 = N(s, 0) ^ N(s, 26) ^ N(s, 56) ^ N(s, 91) ^ N(s, 96);
    uint64_t t1 = N(s, 3) & N(s, 67);
    uint64_t t2 = N(s, 11) & N(s, 13);
    uint64_t t3 = N(s, 17) & N(s, 18);
    uint64_t t4 = N(s, 27) & N(s, 59);
    uint64_t t5 = N(s, 40) & N(s, 48);
    uint64_t t6 = N(s, 61) & N(s, 65);
    uint64_t t7 = N(s, 68) & N(s, 84);
    uint64_t t8 = N(s, 22) & N(s, 24) & N(s, 25);
    uint64_t t9 = N(s, 70) & N(s, 78) & N(s, 82);
    uint64_t t10 = N(s, 88) & N(s, 92) & N(s, 93) & N(s, 95);
    return s0 ^ t0 ^ t1 ^ t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7 ^ t8 ^ t9 ^ t10;
}

static inline void bs_clock_init(bs_grain_t *s) {
    uint64_t y = bs_preoutput(s);
    uint64_t ln = bs_l_feedback(s) ^ y;
    uint64_t fn = bs_f_feedback(s) ^ y;
    int p = s->off;
    s->nfsr[p & 127] = fn;
    s->lfsr[p & 127] = ln;
    s->off = (p + 1) & 127;
}

static inline void bs_clock(bs_grain_t *s) {
    uint64_t ln = bs_l_feedback(s);
    uint64_t fn = bs_f_feedback(s);
    int p = s->off;
    s->nfsr[p & 127] = fn;
    s->lfsr[p & 127] = ln;
    s->off = (p + 1) & 127;
}

void bs_load(bs_grain_t *s, const uint8_t keys[][16], int num_keys,
             const uint8_t iv[12]) {
    s->off = 0;

    /* NFSR = key (little-endian): different per candidate */
    for (int bit = 0; bit < 128; bit++) {
        uint64_t word = 0;
        int byte_idx = bit >> 3;
        int bit_mask = 1 << (bit & 7);
        for (int k = 0; k < num_keys; k++) {
            if (keys[k][byte_idx] & bit_mask)
                word |= (1ULL << k);
        }
        s->nfsr[bit] = word;
    }

    /* LFSR = IV(96) || ones(31) || 0: same for all candidates */
    for (int bit = 0; bit < 96; bit++) {
        int byte_idx = bit >> 3;
        int bit_mask = 1 << (bit & 7);
        s->lfsr[bit] = (iv[byte_idx] & bit_mask) ? ~0ULL : 0ULL;
    }
    for (int bit = 96; bit < 127; bit++)
        s->lfsr[bit] = ~0ULL;
    s->lfsr[127] = 0ULL;
}

void bs_init_rounds(bs_grain_t *s) {
    for (int i = 0; i < 256; i++)
        bs_clock_init(s);
}

uint64_t bs_test_constraint(bs_grain_t *s, const sparse_constraint_t *con) {
    uint64_t survivors = ~0ULL;
    int next_check = 0;

    for (int byte_off = 0; byte_off <= con->max_offset; byte_off++) {
        /* Generate 8 keystream bits (one byte) */
        uint64_t ks_bits[8];
        for (int j = 0; j < 8; j++) {
            ks_bits[j] = bs_preoutput(s);
            bs_clock(s);
        }

        if (next_check < con->num_known && byte_off == con->offsets[next_check]) {
            uint8_t exp = con->expected[next_check];
            uint64_t mismatch = 0;
            for (int j = 0; j < 8; j++) {
                uint64_t exp_bits = (exp & (1 << (7 - j))) ? ~0ULL : 0ULL;
                mismatch |= (ks_bits[j] ^ exp_bits);
            }
            survivors &= ~mismatch;
            next_check++;
            if (!survivors) return 0;
        }
    }
    return survivors;
}

uint64_t bs_test_keys(const uint8_t keys[][16], int num_keys,
                      const sparse_constraint_t *con) {
    bs_grain_t state;
    bs_load(&state, keys, num_keys, con->iv);
    bs_init_rounds(&state);
    return bs_test_constraint(&state, con);
}

int load_sparse_constraints(const char *path, sparse_constraint_t *out, int max) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open constraints file: %s\n", path);
        fprintf(stderr, "Generate with: cd ../mac_capture && mix run -e \"GrainExperiments.export_constraints_c()\"\n");
        return 0;
    }

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) && count < max) {
        sparse_constraint_t *c = &out[count];
        memset(c, 0, sizeof(*c));

        /* Parse IV (first 24 hex chars) */
        if (strlen(line) < 24) continue;
        for (int i = 0; i < 12; i++)
            sscanf(&line[i * 2], "%2hhx", &c->iv[i]);

        /* Parse offset:byte pairs */
        const char *p = line + 24;
        c->num_known = 0;
        c->max_offset = 0;
        while (*p && c->num_known < MAX_SPARSE_BYTES) {
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '\n' || *p == '\0') break;

            int off;
            unsigned int val;
            if (sscanf(p, "%d:%2x", &off, &val) == 2) {
                c->offsets[c->num_known] = off;
                c->expected[c->num_known] = (uint8_t)val;
                if (off > c->max_offset) c->max_offset = off;
                c->num_known++;
            }
            while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        }

        if (c->num_known > 0) count++;
    }
    fclose(f);
    return count;
}

/*
 * Cross-validate bitsliced output against scalar implementation for a batch.
 */
void bs_self_test(void) {
    uint8_t keys[BS_WIDTH][16];
    uint8_t iv[12];

    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)i;

    for (int k = 0; k < BS_WIDTH; k++) {
        for (int i = 0; i < 16; i++)
            keys[k][i] = (uint8_t)(k * 17 + i);
    }

    /* Generate keystream with scalar for each key */
    uint8_t scalar_ks[BS_WIDTH][16];
    for (int k = 0; k < BS_WIDTH; k++) {
        grain_state_t gs;
        grain_init(&gs, keys[k], iv);
        grain_keystream(&gs, scalar_ks[k], 16);
    }

    /* Generate with bitsliced for all 64 simultaneously */
    bs_grain_t bs;
    bs_load(&bs, keys, BS_WIDTH, iv);
    bs_init_rounds(&bs);

    for (int byte_off = 0; byte_off < 16; byte_off++) {
        uint64_t ks_bits[8];
        for (int j = 0; j < 8; j++) {
            ks_bits[j] = bs_preoutput(&bs);
            bs_clock(&bs);
        }

        for (int k = 0; k < BS_WIDTH; k++) {
            uint8_t reconstructed = 0;
            for (int j = 0; j < 8; j++) {
                if (ks_bits[j] & (1ULL << k))
                    reconstructed |= (1 << (7 - j));
            }
            if (reconstructed != scalar_ks[k][byte_off]) {
                fprintf(stderr,
                    "bs_self_test FAIL: key %d byte %d: scalar=%02X bs=%02X\n",
                    k, byte_off, scalar_ks[k][byte_off], reconstructed);
                exit(1);
            }
        }
    }
    printf("bs_self_test: OK (64 keys × 16 bytes match scalar)\n");
}
