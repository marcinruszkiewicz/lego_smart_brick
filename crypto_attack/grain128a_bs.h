#ifndef GRAIN128A_BS_H
#define GRAIN128A_BS_H

/*
 * Bitsliced Grain-128A — processes 64 key candidates per clock cycle.
 *
 * Each bit position i of the 128-bit LFSR/NFSR is stored as a uint64_t,
 * where bit k of that word represents candidate k's value at position i.
 * XOR/AND on uint64_t operate on all 64 candidates simultaneously.
 *
 * Uses a circular buffer (offset pointer) to avoid memmove on every shift.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define BS_WIDTH 64
#define MAX_SPARSE_BYTES 32
#define MAX_CONSTRAINTS 32

typedef struct {
    uint64_t nfsr[128];
    uint64_t lfsr[128];
    int off;
} bs_grain_t;

typedef struct {
    uint8_t iv[12];
    int     num_known;
    int     offsets[MAX_SPARSE_BYTES];
    uint8_t expected[MAX_SPARSE_BYTES];
    int     max_offset;
} sparse_constraint_t;

/* Load 64 keys (little-endian) and a shared IV into the bitsliced state. */
void bs_load(bs_grain_t *s, const uint8_t keys[][16], int num_keys,
             const uint8_t iv[12]);

/* Run 256 initialization clocks (preoutput fed back into both registers). */
void bs_init_rounds(bs_grain_t *s);

/*
 * Generate keystream and check against sparse constraint.
 * Returns bitmask: bit k set iff candidate k matches ALL known bytes.
 * Exits early when all candidates are eliminated (survivors == 0).
 */
uint64_t bs_test_constraint(bs_grain_t *s, const sparse_constraint_t *con);

/*
 * Full pipeline: load keys, init, check constraint. Returns survivor mask.
 */
uint64_t bs_test_keys(const uint8_t keys[][16], int num_keys,
                      const sparse_constraint_t *con);

/* Load sparse constraints from file. Returns number loaded. */
int load_sparse_constraints(const char *path, sparse_constraint_t *out, int max);

/* Verify bitsliced implementation matches scalar. */
void bs_self_test(void);

#endif
