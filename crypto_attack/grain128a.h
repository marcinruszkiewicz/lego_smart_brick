#ifndef GRAIN128A_H
#define GRAIN128A_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef unsigned __int128 uint128_t;

typedef struct {
    uint128_t nfsr;
    uint128_t lfsr;
} grain_state_t;

typedef struct {
    uint8_t iv[12];
    uint8_t keystream[256];
    size_t  ks_len;
} grain_constraint_t;

void grain_init(grain_state_t *s, const uint8_t key[16], const uint8_t iv[12]);
uint8_t grain_preoutput_bit(const grain_state_t *s);
void grain_clock(grain_state_t *s);
void grain_clock_init(grain_state_t *s);
void grain_keystream(grain_state_t *s, uint8_t *out, size_t num_bytes);
bool grain_verify_keystream(const uint8_t key[16], const grain_constraint_t *constraints,
                            size_t num_constraints);
void grain_self_test(void);

#endif
