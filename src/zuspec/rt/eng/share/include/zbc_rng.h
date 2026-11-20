/*
 * zbc_rng.h -- Python's random.Random (MT19937) in C.
 *
 * The Python VM draws buffer-object picks and resource-pool deals from
 * random.Random(seed); the C engine must make the same draws to pick the same
 * objects. zbc_mt_seed seeds exactly as random.Random(<non-negative int>) does
 * (init_by_array over the seed's 32-bit little-endian words), and
 * zbc_mt_randrange(k, n) returns what Random.randrange(k, n) returns.
 */
#ifndef ZBC_RNG_H
#define ZBC_RNG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zbc_mt {
    uint32_t mt[624];
    uint32_t mti;
} zbc_mt_t;

/* random.Random(seed) for a non-negative seed < 2^64. */
void     zbc_mt_seed(zbc_mt_t *g, uint64_t seed);
/* Random.getrandbits(32) == genrand_uint32(). */
uint32_t zbc_mt_u32(zbc_mt_t *g);
/* Random.getrandbits(k), 1 <= k <= 64. */
uint64_t zbc_mt_getrandbits(zbc_mt_t *g, unsigned k);
/* Random.randrange(k, n), k < n (n - k < 2^64). */
uint64_t zbc_mt_randrange(zbc_mt_t *g, uint64_t k, uint64_t n);

/* Test hook: seed a generator, then write `count` randrange(k, n) draws to
 * out[], each for k = lo[i], n = hi[i]. Returns 0. */
int zbc_mt_test_draws(uint64_t seed, const uint64_t *lo, const uint64_t *hi,
                      uint32_t count, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ZBC_RNG_H */
