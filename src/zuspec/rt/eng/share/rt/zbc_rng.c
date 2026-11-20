/*
 * zbc_rng.c -- MT19937 seeded and drawn as CPython's random.Random (see zbc_rng.h).
 * The generator is the reference mt19937ar (Matsumoto/Nishimura), as CPython's
 * Modules/_randommodule.c uses it.
 */
#include "zbc_rng.h"

#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A   0x9908b0dfu
#define MT_UPPER_MASK 0x80000000u
#define MT_LOWER_MASK 0x7fffffffu

static void mt_init_genrand(zbc_mt_t *g, uint32_t s)
{
    g->mt[0] = s;
    for (uint32_t i = 1; i < MT_N; i++)
        g->mt[i] = 1812433253u * (g->mt[i - 1] ^ (g->mt[i - 1] >> 30)) + i;
    g->mti = MT_N;
}

static void mt_init_by_array(zbc_mt_t *g, const uint32_t *key, uint32_t len)
{
    uint32_t i = 1, j = 0, k;
    mt_init_genrand(g, 19650218u);
    for (k = (MT_N > len ? MT_N : len); k; k--) {
        g->mt[i] = (g->mt[i] ^ ((g->mt[i - 1] ^ (g->mt[i - 1] >> 30)) * 1664525u))
                   + key[j] + j;
        i++; j++;
        if (i >= MT_N) { g->mt[0] = g->mt[MT_N - 1]; i = 1; }
        if (j >= len) j = 0;
    }
    for (k = MT_N - 1; k; k--) {
        g->mt[i] = (g->mt[i] ^ ((g->mt[i - 1] ^ (g->mt[i - 1] >> 30)) * 1566083941u)) - i;
        i++;
        if (i >= MT_N) { g->mt[0] = g->mt[MT_N - 1]; i = 1; }
    }
    g->mt[0] = 0x80000000u;
}

void zbc_mt_seed(zbc_mt_t *g, uint64_t seed)
{
    /* CPython: key = abs(seed) as 32-bit words, least significant first, with
     * no high zero words (seed 0 -> one word, 0). */
    uint32_t key[2] = { (uint32_t)seed, (uint32_t)(seed >> 32) };
    mt_init_by_array(g, key, key[1] ? 2u : 1u);
}

uint32_t zbc_mt_u32(zbc_mt_t *g)
{
    static const uint32_t mag01[2] = { 0u, MT_MATRIX_A };
    uint32_t y;
    if (g->mti >= MT_N) {
        uint32_t kk;
        for (kk = 0; kk < MT_N - MT_M; kk++) {
            y = (g->mt[kk] & MT_UPPER_MASK) | (g->mt[kk + 1] & MT_LOWER_MASK);
            g->mt[kk] = g->mt[kk + MT_M] ^ (y >> 1) ^ mag01[y & 1u];
        }
        for (; kk < MT_N - 1; kk++) {
            y = (g->mt[kk] & MT_UPPER_MASK) | (g->mt[kk + 1] & MT_LOWER_MASK);
            g->mt[kk] = g->mt[kk + (MT_M - MT_N)] ^ (y >> 1) ^ mag01[y & 1u];
        }
        y = (g->mt[MT_N - 1] & MT_UPPER_MASK) | (g->mt[0] & MT_LOWER_MASK);
        g->mt[MT_N - 1] = g->mt[MT_M - 1] ^ (y >> 1) ^ mag01[y & 1u];
        g->mti = 0;
    }
    y = g->mt[g->mti++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680u;
    y ^= (y << 15) & 0xefc60000u;
    y ^= (y >> 18);
    return y;
}

uint64_t zbc_mt_getrandbits(zbc_mt_t *g, unsigned k)
{
    /* CPython fills 32-bit words least significant first; only the last
     * (most significant) word is shifted down to the bits left. */
    if (k <= 32) return zbc_mt_u32(g) >> (32 - k);
    uint64_t lo = zbc_mt_u32(g);
    uint64_t hi = zbc_mt_u32(g) >> (64 - k);
    return lo | (hi << 32);
}

uint64_t zbc_mt_randrange(zbc_mt_t *g, uint64_t k, uint64_t n)
{
    /* randrange(k, n) = k + _randbelow_with_getrandbits(n - k). */
    uint64_t w = n - k, r;
    unsigned b = 0;
    for (uint64_t x = w; x; x >>= 1) b++;
    do { r = zbc_mt_getrandbits(g, b); } while (r >= w);
    return k + r;
}

int zbc_mt_test_draws(uint64_t seed, const uint64_t *lo, const uint64_t *hi,
                      uint32_t count, uint64_t *out)
{
    zbc_mt_t g;
    zbc_mt_seed(&g, seed);
    for (uint32_t i = 0; i < count; i++) out[i] = zbc_mt_randrange(&g, lo[i], hi[i]);
    return 0;
}
