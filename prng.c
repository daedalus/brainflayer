/* PRNG private key generators, see prng.h */
#include <string.h>

#include "prng.h"

const char *prng_types = "mt19937 pymt lcg64 xorshift64 xorshift128p splitmix64";

/* MT19937 */
#define MT_M 397

static void mt_init_genrand(prng_t *p, uint32_t s) {
  int i;
  p->mt[0] = s;
  for (i = 1; i < PRNG_MT_N; ++i) {
    p->mt[i] = 1812433253u * (p->mt[i-1] ^ (p->mt[i-1] >> 30)) + i;
  }
  p->mti = PRNG_MT_N;
}

static void mt_init_by_array(prng_t *p, const uint32_t *key, int key_len) {
  int i = 1, j = 0, k;
  mt_init_genrand(p, 19650218u);
  for (k = (PRNG_MT_N > key_len ? PRNG_MT_N : key_len); k; --k) {
    p->mt[i] = (p->mt[i] ^ ((p->mt[i-1] ^ (p->mt[i-1] >> 30)) * 1664525u)) + key[j] + j;
    ++i; ++j;
    if (i >= PRNG_MT_N) { p->mt[0] = p->mt[PRNG_MT_N-1]; i = 1; }
    if (j >= key_len) { j = 0; }
  }
  for (k = PRNG_MT_N - 1; k; --k) {
    p->mt[i] = (p->mt[i] ^ ((p->mt[i-1] ^ (p->mt[i-1] >> 30)) * 1566083941u)) - i;
    ++i;
    if (i >= PRNG_MT_N) { p->mt[0] = p->mt[PRNG_MT_N-1]; i = 1; }
  }
  p->mt[0] = 0x80000000u;
}

static uint32_t mt_next32(prng_t *p) {
  uint32_t y;
  int i;

  if (p->mti >= PRNG_MT_N) {
    for (i = 0; i < PRNG_MT_N; ++i) {
      y = (p->mt[i] & 0x80000000u) | (p->mt[(i+1) % PRNG_MT_N] & 0x7fffffffu);
      p->mt[i] = p->mt[(i+MT_M) % PRNG_MT_N] ^ (y >> 1) ^ ((y & 1) ? 0x9908b0dfu : 0);
    }
    p->mti = 0;
  }

  y = p->mt[p->mti++];
  y ^= y >> 11;
  y ^= (y << 7) & 0x9d2c5680u;
  y ^= (y << 15) & 0xefc60000u;
  y ^= y >> 18;
  return y;
}

/* Knuth MMIX LCG, output is the full 64-bit state */
static uint64_t lcg64_next64(prng_t *p) {
  p->s[0] = p->s[0] * 6364136223846793005ULL + 1442695040888963407ULL;
  return p->s[0];
}

/* Marsaglia xorshift64 (13, 7, 17) */
static uint64_t xorshift64_next64(prng_t *p) {
  uint64_t x = p->s[0];
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  return p->s[0] = x;
}

static uint64_t splitmix64_next64(prng_t *p) {
  uint64_t z = (p->s[0] += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

/* xorshift128+ (23, 17, 26), state seeded from splitmix64(seed) */
static uint64_t xorshift128p_next64(prng_t *p) {
  uint64_t s1 = p->s[0];
  const uint64_t s0 = p->s[1];
  p->s[0] = s0;
  s1 ^= s1 << 23;
  p->s[1] = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
  return p->s[1] + s0;
}

int prng_init(prng_t *p, const char *type, uint64_t seed) {
  memset(p, 0, sizeof(*p));
  p->name = type;

  if (strcmp(type, "mt19937") == 0) {
    /* init_genrand: C reference, C++ std::mt19937, numpy RandomState(seed) */
    if (seed >> 32) { return -1; }
    mt_init_genrand(p, seed);
    p->next32 = mt_next32;
  } else if (strcmp(type, "pymt") == 0) {
    /* init_by_array: Python random.seed(seed), Ruby srand(seed) */
    uint32_t key[2] = { seed & 0xffffffffu, seed >> 32 };
    mt_init_by_array(p, key, key[1] ? 2 : 1);
    p->next32 = mt_next32;
  } else if (strcmp(type, "lcg64") == 0) {
    p->s[0] = seed;
    p->next64 = lcg64_next64;
  } else if (strcmp(type, "xorshift64") == 0) {
    if (seed == 0) { return -1; }
    p->s[0] = seed;
    p->next64 = xorshift64_next64;
  } else if (strcmp(type, "splitmix64") == 0) {
    p->s[0] = seed;
    p->next64 = splitmix64_next64;
  } else if (strcmp(type, "xorshift128p") == 0) {
    p->s[0] = seed;
    uint64_t a = splitmix64_next64(p), b = splitmix64_next64(p);
    p->s[0] = a;
    p->s[1] = b;
    p->next64 = xorshift128p_next64;
  } else {
    return -1;
  }

  return 0;
}

void prng_next256(prng_t *p, unsigned char *priv) {
  int i, j;

  if (p->next32) {
    for (i = 0; i < 8; ++i) {
      uint32_t w = p->next32(p);
      for (j = 0; j < 4; ++j) { priv[31 - 4*i - j] = w >> (8*j); }
    }
  } else {
    for (i = 0; i < 4; ++i) {
      uint64_t w = p->next64(p);
      for (j = 0; j < 8; ++j) { priv[31 - 8*i - j] = w >> (8*j); }
    }
  }
}

void prng_skip256(prng_t *p, uint64_t n) {
  unsigned char tmp[32];
  while (n--) { prng_next256(p, tmp); }
}

/*  vim: set ts=2 sw=2 et ai si: */
