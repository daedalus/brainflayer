/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <math.h>

#include "bloom.h"
#include "mmapf.h"

#ifdef BLOOM_SIMD
#include <immintrin.h>

static int bloom_cpu_simd(void) {
  static int simd = -1;
  if (simd < 0) {
    __builtin_cpu_init();
    const char *e = getenv("BRAINFLAYER_SIMD");
    simd = e != NULL && strcmp(e, "0") != 0 && __builtin_cpu_supports("avx2");
  }
  return simd;
}

/* BH00..BH24 as N[a] << sl | N[b] >> sr, where a shift by 32 gives 0 */
static const uint8_t legacy_a[25] = {
  0, 1, 2, 3, 4,  0, 1, 2, 3, 4,  0, 1, 2, 3, 4,  0, 1, 2, 3, 4,  0, 1, 2, 3, 4 };
static const uint8_t legacy_b[25] = {
  0, 0, 0, 0, 0,  1, 2, 3, 4, 0,  1, 2, 3, 4, 0,  1, 2, 3, 4, 0,  1, 2, 3, 4, 0 };
static const uint8_t legacy_sl[25] = {
  0, 0, 0, 0, 0, 16,16,16,16,16,  8, 8, 8, 8, 8, 24,24,24,24,24, 16,16,16,16,16 };
static const uint8_t legacy_sr[25] = {
 32,32,32,32,32, 16,16,16,16,16, 24,24,24,24,24,  8, 8, 8, 8, 8, 24,24,24,24,24 };

/* eight hashes at a time, one per 32-bit lane */
__attribute__((target("avx2")))
static void bloom_chk_legacy_avx2(const unsigned char *bits, const uint32_t *h, size_t n, unsigned char *hit) {
  const __m256i lane = _mm256_setr_epi32(0, 5, 10, 15, 20, 25, 30, 35);
  const __m256i zero = _mm256_setzero_si256(), one = _mm256_set1_epi32(1);
  const __m256i lo5 = _mm256_set1_epi32(31);
  __m256i w[5], live, t, v;
  size_t i, j, m;
  unsigned int s, mm;

  for (i = 0; i < n; i += 8) {
    m = n - i < 8 ? n - i : 8;
    live = _mm256_cmpgt_epi32(_mm256_set1_epi32(m), _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
    for (j = 0; j < 5; ++j) {
      w[j] = _mm256_mask_i32gather_epi32(zero, (const int *)(h + 5*i + j), lane, live, 4);
    }
    for (s = 0; s < 25 && !_mm256_testz_si256(live, live); ++s) {
      t = _mm256_or_si256(_mm256_sll_epi32(w[legacy_a[s]], _mm_cvtsi32_si128(legacy_sl[s])),
                          _mm256_srl_epi32(w[legacy_b[s]], _mm_cvtsi32_si128(legacy_sr[s])));
      /* t < 2^32, so t >> 5 fits a signed gather index */
      v = _mm256_mask_i32gather_epi32(zero, (const int *)bits, _mm256_srli_epi32(t, 5), live, 4);
      v = _mm256_and_si256(_mm256_srlv_epi32(v, _mm256_and_si256(t, lo5)), one);
      live = _mm256_and_si256(live, _mm256_cmpeq_epi32(v, one));
    }
    mm = _mm256_movemask_ps(_mm256_castsi256_ps(live));
    for (j = 0; j < m; ++j) { hit[i+j] = mm >> j & 1; }
  }
}

/* four hashes at a time, one per 64-bit lane */
__attribute__((target("avx2")))
static void bloom_chk_sliced_avx2(const bloom_t *b, const uint32_t *h, size_t n, unsigned char *hit) {
  const __m128i lane = _mm_setr_epi32(0, 5, 10, 15);
  const __m256i zero = _mm256_setzero_si256(), one = _mm256_set1_epi64x(1);
  const __m256i lo6 = _mm256_set1_epi64x(63), mask = _mm256_set1_epi64x(b->mask);
  __m256i w[7], live, x, t, v;
  __m128i live32;
  size_t i, j, m;
  unsigned int s, mm;

  for (i = 0; i < n; i += 4) {
    m = n - i < 4 ? n - i : 4;
    live32 = _mm_cmpgt_epi32(_mm_set1_epi32(m), _mm_setr_epi32(0, 1, 2, 3));
    live = _mm256_cvtepi32_epi64(live32);
    for (j = 0; j < 5; ++j) {
      w[j] = _mm256_cvtepu32_epi64(_mm_mask_i32gather_epi32(_mm_setzero_si128(),
                                   (const int *)(h + 5*i + j), lane, live32, 4));
    }
    w[5] = w[0]; w[6] = w[1];
    for (s = 0; s < b->k && !_mm256_testz_si256(live, live); ++s) {
      j = b->word[s];
      x = _mm256_or_si256(_mm256_slli_epi64(w[j], 32), w[j+1]);
      if (b->shift[s] >= 0) {
        t = _mm256_srl_epi64(x, _mm_cvtsi32_si128(b->shift[s]));
      } else {
        t = _mm256_or_si256(_mm256_sll_epi64(x, _mm_cvtsi32_si128(b->lshift[s])),
                            _mm256_srl_epi64(w[j+2], _mm_cvtsi32_si128(32 - b->lshift[s])));
      }
      t = _mm256_and_si256(t, mask);
      v = _mm256_mask_i64gather_epi64(zero, (const long long *)b->bits, _mm256_srli_epi64(t, 6), live, 8);
      v = _mm256_and_si256(_mm256_srlv_epi64(v, _mm256_and_si256(t, lo6)), one);
      live = _mm256_and_si256(live, _mm256_cmpeq_epi64(v, one));
    }
    mm = _mm256_movemask_pd(_mm256_castsi256_pd(live));
    for (j = 0; j < m; ++j) { hit[i+j] = mm >> j & 1; }
  }
}
#endif

int bloom_init(bloom_t *b, unsigned int log2bits, unsigned int k) {
  unsigned int i, o, r;

  memset(b, 0, sizeof(*b));
#ifdef BLOOM_SIMD
  b->simd = bloom_cpu_simd();
#endif
  if (log2bits == 0) {
    b->legacy = 1;
    b->log2bits = 32;
    b->k = 25;
    b->bits_sz = BLOOM_SIZE;
    return 0;
  }
  if (log2bits < BLOOM_LOG2_MIN || log2bits > BLOOM_LOG2_MAX) { return -1; }
  if (k < 1 || k > BLOOM_SLICES_MAX) { return -1; }

  b->log2bits = log2bits;
  b->k = k;
  b->mask = (1ULL << log2bits) - 1;
  b->bits_sz = (size_t)1 << (log2bits - 3);
  for (i = 0; i < k; ++i) {
    o = i * 160 / k;  /* evenly spaced, distinct offsets */
    r = o % 32;
    b->word[i] = o / 32;
    if (r + log2bits <= 64) {
      b->shift[i] = 64 - r - log2bits;
    } else {
      b->shift[i] = -1;
      b->lshift[i] = r + log2bits - 64;
    }
  }
  return 0;
}

size_t bloom_file_size(const bloom_t *b) {
  return b->legacy ? b->bits_sz : b->bits_sz + BLOOM_TRAILER_SZ;
}

void bloom_trailer(const bloom_t *b, unsigned char *t) {
  memset(t, 0, BLOOM_TRAILER_SZ);
  memcpy(t, BLOOM_MAGIC, 8);
  t[8] = BLOOM_VERSION;
  t[9] = b->log2bits;
  t[10] = b->k;
}

int bloom_probe(bloom_t *b, const char *filename) {
  unsigned char t[BLOOM_TRAILER_SZ];
  struct stat sb;
  FILE *f;
  int ok;

  if (stat(filename, &sb) != 0 || !S_ISREG(sb.st_mode)) { return -1; }
  if ((size_t)sb.st_size == BLOOM_SIZE) { return bloom_init(b, 0, 0); }
  if (sb.st_size < BLOOM_TRAILER_SZ || (f = fopen(filename, "r")) == NULL) { return -1; }
  ok = fseeko(f, sb.st_size - BLOOM_TRAILER_SZ, SEEK_SET) == 0 &&
       fread(t, sizeof(t), 1, f) == 1;
  fclose(f);
  if (!ok || memcmp(t, BLOOM_MAGIC, 8) != 0 || t[8] != BLOOM_VERSION) { return -1; }
  if (bloom_init(b, t[9], t[10]) != 0) { return -1; }
  return (size_t)sb.st_size == bloom_file_size(b) ? 0 : -1;
}

int bloom_open(bloom_t *b, mmapf_ctx *ctx, const char *filename) {
  int ret;
  if (bloom_probe(b, filename) != 0) { return MMAPF_ESIZE; }
  if ((ret = mmapf(ctx, filename, bloom_file_size(b), MMAPF_RNDRD)) != MMAPF_OKAY) { return ret; }
  b->bits = ctx->mem;
  return MMAPF_OKAY;
}

void bloom_set(bloom_t *b, const uint32_t *h) {
  uint32_t w[7];
  unsigned int i;
  uint64_t t;

  if (b->legacy) { bloom_set_hash160(b->bits, (uint32_t *)h); return; }

  memcpy(w, h, 20);
  w[5] = h[0]; w[6] = h[1];
  for (i = 0; i < b->k; ++i) {
    t = bloom_slice(b, w, i);
    b->bits[t >> 3] |= 1 << (t & 7);
  }
}

#define BLOOM_PREFETCH_DIST 8

static inline void bloom_prefetch(const bloom_t *b, const uint32_t *h) {
  uint32_t w[7];

  if (b->legacy) {
    __builtin_prefetch(b->bits + (BH00(h) >> 3));
    __builtin_prefetch(b->bits + (BH01(h) >> 3));
    return;
  }
  memcpy(w, h, 20);
  w[5] = h[0]; w[6] = h[1];
  __builtin_prefetch(b->bits + (bloom_slice(b, w, 0) >> 3));
  if (b->k > 1) { __builtin_prefetch(b->bits + (bloom_slice(b, w, 1) >> 3)); }
}

/* the AVX2 code reads the bits as little endian words, which x86 is */
void bloom_chk_n(const bloom_t *b, const uint32_t *h, size_t n, unsigned char *hit) {
  size_t i;
#ifdef BLOOM_SIMD
  if (b->simd) {
    if (b->legacy) {
      bloom_chk_legacy_avx2(b->bits, h, n, hit);
    } else {
      bloom_chk_sliced_avx2(b, h, n, hit);
    }
    return;
  }
#endif
  for (i = 0; i < n && i < BLOOM_PREFETCH_DIST; ++i) { bloom_prefetch(b, h + 5*i); }
  for (i = 0; i < n; ++i) {
    if (i + BLOOM_PREFETCH_DIST < n) { bloom_prefetch(b, h + 5*(i + BLOOM_PREFETCH_DIST)); }
    hit[i] = bloom_chk(b, h + 5*i);
  }
}

double bloom_fp_rate(const bloom_t *b, double n) {
  /* legacy slices are 32 bits wide, so only the first 2^32 bits are used */
  return pow(1 - exp(-(double)b->k * n / ldexp(1, b->log2bits)), b->k);
}

unsigned int bloom_best_k(unsigned int log2bits, double n) {
  double k = n > 0 ? round(ldexp(1, log2bits) / n * M_LN2) : BLOOM_SLICES_MAX;
  if (k < 1) { k = 1; }
  if (k > BLOOM_SLICES_MAX) { k = BLOOM_SLICES_MAX; }
  return k;
}

void bloom_set_hash160(unsigned char *bloom, uint32_t *h) {
  unsigned int t;
  t = BH00(h); BLOOM_SET_BIT(t);
  t = BH01(h); BLOOM_SET_BIT(t);
  t = BH02(h); BLOOM_SET_BIT(t);
  t = BH03(h); BLOOM_SET_BIT(t);
  t = BH04(h); BLOOM_SET_BIT(t);
  t = BH05(h); BLOOM_SET_BIT(t);
  t = BH06(h); BLOOM_SET_BIT(t);
  t = BH07(h); BLOOM_SET_BIT(t);
  t = BH08(h); BLOOM_SET_BIT(t);
  t = BH09(h); BLOOM_SET_BIT(t);
  t = BH10(h); BLOOM_SET_BIT(t);
  t = BH11(h); BLOOM_SET_BIT(t);
  t = BH12(h); BLOOM_SET_BIT(t);
  t = BH13(h); BLOOM_SET_BIT(t);
  t = BH14(h); BLOOM_SET_BIT(t);
  t = BH15(h); BLOOM_SET_BIT(t);
  t = BH16(h); BLOOM_SET_BIT(t);
  t = BH17(h); BLOOM_SET_BIT(t);
  t = BH18(h); BLOOM_SET_BIT(t);
  t = BH19(h); BLOOM_SET_BIT(t);
  t = BH20(h); BLOOM_SET_BIT(t);
  t = BH21(h); BLOOM_SET_BIT(t);
  t = BH22(h); BLOOM_SET_BIT(t);
  t = BH23(h); BLOOM_SET_BIT(t);
  t = BH24(h); BLOOM_SET_BIT(t);
}

/*
int bloom_save(unsigned char *filename, unsigned char *bloom);
*/

/*  vim: set ts=2 sw=2 et ai si: */
