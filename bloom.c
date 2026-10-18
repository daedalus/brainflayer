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

int bloom_init(bloom_t *b, unsigned int log2bits, unsigned int k) {
  unsigned int i, o, r;

  memset(b, 0, sizeof(*b));
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
