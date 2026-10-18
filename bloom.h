/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#ifndef __BRAINFLAYER_BLOOM_H_
#define __BRAINFLAYER_BLOOM_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "mmapf.h"

/* legacy filter file: 1 GiB, indexed by 32-bit slices (BH00..BH24) */
#define BLOOM_SIZE (512*1024*1024*2)

#define BLOOM_SET_BIT(N) (bloom[(N)>>3] = bloom[(N)>>3] | (1<<((N)&7)))
#define BLOOM_GET_BIT(N) ( ( bloom[(N)>>3]>>((N)&7) )&1)

#define BH00(N) (N[0])
#define BH01(N) (N[1])
#define BH02(N) (N[2])
#define BH03(N) (N[3])
#define BH04(N) (N[4])

#define BH05(N) (N[0]<<16|N[1]>>16)
#define BH06(N) (N[1]<<16|N[2]>>16)
#define BH07(N) (N[2]<<16|N[3]>>16)
#define BH08(N) (N[3]<<16|N[4]>>16)
#define BH09(N) (N[4]<<16|N[0]>>16)

#define BH10(N) (N[0]<< 8|N[1]>>24)
#define BH11(N) (N[1]<< 8|N[2]>>24)
#define BH12(N) (N[2]<< 8|N[3]>>24)
#define BH13(N) (N[3]<< 8|N[4]>>24)
#define BH14(N) (N[4]<< 8|N[0]>>24)

#define BH15(N) (N[0]<<24|N[1]>> 8)
#define BH16(N) (N[1]<<24|N[2]>> 8)
#define BH17(N) (N[2]<<24|N[3]>> 8)
#define BH18(N) (N[3]<<24|N[4]>> 8)
#define BH19(N) (N[4]<<24|N[0]>> 8)
#define BH20(N) (N[0]<<16|N[1]>>24)
#define BH21(N) (N[1]<<16|N[2]>>24)
#define BH22(N) (N[2]<<16|N[3]>>24)
#define BH23(N) (N[3]<<16|N[4]>>24)
#define BH24(N) (N[4]<<16|N[0]>>24)

void bloom_set_hash160(unsigned char *, uint32_t *);
#pragma GCC diagnostic ignored "-Wunused-function"
static unsigned int bloom_chk_hash160(unsigned char *bloom, uint32_t *h) {
  unsigned int t;
  t = BH00(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH01(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH02(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH03(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH04(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH05(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH06(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH07(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH08(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH09(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH10(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH11(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH12(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH13(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH14(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH15(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH16(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH17(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH18(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH19(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH20(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH21(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH22(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH23(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  t = BH24(h); if (BLOOM_GET_BIT(t) == 0) { return 0; }
  return 1;
}
#pragma GCC diagnostic pop

/* Sliced bloom filter with a configurable size.
 *
 * Like the legacy filter, no extra hashing is done: hash160 is already
 * uniformly random, so each of the k bit positions is a slice of it. The
 * 160 bits (the five words, most significant bit first, wrapping around)
 * are cut into k windows of log2bits bits at evenly spaced offsets. A bigger
 * filter means wider slices, and more capacity means more slices.
 *
 * File layout: 2^log2bits bits of filter followed by a 16 byte trailer,
 * "BLFSLICE", version, log2bits, k, then five zero bytes. A 1 GiB file
 * without a trailer is a legacy filter. */
#define BLOOM_MAGIC "BLFSLICE"
#define BLOOM_TRAILER_SZ 16
#define BLOOM_VERSION 1
#define BLOOM_LOG2_MIN 20
#define BLOOM_LOG2_MAX 40
#define BLOOM_SLICES_MAX 160

/* On x86 bloom_chk_n can use AVX2, but only when the environment sets
 * BRAINFLAYER_SIMD (and not to 0) and the CPU has it: lookups into a filter
 * bigger than the caches are bound by memory latency, and on the CPUs tried
 * the gathers were slower than the scalar code with prefetching, which is
 * the default and the fallback. */
#if defined(__x86_64__) || defined(__i386__)
#define BLOOM_SIMD 1
#endif

typedef struct {
  unsigned char *bits;
  int legacy;
  unsigned int log2bits, k;
  uint64_t mask;
  size_t bits_sz;      /* bytes of filter, without the trailer */
  uint8_t word[BLOOM_SLICES_MAX];
  int8_t shift[BLOOM_SLICES_MAX];
  uint8_t lshift[BLOOM_SLICES_MAX];
  int simd;            /* bloom_chk_n uses AVX2 */
} bloom_t;

/* set up legacy (log2bits == 0) or sliced parameters, returns 0 if valid */
int bloom_init(bloom_t *, unsigned int log2bits, unsigned int k);
/* bytes on disk, including the trailer */
size_t bloom_file_size(const bloom_t *);
void bloom_trailer(const bloom_t *, unsigned char *);
/* detect the format of an existing file, returns 0 if it is a bloom filter */
int bloom_probe(bloom_t *, const char *);
/* probe and mmap a filter read-only, returns 0 or an mmapf error */
int bloom_open(bloom_t *, mmapf_ctx *, const char *);
void bloom_set(bloom_t *, const uint32_t *);
double bloom_fp_rate(const bloom_t *, double n);
unsigned int bloom_best_k(unsigned int log2bits, double n);

static inline uint64_t bloom_slice(const bloom_t *b, const uint32_t *w, int i) {
  int j = b->word[i];
  uint64_t x = (uint64_t)w[j] << 32 | w[j+1];
  if (b->shift[i] >= 0) { return (x >> b->shift[i]) & b->mask; }
  return ((x << b->lshift[i]) | (w[j+2] >> (32 - b->lshift[i]))) & b->mask;
}

static inline unsigned int bloom_chk(const bloom_t *b, const uint32_t *h) {
  uint32_t w[7];
  unsigned int i;
  uint64_t t;

  if (b->legacy) { return bloom_chk_hash160(b->bits, (uint32_t *)h); }

  memcpy(w, h, 20);
  w[5] = h[0]; w[6] = h[1];
  for (i = 0; i < b->k; ++i) {
    t = bloom_slice(b, w, i);
    if (((b->bits[t >> 3] >> (t & 7)) & 1) == 0) { return 0; }
  }
  return 1;
}

/* Check n hashes, stored back to back (an array of hash160_t), setting hit[i]
 * to bloom_chk of hash i. The scalar version prefetches the first two bits of
 * the hash a few places ahead, so the cache misses of several hashes overlap.
 * The AVX2 version puts one hash in each lane and checks a slice of all of
 * them at once, only fetching bits for the lanes still in the running. */
void bloom_chk_n(const bloom_t *, const uint32_t *h, size_t n, unsigned char *hit);

//#define bloom_new() malloc(536870912)
//unsigned char * bloom_load(unsigned char *);
//int bloom_save(unsigned char *, unsigned char *);

/*  vim: set ts=2 sw=2 et ai si: */
#endif /* __BRAINFLAYER_BLOOM_H_ */
