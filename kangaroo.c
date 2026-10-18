/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */

/* Pollard's kangaroo (lambda) method for solving the elliptic curve discrete
 * logarithm over an interval. Given a public key Q = k*G with k known to be in
 * [a, b], we release a herd of "tame" kangaroos starting from a known scalar
 * near the middle of the interval and a herd of "wild" kangaroos starting from
 * Q. Every kangaroo takes pseudo-random jumps determined only by its current
 * position, so a tame and a wild kangaroo that ever land on the same point
 * follow the same path forever afterwards. We record "distinguished" points
 * (those whose x coordinate has some number of low bits clear) in a hash table;
 * when a tame point meets a wild point there we can read off the private key
 * from their accumulated travel distances.
 *
 * All of the elliptic curve arithmetic lives behind the opaque helpers in
 * ec_pubkey_fast.c so that the secp256k1 internals stay in one translation
 * unit. */

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kangaroo.h"
#include "ec_pubkey_fast.h"

static void *chk_malloc(size_t sz) {
  void *p = malloc(sz);
  if (!p) { fprintf(stderr, "kangaroo: malloc(%zu) failed\n", sz); exit(1); }
  return p;
}

static void *chk_calloc(size_t n, size_t sz) {
  void *p = calloc(n, sz);
  if (!p) { fprintf(stderr, "kangaroo: calloc(%zu, %zu) failed\n", n, sz); exit(1); }
  return p;
}

/* ------------------------------------------------------------------ */
/* 256-bit big-endian helpers (plain integers, not reduced mod n)      */
/* ------------------------------------------------------------------ */

static int be_cmp(const unsigned char a[32], const unsigned char b[32]) {
  return memcmp(a, b, 32);
}

/* out = a - b, assumes a >= b */
static void be_sub(unsigned char out[32], const unsigned char a[32], const unsigned char b[32]) {
  int i, borrow = 0;
  for (i = 31; i >= 0; --i) {
    int d = (int)a[i] - (int)b[i] - borrow;
    borrow = d < 0;
    out[i] = (unsigned char)(d & 0xff);
  }
}

/* out = a + b (wraps at 256 bits, which never happens for our inputs) */
static void be_add(unsigned char out[32], const unsigned char a[32], const unsigned char b[32]) {
  int i, carry = 0;
  for (i = 31; i >= 0; --i) {
    int s = (int)a[i] + (int)b[i] + carry;
    carry = s >> 8;
    out[i] = (unsigned char)(s & 0xff);
  }
}

/* out = a >> 1 */
static void be_rshift1(unsigned char out[32], const unsigned char a[32]) {
  int i, carry = 0;
  for (i = 0; i < 32; ++i) {
    int bit = a[i] & 1;
    out[i] = (unsigned char)((a[i] >> 1) | (carry << 7));
    carry = bit;
  }
}

static void be_from_u64(unsigned char out[32], uint64_t v) {
  int i;
  memset(out, 0, 32);
  for (i = 0; i < 8; ++i) { out[31 - i] = (unsigned char)(v >> (8 * i)); }
}

/* number of significant bits (position of the highest set bit + 1) */
static unsigned be_bitlen(const unsigned char a[32]) {
  int i, j;
  for (i = 0; i < 32; ++i) {
    if (a[i]) {
      for (j = 7; j >= 0; --j) {
        if (a[i] & (1 << j)) { return (unsigned)((31 - i) * 8 + j + 1); }
      }
    }
  }
  return 0;
}

/* set a single bit (bit 0 is the least significant) */
static void be_setbit(unsigned char out[32], unsigned bit) {
  memset(out, 0, 32);
  if (bit < 256) { out[31 - bit / 8] |= (unsigned char)(1 << (bit & 7)); }
}

/* the low 64 bits of a big-endian value */
static uint64_t be_low64(const unsigned char a[32]) {
  uint64_t v = 0;
  int i;
  for (i = 0; i < 8; ++i) { v = (v << 8) | a[24 + i]; }
  return v;
}

/* ------------------------------------------------------------------ */
/* splitmix64 - used to pick jump distances and reseed offsets         */
/* ------------------------------------------------------------------ */

static uint64_t sm_state;
static uint64_t sm_next(void) {
  uint64_t z = (sm_state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

/* ------------------------------------------------------------------ */
/* distinguished point hash table (open addressing, linear probing)    */
/* ------------------------------------------------------------------ */

typedef struct {
  unsigned char x[32];
  unsigned char v[32];
  uint8_t type; /* 0 = tame, 1 = wild */
  uint8_t used;
} dp_entry_t;

static dp_entry_t *dp_tab = NULL;
static size_t dp_mask = 0;   /* table size - 1 (size is a power of two) */
static size_t dp_count = 0;
static size_t dp_max_slots = 0;

static uint64_t dp_hash(const unsigned char x[32]) {
  uint64_t h;
  memcpy(&h, x, 8);
  h ^= h >> 33; h *= 0xff51afd7ed558ccdULL; h ^= h >> 33;
  return h;
}

static dp_entry_t *dp_get(const unsigned char x[32]) {
  size_t i = dp_hash(x) & dp_mask;
  while (dp_tab[i].used) {
    if (memcmp(dp_tab[i].x, x, 32) == 0) { return &dp_tab[i]; }
    i = (i + 1) & dp_mask;
  }
  return NULL;
}

static void dp_put_raw(dp_entry_t *tab, size_t mask, const unsigned char x[32],
                       const unsigned char v[32], uint8_t type) {
  size_t i = dp_hash(x) & mask;
  while (tab[i].used && memcmp(tab[i].x, x, 32) != 0) { i = (i + 1) & mask; }
  memcpy(tab[i].x, x, 32);
  memcpy(tab[i].v, v, 32);
  tab[i].type = type;
  tab[i].used = 1;
}

static int dp_grow(void) {
  size_t newsize = (dp_mask + 1) << 1;
  dp_entry_t *nt;
  size_t i;
  if (newsize > dp_max_slots) { return 1; }
  nt = calloc(newsize, sizeof(dp_entry_t));
  if (!nt) { return 1; }
  for (i = 0; i <= dp_mask; ++i) {
    if (dp_tab[i].used) { dp_put_raw(nt, newsize - 1, dp_tab[i].x, dp_tab[i].v, dp_tab[i].type); }
  }
  free(dp_tab);
  dp_tab = nt;
  dp_mask = newsize - 1;
  return 0;
}

static void dp_insert(const unsigned char x[32], const unsigned char v[32], uint8_t type) {
  size_t i;
  /* grow at 70% load; if we can't grow and are nearly full, drop the point to
   * avoid an unbounded probe (collisions are still found via stored points) */
  if ((dp_count + 1) * 10 >= (dp_mask + 1) * 7) {
    if (dp_grow() != 0 && (dp_count + 1) * 10 >= (dp_mask + 1) * 9) { return; }
  }
  i = dp_hash(x) & dp_mask;
  while (dp_tab[i].used) {
    if (memcmp(dp_tab[i].x, x, 32) == 0) {
      memcpy(dp_tab[i].v, v, 32);
      dp_tab[i].type = type;
      return;
    }
    i = (i + 1) & dp_mask;
  }
  memcpy(dp_tab[i].x, x, 32);
  memcpy(dp_tab[i].v, v, 32);
  dp_tab[i].type = type;
  dp_tab[i].used = 1;
  ++dp_count;
}

/* ------------------------------------------------------------------ */

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* does cand * G equal the target public key? */
static int kangaroo_verify(const unsigned char cand[32], const unsigned char *pub, size_t pub_sz) {
  unsigned char candpub[65];
  int sz;
  secp256k1_ec_pubkey_create_precomp(candpub, &sz, cand);
  if (memcmp(candpub + 1, pub + 1, 32) != 0) { return 0; }
  if (pub_sz == 65) {
    return memcmp(candpub + 33, pub + 33, 32) == 0;
  }
  /* compressed: compare the parity of y */
  return (candpub[64] & 1) == (pub[0] == 0x03);
}

/* try to recover the key from a tame/wild distinguished-point meeting.
 * x(tame) == x(wild) means the affine points are equal or negatives of each
 * other, which gives two candidate keys; return 1 and fill out if either is
 * the real private key. */
static int kangaroo_try_solve(unsigned char out[32], const unsigned char vt[32],
                              const unsigned char vw[32], const kangaroo_opts_t *opts) {
  unsigned char cand[32], neg[32];

  /* points equal: k = vt - vw */
  secp256k1_ec_scalar_sub_b32(cand, vt, vw);
  if (kangaroo_verify(cand, opts->pub, opts->pub_sz)) { memcpy(out, cand, 32); return 1; }

  /* points negated: k = -vt - vw */
  secp256k1_ec_scalar_neg_b32(neg, vt);
  secp256k1_ec_scalar_sub_b32(cand, neg, vw);
  if (kangaroo_verify(cand, opts->pub, opts->pub_sz)) { memcpy(out, cand, 32); return 1; }

  return 0;
}

int kangaroo_solve(unsigned char out_priv[32], const kangaroo_opts_t *opts) {
  unsigned char width[32], halfwidth[32], midpoint[32], tmp[32];
  unsigned char (*jump_d)[32] = NULL;
  unsigned char (*V)[32] = NULL, (*X)[32] = NULL;
  unsigned int *idx = NULL;
  uint8_t *type = NULL;
  char *points = NULL, *jumps_ge = NULL;
  void *qgej = NULL, *scratch_ge = NULL;
  size_t gej_sz, ge_sz;
  unsigned int L, half, dp_bits, n_jumps, herd, n, j;
  uint64_t dp_mask_bits, use_random_bound, span;
  uint64_t steps = 0, dp_found = 0;
  uint64_t t_start, t_last, steps_last = 0;
  int ret = 1, use_random;
  size_t i;

  gej_sz = secp256k1_ec_gej_size();
  ge_sz  = secp256k1_ec_ge_size();

  /* interval sanity */
  if (be_cmp(opts->range_start, opts->range_end) > 0) {
    fprintf(stderr, "kangaroo: range start must be <= range end\n");
    return -1;
  }

  /* width = end - start, and the known starting scalar in the middle */
  be_sub(width, opts->range_end, opts->range_start);
  be_rshift1(halfwidth, width);
  be_add(midpoint, opts->range_start, halfwidth);

  L = be_bitlen(width);
  if (L == 0) { L = 1; }
  half = (L + 1) / 2;

  n_jumps = opts->n_jumps ? opts->n_jumps : 32;
  if (n_jumps < 1) { n_jumps = 1; }

  /* A larger herd does not reduce the total number of steps on a single
   * thread (each kangaroo still has to walk the gap to the key); it only
   * amortises the batched field inversion. A small herd near the point where
   * inversion cost per point stops dominating is the sweet spot. */
  herd = opts->herd ? opts->herd : 8;
  if (herd < 1) { herd = 1; }
  n = herd * 2; /* tame kangaroos [0, herd), wild kangaroos [herd, 2*herd) */

  /* Distinguished point rarity. All 2*herd kangaroos step in lockstep, so once
   * a tame and a wild path collide it takes about 2^dp more steps for the pair
   * to reach a distinguished point and be noticed, wasting 2*herd group ops per
   * step. Collision itself is expected after about 2*sqrt(width)/herd steps, so
   * we pick dp to make the two costs comparable: 2^dp ~ sqrt(width)/herd. */
  dp_bits = opts->dp_bits;
  if (dp_bits == 0) {
    unsigned log2_herd = 0, h = herd;
    while (h > 1) { ++log2_herd; h >>= 1; }
    dp_bits = (half > log2_herd) ? (half - log2_herd) : 1;
    if (dp_bits < 1)  { dp_bits = 1; }
    if (dp_bits > 48) { dp_bits = 48; }
  }
  if (dp_bits > 48) { dp_bits = 48; }
  dp_mask_bits = (dp_bits >= 64) ? ~0ULL : ((1ULL << dp_bits) - 1);

  /* jump distances have mean ~ sqrt(width)/2 so a wild and tame kangaroo are
   * expected to meet after about 2*sqrt(width) total steps */
  use_random = (half <= 62);
  use_random_bound = use_random ? (1ULL << half) : 0;

  /* allocations */
  jump_d   = chk_calloc(n_jumps, sizeof(*jump_d));
  jumps_ge = chk_malloc((size_t)n_jumps * ge_sz);
  points   = chk_malloc((size_t)n * gej_sz);
  V        = chk_calloc(n, sizeof(*V));
  X        = chk_calloc(n, sizeof(*X));
  idx      = chk_malloc((size_t)n * sizeof(*idx));
  type     = chk_malloc((size_t)n * sizeof(*type));
  qgej       = chk_malloc(gej_sz); /* parsed target, aligned by malloc */
  scratch_ge = chk_malloc(ge_sz);  /* scratch affine point            */

  /* distinguished point table */
  dp_count = 0;
  dp_mask = (1u << 16) - 1;
  dp_max_slots = (size_t)1 << 24; /* cap ~16M slots */
  dp_tab = chk_calloc(dp_mask + 1, sizeof(dp_entry_t));

  /* build the jump table: distance d_i and the point d_i*G */
  sm_state = 0x6a09e667f3bcc908ULL ^ ((uint64_t)L << 32) ^ n_jumps;
  for (j = 0; j < n_jumps; ++j) {
    if (use_random) {
      uint64_t d = (use_random_bound > 1) ? ((sm_next() % use_random_bound) + 1) : 1;
      be_from_u64(jump_d[j], d);
    } else {
      /* interval too wide for 64-bit jumps: use powers of two around sqrt(w) */
      unsigned bit = (half > n_jumps / 2) ? (half - n_jumps / 2 + j) : (j + 1);
      be_setbit(jump_d[j], bit);
    }
    secp256k1_ec_scalar_mul_g_ge(jumps_ge + (size_t)j * ge_sz, jump_d[j]);
  }

  /* Spread each herd over a window of this many scalars so that its members
   * stay roughly a couple of mean jumps apart. If they started clustered they
   * would mostly just collide with each other instead of the other herd. The
   * window is about 2*herd*mean_jump, bounded by half the interval, and must
   * fit in 64 bits to be generated cheaply. */
  {
    unsigned lh = 0, hh = herd;
    unsigned span_bits;
    while (hh > 1) { ++lh; hh >>= 1; }
    span_bits = half + lh + 1;
    if (L >= 2 && span_bits > L - 1) { span_bits = L - 1; }
    if (span_bits < 1)  { span_bits = 1; }
    if (span_bits > 61) { span_bits = 61; }
    span = (1ULL << span_bits) - 1; /* used as an AND mask */
  }

  /* release the tame herd: start at known scalars spread above the middle */
  for (j = 0; j < herd; ++j) {
    be_from_u64(tmp, sm_next() & span);
    be_add(V[j], midpoint, tmp);
    secp256k1_ec_scalar_mul_g_gej(points + (size_t)j * gej_sz, V[j]);
    type[j] = 0;
  }

  /* release the wild herd: start at Q + off*G with a known, spread offset */
  if (secp256k1_ec_pubkey_to_gej(qgej, opts->pub, opts->pub_sz) != 0) {
    fprintf(stderr, "kangaroo: could not parse target public key\n");
    ret = -1;
    goto done;
  }
  for (j = 0; j < herd; ++j) {
    unsigned int w = herd + j;
    uint64_t off = sm_next() & span;
    be_from_u64(V[w], off);
    if (off == 0) {
      memcpy(points + (size_t)w * gej_sz, qgej, gej_sz);
    } else {
      secp256k1_ec_scalar_mul_g_ge(scratch_ge, V[w]);
      secp256k1_ec_gej_add_ge(points + (size_t)w * gej_sz, qgej, scratch_ge);
    }
    type[w] = 1;
  }

  /* starting x coordinates */
  secp256k1_ec_gej_get_x_batch(X, points, n);

  t_start = t_last = now_ns();

  for (;;) {
    for (i = 0; i < n; ++i) {
      uint64_t lo = be_low64(X[i]);

      if ((lo & dp_mask_bits) == 0) {
        dp_entry_t *e = dp_get(X[i]);
        if (e) {
          if (e->type != type[i]) {
            const unsigned char *vt = (type[i] == 0) ? V[i] : e->v;
            const unsigned char *vw = (type[i] == 0) ? e->v : V[i];
            if (kangaroo_try_solve(out_priv, vt, vw, opts)) {
              ret = 0;
              goto done;
            }
          } else {
            /* two kangaroos of the same herd merged; reseed this one with a
             * fresh offset so it keeps contributing new distinguished points */
            uint64_t off = sm_next() & span;
            if (type[i] == 0) {
              be_from_u64(tmp, off);
              be_add(V[i], midpoint, tmp);
              secp256k1_ec_scalar_mul_g_gej(points + i * gej_sz, V[i]);
            } else {
              be_from_u64(V[i], off);
              secp256k1_ec_scalar_mul_g_ge(scratch_ge, V[i]);
              secp256k1_ec_gej_add_ge(points + i * gej_sz, qgej, scratch_ge);
            }
            secp256k1_ec_gej_get_x(X[i], points + i * gej_sz);
            lo = be_low64(X[i]);
          }
        } else {
          dp_insert(X[i], V[i], type[i]);
          ++dp_found;
        }
      }

      idx[i] = (unsigned int)(lo % n_jumps);
      /* keep V as the discrete log of the point we are about to move to */
      secp256k1_scalar_add_b32(V[i], V[i], jump_d[idx[i]]);
    }

    secp256k1_ec_kangaroo_batch_step(points, jumps_ge, idx, X, n);
    steps += n;

    if (opts->max_steps && steps >= opts->max_steps) {
      if (opts->verbose) { fprintf(stderr, "\nkangaroo: step limit reached\n"); }
      ret = 1;
      goto done;
    }

    if (opts->verbose) {
      uint64_t t = now_ns();
      uint64_t dt = t - t_last;
      if (dt > 5000000000ULL) {
        double rate = (double)(steps - steps_last) * 1.0e9 / (double)dt;
        fprintf(stderr,
                "\033[0G\033[2K rate: %9.2f st/s  dps: %-8ju  steps: %-14ju  elapsed: %8.3f s\033[0G",
                rate, (uintmax_t)dp_found, (uintmax_t)steps, (double)(t - t_start) / 1.0e9);
        fflush(stderr);
        t_last = t;
        steps_last = steps;
      }
    }
  }

done:
  if (ret == 0) {
    unsigned char hexed[65];
    static const char hx[] = "0123456789abcdef";
    for (i = 0; i < 32; ++i) {
      hexed[i * 2]     = hx[out_priv[i] >> 4];
      hexed[i * 2 + 1] = hx[out_priv[i] & 15];
    }
    hexed[64] = 0;
    if (opts->verbose) { fprintf(stderr, "\n"); }
    fprintf(opts->ofile, "%s\n", hexed);
    fflush(opts->ofile);
  }

  free(jump_d); free(jumps_ge); free(points);
  free(V); free(X); free(idx); free(type);
  free(qgej); free(scratch_ge);
  free(dp_tab); dp_tab = NULL;
  return ret;
}

/*  vim: set ts=2 sw=2 et ai si: */
