/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#ifndef __KANGAROO_H_
#define __KANGAROO_H_

#include <stdint.h>
#include <stdio.h>

/* Pollard's kangaroo (lambda) method for the elliptic curve discrete log
 * problem over an interval: given a public key Q = k*G with k known to lie in
 * [range_start, range_end], recover k. */

typedef struct kangaroo_opts_s {
  const unsigned char *pub;      /* target public key bytes (SEC1)            */
  size_t               pub_sz;   /* 33 (compressed) or 65 (uncompressed)      */
  unsigned char        range_start[32]; /* interval start, 32 byte big-endian */
  unsigned char        range_end[32];   /* interval end,   32 byte big-endian */
  unsigned int         dp_bits;  /* distinguished point bits  (0 = auto)      */
  unsigned int         n_jumps;  /* size of the jump table    (0 = auto)      */
  unsigned int         herd;     /* kangaroos per herd        (0 = auto)      */
  uint64_t             max_steps;/* give up after this many steps (0 = never) */
  int                  verbose;  /* print progress to stderr                  */
  FILE                *ofile;    /* where to write the result                 */
} kangaroo_opts_t;

/* Returns 0 and writes the 32 byte big-endian private key to out_priv on
 * success, 1 if the step limit was reached without a solution, and a negative
 * value on a usage/setup error. */
int kangaroo_solve(unsigned char out_priv[32], const kangaroo_opts_t *opts);

#endif//__KANGAROO_H_
