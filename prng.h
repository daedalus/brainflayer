#ifndef __BRAINFLAYER_PRNG_H_
#define __BRAINFLAYER_PRNG_H_

#include <stdint.h>

/* Non-cryptographic PRNGs used as private key generators.
 *
 * Each 256-bit element of the sequence is built from consecutive raw outputs,
 * least significant word first (the same order as Python's getrandbits(256)),
 * and written big-endian into a 32 byte private key. */

#define PRNG_MT_N 624

typedef struct prng_s {
  const char *name;
  uint32_t (*next32)(struct prng_s *);  /* set for 32-bit generators */
  uint64_t (*next64)(struct prng_s *);  /* set for 64-bit generators */
  uint32_t mt[PRNG_MT_N];
  int mti;
  uint64_t s[2];
} prng_t;

/* returns 0 on success, -1 for an unknown type or an invalid seed */
int prng_init(prng_t *p, const char *type, uint64_t seed);
void prng_next256(prng_t *p, unsigned char *priv);
void prng_skip256(prng_t *p, uint64_t n);

extern const char *prng_types;

#endif /* __BRAINFLAYER_PRNG_H_ */

/*  vim: set ts=2 sw=2 et ai si: */
