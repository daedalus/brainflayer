#ifndef __RIPEMD160_256_H_
#define __RIPEMD160_256_H_

#include <stdint.h>

#include <stddef.h>

void ripemd160_256(const void *in, void *out);

/* RIPEMD-160 of n 32 byte inputs stored back to back, writing n 20 byte
 * digests back to back (an array of hash160_t). On x86 this hashes 16, 8 or
 * 4 inputs at once with AVX-512F, AVX2 or SSE2, whichever the CPU has, and
 * the rest one at a time. BRAINFLAYER_RIPEMD_LANES caps the width (1 turns
 * the vector code off). */
void ripemd160_256_n(const void *in, void *out, size_t n);
/* how many inputs ripemd160_256_n hashes at once */
int ripemd160_256_lanes(void);

#endif//__RIPEMD160_256_H_
