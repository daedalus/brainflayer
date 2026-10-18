#ifndef __SHA256_PUB_H_
#define __SHA256_PUB_H_

#include <stddef.h>

/* SHA-256 of a 65 byte uncompressed public key, and of its 33 byte
 * compressed form */
void sha256_upub(unsigned char *out, const unsigned char *upub);
void sha256_cpub(unsigned char *out, const unsigned char *upub);

/* The same for n public keys, writing n 32 byte digests. On x86 this hashes
 * 16, 8 or 4 keys at once with AVX-512F, AVX2 or SSE2, whichever the CPU has,
 * and the rest one at a time. SSE2 is not used on CPUs with SHA-NI, which is
 * faster, unless asked for: BRAINFLAYER_SHA256_LANES caps the width (1 turns
 * the vector code off). */
void sha256_upub_n(unsigned char (*out)[32], const unsigned char (*upub)[65], size_t n);
void sha256_cpub_n(unsigned char (*out)[32], const unsigned char (*upub)[65], size_t n);
/* how many keys sha256_upub_n and sha256_cpub_n hash at once */
int sha256_pub_lanes(void);

#endif//__SHA256_PUB_H_
