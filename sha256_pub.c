/* SHA-256 of secp256k1 public keys, for the u and c hash160s */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include "sha256_pub.h"

void sha256_upub(unsigned char *out, const unsigned char *upub) {
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, upub, 65);
  SHA256_Final(out, &ctx);
}

void sha256_cpub(unsigned char *out, const unsigned char *upub) {
  SHA256_CTX ctx;
  unsigned char cpub[33];

  /* quick and dirty public key compression */
  cpub[0] = 0x02 | (upub[64] & 0x01);
  memcpy(cpub + 1, upub + 1, 32);
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, cpub, 33);
  SHA256_Final(out, &ctx);
}

/* Several keys at once: SSE2 (4), AVX2 (8) and AVX-512F (16 lanes). */
#if (defined(__x86_64__) || defined(__i386__)) && defined(__GNUC__) && !defined(PCT_BIG_ENDIAN)
#define SHA256_SIMD 1

#include <cpuid.h>

static const uint32_t initial_h256[8] = {
  0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const uint32_t K256[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static inline uint32_t be32(const unsigned char *p) {
  uint32_t v;
  memcpy(&v, p, 4);
  return __builtin_bswap32(v);
}

typedef uint32_t sha_v4 __attribute__((vector_size(16)));
typedef uint32_t sha_v8 __attribute__((vector_size(32)));
typedef uint32_t sha_v16 __attribute__((vector_size(64)));

#define SHA_V sha_v4
#define SHA_LANES 4
#define SHA_UNAME sha256_upub_x4
#define SHA_CNAME sha256_cpub_x4
#define SHA_BLOCK sha256_block_x4
#define SHA_TARGET __attribute__((target("sse2")))
#include "sha256_simd.h"
#undef SHA_V
#undef SHA_LANES
#undef SHA_UNAME
#undef SHA_CNAME
#undef SHA_BLOCK
#undef SHA_TARGET

#define SHA_V sha_v8
#define SHA_LANES 8
#define SHA_UNAME sha256_upub_x8
#define SHA_CNAME sha256_cpub_x8
#define SHA_BLOCK sha256_block_x8
#define SHA_TARGET __attribute__((target("avx2")))
#include "sha256_simd.h"
#undef SHA_V
#undef SHA_LANES
#undef SHA_UNAME
#undef SHA_CNAME
#undef SHA_BLOCK
#undef SHA_TARGET

#define SHA_V sha_v16
#define SHA_LANES 16
#define SHA_UNAME sha256_upub_x16
#define SHA_CNAME sha256_cpub_x16
#define SHA_BLOCK sha256_block_x16
#define SHA_TARGET __attribute__((target("avx512f")))
#include "sha256_simd.h"
#undef SHA_V
#undef SHA_LANES
#undef SHA_UNAME
#undef SHA_CNAME
#undef SHA_BLOCK
#undef SHA_TARGET
#endif

int sha256_pub_lanes(void) {
  static int lanes = 0;
  const char *e;
  int max;

  if (lanes) { return lanes; }
  max = (e = getenv("BRAINFLAYER_SHA256_LANES")) != NULL ? atoi(e) : 16;
  lanes = 1;
#ifdef SHA256_SIMD
  __builtin_cpu_init();
  if (max >= 16 && __builtin_cpu_supports("avx512f")) {
    lanes = 16;
  } else if (max >= 8 && __builtin_cpu_supports("avx2")) {
    lanes = 8;
  } else if (max >= 4 && __builtin_cpu_supports("sse2")) {
    lanes = 4;
  }
  /* SHA-NI, which OpenSSL uses one key at a time, is faster than SSE2, but
   * do as asked if the width was given */
  if (lanes == 4 && e == NULL) {
    unsigned int a, b, c, d;
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & bit_SHA)) { lanes = 1; }
  }
#else
  (void)max;
#endif
  return lanes;
}

#ifdef SHA256_SIMD
#define SHA256_PUB_N(x16, x8, x4) \
  int lanes = sha256_pub_lanes(); \
  for (; lanes >= 16 && n >= 16; n -= 16, upub += 16, out += 16) { x16(upub, out); } \
  for (; lanes >= 8 && n >= 8; n -= 8, upub += 8, out += 8) { x8(upub, out); } \
  for (; lanes >= 4 && n >= 4; n -= 4, upub += 4, out += 4) { x4(upub, out); }
#else
#define SHA256_PUB_N(x16, x8, x4)
#endif

void sha256_upub_n(unsigned char (*out)[32], const unsigned char (*upub)[65], size_t n) {
  SHA256_PUB_N(sha256_upub_x16, sha256_upub_x8, sha256_upub_x4)
  for (; n > 0; --n, ++upub, ++out) { sha256_upub(*out, *upub); }
}

void sha256_cpub_n(unsigned char (*out)[32], const unsigned char (*upub)[65], size_t n) {
  SHA256_PUB_N(sha256_cpub_x16, sha256_cpub_x8, sha256_cpub_x4)
  for (; n > 0; --n, ++upub, ++out) { sha256_cpub(*out, *upub); }
}
