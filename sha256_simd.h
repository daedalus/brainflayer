/* SHA-256 of public keys, SHA_LANES of them at once, one per lane of a GCC
 * vector. Included by sha256_pub.c once per instruction set, with SHA_V (a
 * vector of SHA_LANES uint32_t), SHA_LANES, SHA_UNAME, SHA_CNAME,
 * SHA_BLOCK and SHA_TARGET defined. Uses the tables of sha256_pub.c.
 * Little endian only. */

#define SHA_ROR(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define SHA_CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define SHA_MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define SHA_S0(x) (SHA_ROR(x, 2) ^ SHA_ROR(x, 13) ^ SHA_ROR(x, 22))
#define SHA_S1(x) (SHA_ROR(x, 6) ^ SHA_ROR(x, 11) ^ SHA_ROR(x, 25))
#define SHA_s0(x) (SHA_ROR(x, 7) ^ SHA_ROR(x, 18) ^ ((x) >> 3))
#define SHA_s1(x) (SHA_ROR(x, 17) ^ SHA_ROR(x, 19) ^ ((x) >> 10))

/* one 64 byte block, W is the message, big endian words already swapped */
SHA_TARGET
static inline void SHA_BLOCK(SHA_V s[8], SHA_V W[16]) {
  SHA_V a = s[0], b = s[1], c = s[2], d = s[3];
  SHA_V e = s[4], f = s[5], g = s[6], h = s[7];
  SHA_V T1, T2;
  unsigned int i;

  _Pragma("GCC unroll 64")
  for (i = 0; i < 64; i++) {
    if (i >= 16) {
      W[i&15] += SHA_s1(W[(i-2)&15]) + W[(i-7)&15] + SHA_s0(W[(i-15)&15]);
    }
    T1 = h + SHA_S1(e) + SHA_CH(e, f, g) + K256[i] + W[i&15];
    T2 = SHA_S0(a) + SHA_MAJ(a, b, c);
    h = g; g = f; f = e; e = d + T1;
    d = c; c = b; b = a; a = T1 + T2;
  }
  s[0] += a; s[1] += b; s[2] += c; s[3] += d;
  s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

/* transpose back: lane i of s[j] is word j of digest i */
#define SHA_STORE() \
  for (j = 0; j < 8; j++) { \
    memcpy(t[j], &s[j], sizeof(SHA_V)); \
    for (i = 0; i < SHA_LANES; i++) { \
      t[j][i] = __builtin_bswap32(t[j][i]); \
      memcpy(out[i] + 4*j, &t[j][i], 4); \
    } \
  }

#define SHA_INIT() \
  for (j = 0; j < 8; j++) { s[j] = (SHA_V){ 0 } + initial_h256[j]; }

/* of the 65 byte uncompressed public keys */
SHA_TARGET
static void SHA_UNAME(const unsigned char (*upub)[65], unsigned char (*out)[32]) {
  uint32_t t[16][SHA_LANES];
  SHA_V W[16], s[8];
  unsigned int i, j;

  SHA_INIT()
  for (j = 0; j < 16; j++) {
    for (i = 0; i < SHA_LANES; i++) { t[j][i] = be32(upub[i] + 4*j); }
    memcpy(&W[j], t[j], sizeof(SHA_V));
  }
  SHA_BLOCK(s, W);

  /* the last byte, then the padding and the length (520 bits) */
  for (i = 0; i < SHA_LANES; i++) { t[0][i] = (uint32_t)upub[i][64] << 24; }
  memcpy(&W[0], t[0], sizeof(SHA_V));
  W[0] += 0x00800000;
  for (j = 1; j < 16; j++) { W[j] = (SHA_V){ 0 }; }
  W[15] += 520;
  SHA_BLOCK(s, W);

  SHA_STORE()
}

/* of the 33 byte compressed form of the uncompressed public keys */
SHA_TARGET
static void SHA_CNAME(const unsigned char (*upub)[65], unsigned char (*out)[32]) {
  uint32_t t[16][SHA_LANES];
  SHA_V W[16], s[8];
  unsigned int i, j;

  SHA_INIT()
  /* the compressed key is the parity byte then the x coordinate, which is
   * where it already is in the uncompressed key */
  for (i = 0; i < SHA_LANES; i++) {
    t[0][i] = (be32(upub[i]) & 0x00ffffff) | (uint32_t)(0x02 | (upub[i][64] & 0x01)) << 24;
  }
  for (j = 1; j < 8; j++) {
    for (i = 0; i < SHA_LANES; i++) { t[j][i] = be32(upub[i] + 4*j); }
  }
  for (i = 0; i < SHA_LANES; i++) { t[8][i] = (uint32_t)upub[i][32] << 24 | 0x00800000; }
  for (j = 0; j < 9; j++) { memcpy(&W[j], t[j], sizeof(SHA_V)); }
  /* the padding and the length (264 bits) */
  for (j = 9; j < 16; j++) { W[j] = (SHA_V){ 0 }; }
  W[15] += 264;
  SHA_BLOCK(s, W);

  SHA_STORE()
}

#undef SHA_INIT
#undef SHA_STORE
#undef SHA_s1
#undef SHA_s0
#undef SHA_S1
#undef SHA_S0
#undef SHA_MAJ
#undef SHA_CH
#undef SHA_ROR
