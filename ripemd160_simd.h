/* RIPEMD-160 of 32 byte inputs, RMD_LANES of them at once, one per lane of a
 * GCC vector. Included by ripemd160_256.c once per instruction set, with
 * RMD_V (a vector of RMD_LANES uint32_t), RMD_NAME and RMD_TARGET defined.
 * Uses the tables of ripemd160_256.c. Little endian only. */

#define RMD_ROL(s, n) (((n) << (s)) | ((n) >> (32-(s))))

#define RMD_LINE(F, A, B, C, D, E, R, S, K, round) \
  _Pragma("GCC unroll 16") \
  for (w = 0; w < 16; w++) { \
    T = RMD_ROL(S[round][w], A + F(B, C, D) + X[R[round][w]] + K[round]) + E; \
    A = E; E = D; D = RMD_ROL(10, C); C = B; B = T; \
  }

RMD_TARGET
static void RMD_NAME(const unsigned char *in, unsigned char *out) {
  uint32_t t[16][RMD_LANES];
  RMD_V X[16], h[5], T;
  RMD_V AL, BL, CL, DL, EL, AR, BR, CR, DR, ER;
  unsigned int i, j, w;

  /* transpose: X[j] holds word j of every input, then the fixed padding */
  for (j = 0; j < 8; j++) {
    for (i = 0; i < RMD_LANES; i++) { memcpy(&t[j][i], in + 32*i + 4*j, 4); }
    memcpy(&X[j], t[j], sizeof(RMD_V));
  }
  for (j = 8; j < 16; j++) { X[j] = (RMD_V){ 0 }; }
  X[8] += 0x80;
  X[14] += 256;

  for (j = 0; j < 5; j++) { h[j] = (RMD_V){ 0 } + initial_h[j]; }
  AL = AR = h[0];
  BL = BR = h[1];
  CL = CR = h[2];
  DL = DR = h[3];
  EL = ER = h[4];

  RMD_LINE(F1, AL, BL, CL, DL, EL, RL, SL, KL, 0)
  RMD_LINE(F5, AR, BR, CR, DR, ER, RR, SR, KR, 0)
  RMD_LINE(F2, AL, BL, CL, DL, EL, RL, SL, KL, 1)
  RMD_LINE(F4, AR, BR, CR, DR, ER, RR, SR, KR, 1)
  RMD_LINE(F3, AL, BL, CL, DL, EL, RL, SL, KL, 2)
  RMD_LINE(F3, AR, BR, CR, DR, ER, RR, SR, KR, 2)
  RMD_LINE(F4, AL, BL, CL, DL, EL, RL, SL, KL, 3)
  RMD_LINE(F2, AR, BR, CR, DR, ER, RR, SR, KR, 3)
  RMD_LINE(F5, AL, BL, CL, DL, EL, RL, SL, KL, 4)
  RMD_LINE(F1, AR, BR, CR, DR, ER, RR, SR, KR, 4)

  /* final mixing stage */
  T = h[1] + CL + DR;
  h[1] = h[2] + DL + ER;
  h[2] = h[3] + EL + AR;
  h[3] = h[4] + AL + BR;
  h[4] = h[0] + BL + CR;
  h[0] = T;

  /* transpose back */
  for (j = 0; j < 5; j++) {
    memcpy(t[j], &h[j], sizeof(RMD_V));
    for (i = 0; i < RMD_LANES; i++) { memcpy(out + 20*i + 4*j, &t[j][i], 4); }
  }
}

#undef RMD_LINE
#undef RMD_ROL
