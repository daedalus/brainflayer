/*  Copyright (c) 2015 Nicolas Courtois, Guangyan Song, Ryan Castellucci, All Rights Reserved */
#ifndef __EC_PUBKEY_FAST_H_
#define __EC_PUBKEY_FAST_H_

int secp256k1_ec_pubkey_precomp_table_save(int, unsigned char *);
int secp256k1_ec_pubkey_precomp_table(int, unsigned char *);
int secp256k1_ec_pubkey_create_precomp(unsigned char *, int *, const unsigned char *);
int secp256k1_ec_pubkey_incr_init(unsigned char *, unsigned int);
int secp256k1_ec_pubkey_incr(unsigned char *, int *, unsigned char *);

int secp256k1_scalar_add_b32(void *, void *, void *);

void priv_add_uint8(unsigned char *, unsigned char);
void priv_add_uint32(unsigned char *, unsigned int);

void * secp256k1_ec_priv_to_gej(unsigned char *);
int secp256k1_ec_pubkey_add_gej(unsigned char *, int *, void *);

int secp256k1_ec_pubkey_batch_init(unsigned int);
int secp256k1_ec_pubkey_batch_create(unsigned int, unsigned char (*)[65], unsigned char (*)[32]);
int secp256k1_ec_pubkey_batch_incr(unsigned int, unsigned int, unsigned char (*)[65], unsigned char (*)[32], unsigned char[32]);

/* --- opaque elliptic curve helpers used by the Pollard kangaroo solver ---
 *
 * Points are passed around as fixed size byte buffers whose sizes are reported
 * by the two accessors below. "gej" buffers hold a Jacobian point, "ge" buffers
 * hold an affine point. This keeps the secp256k1 internal types confined to
 * this translation unit (the only one that includes the library internals).
 * All scalars are 32 byte big-endian and are reduced modulo the group order. */
#include <stddef.h>

size_t secp256k1_ec_gej_size(void);
size_t secp256k1_ec_ge_size(void);

/* parse a 33 (compressed) or 65 (uncompressed) byte public key into a gej;
 * returns 0 on success, non-zero if the key could not be parsed */
int secp256k1_ec_pubkey_to_gej(void *gej, const unsigned char *pub, size_t pub_sz);

/* r = scalar * G */
void secp256k1_ec_scalar_mul_g_gej(void *gej, const unsigned char scalar[32]);
void secp256k1_ec_scalar_mul_g_ge(void *ge, const unsigned char scalar[32]);

/* r_gej = a_gej + b_ge (a and r may be the same buffer) */
void secp256k1_ec_gej_add_ge(void *r_gej, const void *a_gej, const void *b_ge);

/* affine x coordinate (32 byte big-endian) of a Jacobian point */
void secp256k1_ec_gej_get_x(unsigned char x[32], const void *gej);

/* affine x coordinates of n Jacobian points, using one batched inversion */
void secp256k1_ec_gej_get_x_batch(unsigned char (*x)[32], const void *gej_array, size_t n);

/* for n kangaroos: gej[i] += jumps[idx[i]], then write the affine x coordinate
 * of each updated point to x_out[i]. A single batched field inversion is used
 * for all n points. */
void secp256k1_ec_kangaroo_batch_step(void *gej_array, const void *jumps_ge_array,
                                      const unsigned int *idx, unsigned char (*x_out)[32],
                                      size_t n);

/* scalar arithmetic modulo the group order, all operands 32 byte big-endian */
void secp256k1_ec_scalar_sub_b32(unsigned char out[32], const unsigned char a[32], const unsigned char b[32]);
void secp256k1_ec_scalar_neg_b32(unsigned char out[32], const unsigned char a[32]);
#endif//__EC_PUBKEY_FAST_H_
