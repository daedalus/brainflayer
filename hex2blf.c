/*  Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h> /*  for ntohl/htonl */

#include <math.h> /* pow/exp */

#include "hex.h"
#include "bloom.h"
#include "hash160.h"

static void usage(char *name) {
  fprintf(stderr, "[!] Usage: %s [-m LOG2BITS] [-k SLICES] hashfile.hex bloomfile.blf\n\
    -m LOG2BITS  filter size is 2^LOG2BITS bits (%d..%d), each slice is that\n\
                 many bits of the hash160; without -m and -k a legacy 1 GiB\n\
                 filter with 25 32-bit slices is made\n\
    -k SLICES    number of slices of each hash160 to set (1..%d), default:\n\
                 the best number for the count of hashes; with only -k,\n\
                 -m defaults to 32\n\
  Adding to an existing filter keeps its size and number of slices.\n",
    name, BLOOM_LOG2_MIN, BLOOM_LOG2_MAX, BLOOM_SLICES_MAX);
  exit(1);
}

int main(int argc, char **argv) {
  hash160_t hash;
  int i, c;
  double pct;
  struct stat sb;
  unsigned char *hashfile, *bloomfile;
  unsigned char trailer[BLOOM_TRAILER_SZ];
  unsigned int mopt = 0, kopt = 0;
  bloom_t bloom;
  FILE *f, *b;
  size_t line_sz = 1024, line_ct = 0;
  char *line;

  double err_rate;

  while ((c = getopt(argc, argv, "m:k:")) != -1) {
    switch (c) {
      case 'm':
        if ((mopt = atoi(optarg)) < BLOOM_LOG2_MIN || mopt > BLOOM_LOG2_MAX) { usage(argv[0]); }
        break;
      case 'k':
        if ((kopt = atoi(optarg)) < 1 || kopt > BLOOM_SLICES_MAX) { usage(argv[0]); }
        break;
      default:
        usage(argv[0]);
    }
  }

  if (argc - optind != 2) { usage(argv[0]); }

  hashfile = argv[optind];
  bloomfile = argv[optind+1];

  if ((f = fopen(hashfile, "r")) == NULL) {
    fprintf(stderr, "[!] Failed to open hash160 file '%s'\n", hashfile);
    exit(1);
  }

  if ((line = malloc(line_sz+1)) == NULL) {
    fprintf(stderr, "[!] malloc failed (line buffer)\n");
    exit(1);
  }

  if (stat(bloomfile, &sb) == 0) {
    if (bloom_probe(&bloom, bloomfile) != 0) {
      fprintf(stderr, "[!] '%s' is not a bloom filter file (wrong size or trailer)\n", bloomfile);
      exit(1);
    }
    if ((mopt && mopt != bloom.log2bits) || (kopt && kopt != bloom.k)) {
      fprintf(stderr, "[!] Existing bloom filter '%s' has 2^%u bits and %u slices\n", bloomfile, bloom.log2bits, bloom.k);
      exit(1);
    }
  } else {
    if (mopt || kopt) {
      if (!mopt) { mopt = 32; }
      if (!kopt) {
        // count the hashes to pick the number of slices
        while (getline(&line, &line_sz, f) > 0) { ++line_ct; }
        rewind(f);
        kopt = bloom_best_k(mopt, line_ct);
        line_ct = 0;
      }
    }
    if (bloom_init(&bloom, mopt, kopt) != 0) {
      fprintf(stderr, "[!] Invalid bloom filter size 2^%u bits or %u slices\n", mopt, kopt);
      usage(argv[0]);
    }
  }

  if (bloom.legacy) {
    fprintf(stderr, "[*] Legacy bloom filter: 2^32 bits used of a %zu byte file, 25 slices\n", bloom.bits_sz);
  } else {
    fprintf(stderr, "[*] Bloom filter: 2^%u bits (%zu bytes), %u slices of %u bits\n",
            bloom.log2bits, bloom.bits_sz, bloom.k, bloom.log2bits);
  }

  if ((bloom.bits = malloc(bloom.bits_sz)) == NULL) {
    fprintf(stderr, "[!] malloc failed (bloom filter)\n");
    exit(1);
  }

  if (stat(bloomfile, &sb) == 0) {
    if ((b = fopen(bloomfile, "r+")) == NULL) {
      fprintf(stderr, "[!] Failed to open bloom filter file '%s' for read/write\n", bloomfile);
      exit(1);
    }
    fprintf(stderr, "[*] Reading existing bloom filter from '%s'...\n", bloomfile);
    if ((fread(bloom.bits, bloom.bits_sz, 1, b)) != 1 || (fseek(b, 0, SEEK_SET)) != 0) {
      fprintf(stderr, "[!] Failed to read existing boom filter from '%s'\n", bloomfile);
      exit(1);
    }
  } else {
    /*  Assume the file didn't exist - yes there is a race condition */
    if ((b = fopen(bloomfile, "w+")) == NULL) {
      fprintf(stderr, "[!] Failed to create bloom filter file '%s'\n", bloomfile);
      exit(1);
    }
    // start it empty
    fprintf(stderr, "[*] Initializing bloom filter...\n");
    memset(bloom.bits, 0, bloom.bits_sz);
  }

  i = 0;
  stat(hashfile, &sb);
  fprintf(stderr, "[*] Loading hash160s from '%s' \033[s  0.0%%", hashfile);
  while (getline(&line, &line_sz, f) > 0) {
    ++line_ct;
    unhex(line, strlen(line), hash.uc, sizeof(hash.uc));
    bloom_set(&bloom, hash.ul);

    if ((++i & 0x3ffff) == 0) {
      pct = 100.0 * ftell(f) / sb.st_size;
      fprintf(stderr, "\033[u%5.1f%%", pct);
      fflush(stderr);
    }
  }
  fprintf(stderr, "\033[u 100.0%%\n");

  err_rate = bloom_fp_rate(&bloom, line_ct);
  fprintf(stderr, "[*] Loaded %zu hashes, false positive rate: ~%.3e (1 in ~%.3e)\n", line_ct, err_rate, 1/err_rate);

  fprintf(stderr, "[*] Writing bloom filter to '%s'...\n", bloomfile);
  bloom_trailer(&bloom, trailer);
  if ((fwrite(bloom.bits, bloom.bits_sz, 1, b)) != 1 ||
      (!bloom.legacy && fwrite(trailer, sizeof(trailer), 1, b) != 1) ||
      fclose(b) != 0) {
    fprintf(stderr, "[!] Failed to write bloom filter file '%s'\n", bloomfile);
    exit(1);
  }

  fprintf(stderr, "[+] Success!\n");
  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
