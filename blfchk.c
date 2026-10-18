/* Copyright (c) 2015 Ryan Castellucci, All Rights Reserved */
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <arpa/inet.h> /* for ntohl/htonl */

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "hex.h"
#include "bloom.h"
#include "mmapf.h"
#include "hash160.h"
#include "hsearchf.h"

/* lines are checked against the filter this many at a time */
#define CHK_BATCH 256

int main(int argc, char **argv) {
  int ret;
  hash160_t hash[CHK_BATCH];
  unsigned char hit[CHK_BATCH];
  char *line[CHK_BATCH] = { NULL };
  size_t line_sz[CHK_BATCH] = { 0 };
  size_t i, n;
  unsigned char *bloomfile, *hashfile;
  bloom_t bloom;
  FILE *ifile = stdin, *ofile = stdout, *hfile = NULL;
  mmapf_ctx bloom_mmapf;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "Usage: %s BLOOM_FILTER_FILE HASH_FILE\n", argv[0]);
    return 1;
  }

  bloomfile = argv[1];

  if ((ret = bloom_open(&bloom, &bloom_mmapf, bloomfile)) != MMAPF_OKAY) {
    fprintf(stderr, "failed to open bloom filter '%s': %s\n", bloomfile, mmapf_strerror(ret));
    return 1;
  } else if (bloom.bits == NULL) {
    fprintf(stderr, "got NULL pointer trying to set up bloom filter\n");
    return 1;
  }

  if (argc == 3) {
    hashfile = argv[2];
    hfile = fopen(hashfile, "r");
  }

  do {
    for (n = 0; n < CHK_BATCH && getline(&line[n], &line_sz[n], ifile) > 0; ++n) {
      memset(hash[n].uc, 0, sizeof(hash[n].uc));
      unhex(line[n], strlen(line[n]), hash[n].uc, sizeof(hash[n].uc));
    }
    bloom_chk_n(&bloom, hash[0].ul, n, hit);

    for (i = 0; i < n; ++i) {
      if (!hit[i]) { continue; }

      if (hfile && hsearchf(hfile, &hash[i]) != 1) {
        //fprintf(ofile, "%s (false positive)\n", hex(hash[i].uc, sizeof(hash[i].uc), buf, sizeof(buf)));
        continue;
      }
      //fprintf(ofile, "%s\n", hex(hash[i].uc, sizeof(hash[i].uc), buf, sizeof(buf)));
      fprintf(ofile, "%s", line[i]);
    }
  } while (n == CHK_BATCH);

  return 0;
}

/*  vim: set ts=2 sw=2 et ai si: */
