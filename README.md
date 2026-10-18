[![Gitpod ready-to-code](https://img.shields.io/badge/Gitpod-ready--to--code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/ryancdotorg/brainflayer)

Brainflayer
===========

Update: Jan 10, 2021

Ubuntu 18.04

Make changes in Makefile, to make Brainflayer compile successfully on Ubuntu 18.04.

Ubuntu 20.04

You should build it from Brainflayer's original repo

[Brainflayer] (https://github.com/ryancdotorg/brainflayer)


Below this line is the original Brainflayer README
----------------------------------------------------------------------------------------------------

Brainflayer is a Proof-of-Concept brainwallet cracking tool that uses
[libsecp256k1](https://github.com/bitcoin/secp256k1) for pubkey generation.
It was originally released as part of my DEFCON talk about cracking brainwallets
([slides](https://rya.nc/dc23), [video](https://rya.nc/b6), [why](https://rya.nc/defcon-brainwallets.html)).

The name is a reference to [Mind Flayers](https://en.wikipedia.org/wiki/Illithid),
a race of monsters from the Dungeons & Dragons role-playing game. They eat
brains, psionically enslave people and look like lovecraftian horrors.

The current release is more than four times faster than the DEFCON release, and
many features have been added.

If brainflayer is useful to you, please get in touch to let me know. I'm very
interested in any research it's being used for, and I'm generally happy to
collaborate with academic groups.

Disclaimer
----------
Just because you *can* steal someone's money doesn't mean you *should*.
Stealing would make you a jerk. Don't be a jerk.

No support will be provided at this time, and I may ignore or close issues
requesting support without responding.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Usage
-----

### Basic

Precompute the bloom filter:

`hex2blf example.hex example.blf`

By default this is the classic 1 GiB filter with 25 slices. Each hash160 is
already uniformly random, so the filter does not rehash it: every bit position
is a slice of the hash160. To hold more addresses at the same false positive
rate, make the filter bigger with `-m` and use more slices with `-k`:

`hex2blf -m 36 -k 40 example.hex example.blf`

* `-m LOG2BITS` the filter has 2^LOG2BITS bits (20..40, e.g. 33 = 1 GiB,
                36 = 8 GiB) and each slice is LOG2BITS bits of the hash160
* `-k SLICES`   how many slices of the hash160 are set and checked (1..160),
                taken at evenly spaced offsets of the 160 bits, wrapping
                around. Without `-k` the best number for the count of hashes
                is used, `round(2^LOG2BITS / n * ln 2)`

These filters end with a 16 byte trailer that records the size and number of
slices, so `brainflayer -b`, `blfchk` and adding more hashes with `hex2blf`
pick them up without extra options. Legacy filters keep working unchanged.
`tests/bloom_test.sh` checks the slicing against a Python reference.

`brainflayer` and `blfchk` check hashes in batches, prefetching bits a few
hashes ahead so the cache misses overlap. On x86 an AVX2 version that checks
several hashes per instruction is used when the environment sets
`BRAINFLAYER_SIMD=1` and the CPU supports it. It is off by default because
lookups into a filter bigger than the CPU caches are bound by memory latency,
and there the scalar code with prefetching was faster on the CPUs tried.

In crack mode the RIPEMD-160 step of the `u` and `c` hash160s is done 16, 8
or 4 keys at a time with AVX-512F, AVX2 or SSE2, whichever the CPU has, which
makes it 4-8x faster than one at a time (`-I -c uc` about 1.4x faster overall).
`BRAINFLAYER_RIPEMD_LANES=N` caps the width, and 1 turns the vector code off.
`tests/ripemd160_test.sh` checks every width against the scalar code.

The SHA-256 of the public keys before it is vectorized the same way, 16, 8 or
4 keys at a time. On CPUs with SHA-NI, which OpenSSL uses for one key at a
time, SSE2 is slower than that and is skipped unless asked for.
`BRAINFLAYER_SHA256_LANES=N` caps the width, and 1 turns the vector code off.
`tests/sha256_test.sh` checks every width against the scalar code.

Run Brainflayer against it:

`brainflayer -v -b example.blf -i phraselist.txt`

or

`your_generator | brainflayer -v -b example.blf`

### Advanced

Brainflayer's design is heavily influenced by [Unix philosophy](https://en.wikipedia.org/wiki/Unix_philosophy).
It (mostly) does one thing: hunt for tasty brainwallets. A major feature it
does *not* have is generating candidate passwords/passphrases. There are plenty
of other great tools that do that, and brainflayer is happy to have you pipe
their output to it.

Unfortunately, brainflayer is not currently multithreaded. If you want to have
it keep multiple cores busy, you'll have to come up with a way to distribute
the work yourself (brainflayer's -n and -k options may help). In my testing,
brainflayer benefits significantly from hyperthreading, so you may want to
run two copies per physical core. Also worth noting is that brainflayer mmaps
its data files in shared memory, so additional brainflayer processes do not
use up that much additional RAM.

While not strictly required, it is *highly* recommended to use the following
options:

* `-m FILE` Load the ecmult table from `FILE` (generated with `ecmtabgen`)
            rather than computing it on startup. This will allow multiple
            brainflayer processes to share the same table in memory, and
            signifigantly reduce startup time when using a large table.

* `-f FILE` Verify check bloom filter matches against `FILE`, a list of all
            hash160s generated with
            `sort -u example.hex | xxd -r -p > example.bin`
            Enough addresses exist on the Bitcoin network to cause false
            positives in the bloom filter, this option will suppress them.

Brainflayer supports a few other types of input via the `-t` option:

* `-t keccak` passphrases to be hashed with keccak256 (some ethereum tools)

* `-t priv` raw private keys - this can be used to support arbitrary
            deterministic wallet schemes via an external program. Any trailing
            data after the hex encoded private key will be included in
            brainflayer's output as well, for reference. See also the `-I`
            option if you want to crack a bunch of sequential keys, which has
            special speed optimizations.

* `-t warp` salts or passwords/passphrases for WarpWallet

* `-t bwio` salts or passwords/passphrases for brainwallet.io

* `-t bv2`  salts or passwords/passphrases for brainv2 - this one is *very* slow
            on CPU, however the parameter choices make it a great target for GPUs
            and FPGAs.

* `-t rush` passwords for password-protected rushwallets - pass the fragment (the
            part of the url after the #) using `-r`. Almost all wrong passwords
            will be rejected even without a bloom filter.

Address types can be specified with the `-c` option:

* `-c u` uncompressed addresses

* `-c c` compressed addresses

* `-c e` ethereum addresses

* `-c x` most signifigant bits of public point's x coordinate

It's possible to combine two or more of these, e.g. the default is `-c uc`.

An incremental private key brute force mode is available for fans of
[directory.io](http://www.directory.io/), try

`brainflayer -v -I 0000000000000000000000000000000000000000000000000000000000000001 -b example.blf`

A PRNG generator mode checks keys produced by common non-cryptographic random
number generators. Pass the generator with `-P`, its seed with `-S` and,
optionally, the first element of the sequence with `-F`; brainflayer checks the
first element and then generates the rest of the sequence from the seeded PRNG:

`brainflayer -v -P pymt -S 2015 -F 0000000000000000000000000000000000000000000000000000000000000001 -b example.blf`

Each generated key is the next 256 bits of the generator's output, least
significant word first (Python's `getrandbits(256)`), so `-P pymt -S N`
produces the same keys as `random.seed(N); random.getrandbits(256)`. Supported
generators:

* `mt19937`      MT19937 seeded with `init_genrand` (C, C++ `std::mt19937`,
                 numpy `RandomState(seed)`), 32-bit seed
* `pymt`         MT19937 seeded with `init_by_array` (Python `random.seed`,
                 Ruby `srand`), up to 64-bit seed
* `lcg64`        64-bit LCG, Knuth's MMIX constants, the seed is the state
* `xorshift64`   Marsaglia xorshift64 (13, 7, 17), non-zero seed
* `xorshift128p` xorshift128+ with its state seeded by splitmix64
* `splitmix64`   splitmix64

`-k K` skips the first K generated keys, `-n K/N` uses only the Kth of every N,
and `-L COUNT` stops after COUNT keys (the default is to run forever). Run
`tests/prng_test.sh` to check the generators against Python reference
implementations.

A Pollard kangaroo mode solves the elliptic curve discrete logarithm over an
interval: given a public key whose private key is known to lie in some range,
it recovers that private key. Unlike the other modes it does not read
candidates from stdin - it is given the target and the range and searches on
its own. Pass the target public key with `-K` (compressed, 66 hex digits, or
uncompressed, 130) and the interval with `-R`:

`brainflayer -v -K 0292a2457e760a248a7f3fa7edd2cfdab72b324d740e18bbb02645ad723fdaea7a -R 29`

The range may be given either as `START:END` hex scalars, or as a single
decimal bit width `BITS` meaning the interval `[2^(BITS-1), 2^BITS - 1]` (the
convention used by the Bitcoin "puzzle" keys). On success the recovered private
key is printed, in hex, to the output (honouring `-o`).

Expected work is about `sqrt(range)` elliptic curve operations, so the interval
has to be small enough to be tractable - a few tens of bits for a quick run on
one core, not a full 256-bit key. The method is Las Vegas randomised; runtime
varies from one attempt to the next. Tuning options (all optional, with
defaults derived from the range width):

* `-D DPBITS` distinguished point rarity - a point is stored when its x
              coordinate has this many low bits clear. Rarer points use less
              memory but add latency to detecting a collision.
* `-J NJUMPS` number of entries in the pseudo-random jump table (default 32)
* `-G HERD`   kangaroos per herd (both a tame and a wild herd of this size are
              run). The search is single threaded, so a large herd does not
              reduce the total work; a small one (the default is 8) is fastest
              because it still lets the batched field inversion amortise.
* `-L COUNT`  give up after COUNT steps instead of running until solved

Run `tests/kangaroo_test.sh` to check that keys in known intervals are
recovered (public keys are derived with an independent secp256k1 implementation
in Python).

See the output of `brainflayer -h` for more detailed usage info.

Also included is `blfchk` - you can pipe it hex encoded hash160 to check a
bloom filter file for. It's very fast - it can easily check millions of
hash160s per second. Not entirely sure what this is good for but I'm sure
you'll come up with something.

#### BIP39

Generate BIP39 for BrainFlayer or similar applications.

Parameters:

- -n how many pieces to be generate.
- -l how many words will there be in a generate?
- -s Will the words be combined?
- -w wordlist

Example command:

    ./brain12words.py -n 9000000000000000000 -l 12 -w brainwalletdictionary.txt | ./brainflayer -v -o found.txt -b bloom.blf

Building
--------

Should compile on Linux with `make` provided you have the required devel libs
installed (at least openssl and gmp are required along with libsecp256k1's
build dependencies). I really need to learn autotools. If you file an issue
about a build failure in libsecp256k1 I will close it.

Dependencies should install with:

```
apt install autoconf autogen automake git libtool make
apt install build-essential libgmp-dev libgmp3-dev libssl-dev zlib1g-dev
```

Supported build target is currently Ubuntu 20.04 on amd64/x86_64. Issues with
building for other platforms probably won’t be fixed. In particular, Kali Linux
is *not* supported. Support for operating systems other than Linux would require
extensive refactoring of Brainflayer's memory optimizations and is not happening.

Redistribution of compiled `brainflayer` binaries is prohibited, and
unauthorized binaries probably contain malware.

Docker
------

Build docker image:

    docker build -t brainflayer .

Precompute the bloom filter:

    docker run -it --entrypoint=/brainflayer/hex2blf -v$(pwd)/data:/data brainflayer /data/input.hex /data/result.blf

Run Brainflayer against it:

    docker run -it -v$(pwd)/data:/data brainflayer -v -b /data/result.blf -i /data/phraselist.txt

Generators
----------

    ./generators/generate2words.py -w wordlist.txt -n 90000000000 \
      | ./brainflayer -v  -o result.txt -b 35.blf
    ./generators/2.py -n 90000000000 | ./brainflayer -v  -o result.txt -b 35.blf

Resources
---------

- https://bitcointalk.org/index.php?topic=267618.0
  on how to find non-zero balance addresses

Authors
-------

The bulk of Brainflayer was written by Ryan Castellucci. Nicolas Courtois and
Guangyan Song contributed the code in `ec_pubkey_fast.c` which more than
doubles the speed of public key computations compared with the stock secp256k1
library from Bitcoin. This code uses a much larger table for ec multiplication
and optimized routines for ec addition and doubling.
