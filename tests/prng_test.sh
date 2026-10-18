#!/bin/sh
# Check brainflayer -P against reference implementations in Python.
# Usage: tests/prng_test.sh [path/to/brainflayer]
set -e
BF=${1:-./brainflayer}
FIRST=0000000000000000000000000000000000000000000000000000000000000001
fail=0

check() { # name seed extra-args python-slice
  got=$("$BF" -c u -w 8 -P "$1" -S "$2" $3 | cut -d: -f4)
  want=$(python3 - "$1" "$2" "$4" <<'EOF'
import random, sys
M64 = (1 << 64) - 1
name, seed, sl = sys.argv[1], int(sys.argv[2], 0), sys.argv[3]

def mt_genrand(s):
    mt = [s]
    for i in range(1, 624):
        mt.append((1812433253 * (mt[-1] ^ (mt[-1] >> 30)) + i) & 0xFFFFFFFF)
    r = random.Random()
    r.setstate((3, tuple(mt) + (624,), None))
    return r

def words64(step):
    while True:
        yield step()

def lcg64(s):
    st = [s]
    def f():
        st[0] = (st[0] * 6364136223846793005 + 1442695040888963407) & M64
        return st[0]
    return f

def xorshift64(s):
    st = [s]
    def f():
        x = st[0]
        x ^= (x << 13) & M64; x ^= x >> 7; x ^= (x << 17) & M64
        st[0] = x
        return x
    return f

def splitmix64(s):
    st = [s]
    def f():
        st[0] = (st[0] + 0x9e3779b97f4a7c15) & M64
        z = st[0]
        z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M64
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M64
        return z ^ (z >> 31)
    return f

def xorshift128p(s):
    sm = splitmix64(s)
    st = [sm(), sm()]
    def f():
        s1, s0 = st
        st[0] = s0
        s1 ^= (s1 << 23) & M64
        st[1] = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26)
        return (st[1] + s0) & M64
    return f

if name in ("mt19937", "pymt"):
    r = mt_genrand(seed) if name == "mt19937" else random.Random(seed)
    keys = [r.getrandbits(256) for _ in range(64)]
else:
    f = {"lcg64": lcg64, "xorshift64": xorshift64,
         "splitmix64": splitmix64, "xorshift128p": xorshift128p}[name](seed)
    keys = [sum(f() << (64 * i) for i in range(4)) for _ in range(64)]
for k in eval("keys" + sl):
    print("%064x" % k)
EOF
)
  if [ "$got" = "$want" ]; then
    echo "ok   $1 seed=$2 $3"
  else
    echo "FAIL $1 seed=$2 $3"; fail=1
  fi
}

for t in mt19937 pymt lcg64 xorshift64 xorshift128p splitmix64; do
  check $t 1 "-L 5" "[:5]"
  check $t 0x7a3f1c09 "-L 20 -B 8" "[:20]"
  check $t 12345 "-L 4 -k 3 -n 2/5" "[4::5][:4]"
done
check mt19937 4294967295 "-L 3" "[:3]"
check pymt 0 "-L 3" "[:3]"
check pymt 0x123456789abcdef "-L 3" "[:3]"

# -F: the given first element comes first, then the generator's output
got=$("$BF" -c u -w 8 -P pymt -S 2015 -F $FIRST -L 3 | cut -d: -f4 | head -1)
[ "$got" = "$FIRST" ] && echo "ok   -F first element" || { echo "FAIL -F first element"; fail=1; }
got=$("$BF" -c u -w 8 -P pymt -S 2015 -F $FIRST -L 3 | cut -d: -f4 | tail -2)
want=$("$BF" -c u -w 8 -P pymt -S 2015 -L 2 | cut -d: -f4)
[ "$got" = "$want" ] && echo "ok   -F rest of sequence" || { echo "FAIL -F rest of sequence"; fail=1; }

# key 1 must hash to the well known address of private key 1
got=$("$BF" -c c -w 8 -P pymt -F $FIRST -L 1 | cut -d: -f1)
[ "$got" = "751e76e8199196d454941c45d1b3a323f1433bd6" ] && echo "ok   hash160 of key 1" \
  || { echo "FAIL hash160 of key 1: $got"; fail=1; }

exit $fail
