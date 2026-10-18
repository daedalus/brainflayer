#!/bin/sh
# Check brainflayer's Pollard kangaroo mode (-K): for a known private key in a
# known interval, derive the public key with a small independent secp256k1
# implementation in Python and make sure brainflayer recovers the key.
# Usage: tests/kangaroo_test.sh [path/to/brainflayer]
set -e
BF=${1:-./brainflayer}
fail=0

# compute the compressed (argv2=c) or uncompressed (u) pubkey of a private key
pub() { # key form
  python3 - "$1" "$2" <<'EOF'
import sys
p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
def inv(a): return pow(a, p - 2, p)
def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
    if P == Q: l = (3 * P[0] * P[0]) * inv(2 * P[1]) % p
    else:      l = (Q[1] - P[1]) * inv(Q[0] - P[0]) % p
    x = (l * l - P[0] - Q[0]) % p
    return (x, (l * (P[0] - x) - P[1]) % p)
def mul(k):
    R, Q = None, (Gx, Gy)
    while k:
        if k & 1: R = add(R, Q)
        Q = add(Q, Q); k >>= 1
    return R
k = int(sys.argv[1], 0)
x, y = mul(k)
if sys.argv[2] == 'u':
    print('04%064x%064x' % (x, y))
else:
    print(('03' if (y & 1) else '02') + '%064x' % x)
EOF
}

check() { # label key range form extra
  key=$2; want=$(python3 -c "print('%064x' % int('$key', 0))")
  P=$(pub "$key" "$4")
  got=$(timeout 180 "$BF" -w 8 -K "$P" -R "$3" $5 | tail -1)
  if [ "$got" = "$want" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1 (key=$key range=$3 got=$got)"; fail=1
  fi
}

# fixed keys, bit-width range form, compressed and uncompressed
check "compressed 20-bit"        0xabcde   20 c
check "uncompressed 20-bit"      0xabcde   20 u
check "compressed 24-bit (02 y)" 0xc0ffee  24 c
check "boundary low  2^(b-1)"    0x80000   20 c
check "boundary high 2^b-1"      0xfffff   20 c

# explicit hex START:END range
check "explicit range"           0x1a2b3c  100000:1fffff c

# a couple of random keys
for b in 24 28; do
  rk=$(python3 -c "import random;print(hex(random.randint(1<<($b-1),(1<<$b)-1)))")
  check "random ${b}-bit" "$rk" "$b" c
done

# tuning knobs should not break correctness
check "custom -D/-J/-G"          0x3fa21   20 c "-D 6 -J 16 -G 16"

exit $fail
