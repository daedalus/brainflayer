#!/bin/sh
# Check that the batched, vectorized sha256 of public keys in crack mode gives
# the same hash160s as the one at a time path of generate mode, at every
# vector width.
# Usage: tests/sha256_test.sh [builddir]
set -e
D=${1:-.}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# 1003 keys: the last chunk of 235 keys leaves a tail for every width
"$D/brainflayer" -c uce -w 8 -P splitmix64 -S 7 -L 1003 | grep splitmix64 > "$T/gen.txt"
cut -d: -f1 "$T/gen.txt" > "$T/all.hex"
"$D/hex2blf" -m 24 -k 8 "$T/all.hex" "$T/all.blf" 2>/dev/null
python3 -c "import sys;sys.stdout.buffer.write(b''.join(sorted(set(bytes.fromhex(l) for l in open(sys.argv[1])))))" \
  "$T/all.hex" > "$T/all.bin"

for lanes in 1 4 8 16; do
  for copt in uce c u; do
    grep -E ":[$copt]:" "$T/gen.txt" > "$T/want" || true
    BRAINFLAYER_SHA256_LANES=$lanes "$D/brainflayer" -c $copt -w 8 -b "$T/all.blf" -f "$T/all.bin" \
      -P splitmix64 -S 7 -L 1003 | grep splitmix64 > "$T/crack"
    cmp -s "$T/want" "$T/crack" && ok "crack mode -c $copt matches generate mode (sha256 lanes <= $lanes)" \
      || bad "crack mode -c $copt differs from generate mode (sha256 lanes <= $lanes)"
  done
done

exit $fail
