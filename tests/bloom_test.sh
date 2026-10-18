#!/bin/sh
# Check sliced bloom filters (hex2blf -m/-k) against a Python reference of the
# slicing, and that blfchk and brainflayer find what hex2blf put in.
# Usage: tests/bloom_test.sh [builddir]
set -e
D=${1:-.}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# hash160s of 200 known keys, plus 2000 keys that are not in the filter
"$D/brainflayer" -c c -w 8 -P splitmix64 -S 1 -L 200 | cut -d: -f1 > "$T/in.hex"
"$D/brainflayer" -c c -w 8 -P splitmix64 -S 2 -L 2000 | cut -d: -f1 > "$T/out.hex"
python3 -c "import sys;sys.stdout.buffer.write(b''.join(sorted(bytes.fromhex(l) for l in open(sys.argv[1]))))" \
  "$T/in.hex" > "$T/in.bin"

for mk in "20 7" "24 30" "33 160" "21 1"; do
  set -- $mk
  rm -f "$T/f.blf"
  "$D/hex2blf" -m $1 -k $2 "$T/in.hex" "$T/f.blf" 2>/dev/null
  python3 - "$T/in.hex" "$T/f.blf" $1 $2 <<'EOF' && ok "hex2blf -m $1 -k $2 matches reference" || bad "hex2blf -m $1 -k $2"
import struct, sys
hexf, blf, b, k = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
data = open(blf, "rb").read()
assert len(data) == (1 << (b - 3)) + 16, "size"
assert data[-16:] == b"BLFSLICE" + bytes([1, b, k]) + bytes(5), "trailer"
want = bytearray(1 << (b - 3))
for line in open(hexf):
    w = struct.unpack("<5I", bytes.fromhex(line.strip()))     # hash160_t.ul on x86
    x = sum(v << (32 * (4 - i)) for i, v in enumerate(w))      # 160 bits, word 0 first
    x2 = x << 160 | x                                          # wrap around
    for i in range(k):
        o = i * 160 // k
        t = (x2 >> (320 - o - b)) & ((1 << b) - 1)
        want[t >> 3] |= 1 << (t & 7)
assert bytes(want) == data[:-16], "bits"
EOF
  got=$("$D/blfchk" "$T/f.blf" < "$T/in.hex" | wc -l)
  [ "$got" -eq 200 ] && ok "blfchk finds all members" || bad "blfchk found $got/200 members"
  got=$("$D/blfchk" "$T/f.blf" "$T/in.bin" < "$T/out.hex" | wc -l)
  [ "$got" -eq 0 ] && ok "blfchk -f rejects non-members" || bad "blfchk matched $got non-members"
done

# -k chosen from the number of hashes; -m 32 when only -k is given
rm -f "$T/f.blf"; "$D/hex2blf" -m 20 "$T/in.hex" "$T/f.blf" 2>"$T/log"
grep -q "160 slices" "$T/log" && ok "best k for 200 hashes in 2^20 bits" || bad "best k: $(cat "$T/log")"
rm -f "$T/f.blf"; "$D/hex2blf" -m 12 "$T/in.hex" "$T/f.blf" 2>/dev/null && bad "-m 12 accepted" || ok "-m 12 rejected"
rm -f "$T/f.blf"; "$D/hex2blf" -k 0 -m 20 "$T/in.hex" "$T/f.blf" 2>/dev/null && bad "-k 0 accepted" || ok "-k 0 rejected"

# adding to an existing filter keeps its parameters
rm -f "$T/f.blf"
head -100 "$T/in.hex" > "$T/a.hex"; tail -100 "$T/in.hex" > "$T/b.hex"
"$D/hex2blf" -m 22 -k 12 "$T/a.hex" "$T/f.blf" 2>/dev/null
"$D/hex2blf" "$T/b.hex" "$T/f.blf" 2>/dev/null
"$D/hex2blf" -m 22 -k 12 "$T/in.hex" "$T/g.blf" 2>/dev/null
cmp -s "$T/f.blf" "$T/g.blf" && ok "append keeps size and slices" || bad "append"
"$D/hex2blf" -k 13 "$T/b.hex" "$T/f.blf" 2>/dev/null && bad "append with other -k accepted" || ok "append with other -k rejected"

# brainflayer finds keys through a sliced filter
"$D/hex2blf" -m 24 -k 20 "$T/in.hex" "$T/h.blf" 2>/dev/null
got=$("$D/brainflayer" -c c -w 8 -b "$T/h.blf" -f "$T/in.bin" -P splitmix64 -S 1 -L 300 | grep -c splitmix64)
[ "$got" -eq 200 ] && ok "brainflayer finds 200/200 keys" || bad "brainflayer found $got/200 keys"

exit $fail
