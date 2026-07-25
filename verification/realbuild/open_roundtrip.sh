#!/bin/bash
# open_roundtrip.sh — build + run the in-process Volume::Open round-trip harness against the real product.
#
# WHAT
#   Compiles verification/realbuild/open_roundtrip.cpp against the built Core.a/Volume.a/Platform.a and
#   drives a matrix of assertions through the REAL C++ mount path (Volume::Open) with NO kernel dm-crypt:
#     * plain volume  : correct password opens + recovers a non-trivial master key; wrong password rejects.
#     * factored volume (HKF_SIMULATOR builds): correct password+factor opens; wrong factor rejects;
#       password alone rejects (the 2FA property) — exercised through a salt-bound (T2-1) derivation.
#   Volumes are created with the proven CLI; the harness only opens. This flips the C++ create->open
#   round-trip (salt-binding / keyslots / duress / Argon2-params all ride the same path) from
#   "real-build-only" to sandbox-verified. Kernel mounting is still out of scope (containers lack dm).
#
# USAGE
#   ./verification/realbuild/open_roundtrip.sh [make feature args]
#   Defaults to the CI full-featured set. Pass the SAME make args used to build the product so the harness
#   is compiled with the matching -D flag set. If the archives are missing it builds them first via
#   scripts/build-product.sh; set VC_OR_SKIP_BUILD=1 to require pre-built archives (CI already built them).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/src"
: "${CXX:=clang++}"

MAKE_ARGS=("$@")
if [ "${#MAKE_ARGS[@]}" -eq 0 ]; then
	MAKE_ARGS=(NOGUI=1 HKF=1 HKF_SIMULATOR=1 KEYSCRUB=1 DURESS=1 KEYSLOTS=1 SHARECODE=1 SHAMIRMAC=1 FLASH_WARN=1 ARGON2PARAMS=1)
fi

log()  { echo "[open-roundtrip] $*"; }
fail() { echo "[open-roundtrip] FAIL: $*" >&2; exit 1; }

VC="$SRC/Main/veracrypt"
ARCHIVES=("$SRC/Core/Core.a" "$SRC/Volume/Volume.a" "$SRC/Platform/Platform.a")

# --- 1. ensure the product is built (archives + binary) --------------------------------------------
need_build=0
[ -x "$VC" ] || need_build=1
for a in "${ARCHIVES[@]}"; do [ -f "$a" ] || need_build=1; done
if [ "$need_build" = 1 ]; then
	if [ "${VC_OR_SKIP_BUILD:-0}" = 1 ]; then
		fail "product archives/binary missing and VC_OR_SKIP_BUILD=1 (run scripts/build-product.sh ${MAKE_ARGS[*]} first)"
	fi
	log "product not built — building: scripts/build-product.sh ${MAKE_ARGS[*]}"
	"$ROOT/scripts/build-product.sh" "${MAKE_ARGS[@]}" || fail "product build failed"
fi

# --- 2. derive the exact -D feature flags the archives were built with ------------------------------
# (make -pn is a dry run: it prints the resolved variables without compiling anything.)
DEFS="$(make -C "$SRC" -pn "${MAKE_ARGS[@]}" 2>/dev/null \
	| grep -E '^C_CXX_FLAGS :?= ' | tail -1 \
	| grep -oE '\-D(VC_ENABLE|TC)_[A-Z_0-9]*' | sort -u | tr '\n' ' ')"
[ -n "$DEFS" ] || log "note: no VC_ENABLE/TC defs resolved (stock build?) — harness will build without factor support"
log "feature defs: $DEFS"

# The archives must have been built from the SAME flag set, or this harness links a mixed binary: it
# compiles with one feature set while Core.a/Volume.a carry another. That mismatch does not announce
# itself as a build error — it shows up as a *behavioural* failure (a volume that will not open), which
# reads exactly like a crypto bug. It cost a session's worth of misdiagnosis on the Argon2 round-trip.
# scripts/build-product.sh writes src/.build-flags; compare and refuse to proceed on a mismatch.
STAMP="$SRC/.build-flags"
if [ -f "$STAMP" ]; then
	STAMPED="$(cat "$STAMP")"
	if [ "$(echo "$STAMPED" | tr -s ' ')" != "$(echo "$DEFS" | tr -s ' ')" ]; then
		log "archive flag stamp: $STAMPED"
		log "harness flag set  : $DEFS"
		if [ "${VC_OR_SKIP_BUILD:-0}" = 1 ]; then
			fail "archives were built with a DIFFERENT feature set than requested (see above). Rebuild: scripts/build-product.sh ${MAKE_ARGS[*]}"
		fi
		log "flag-set mismatch — rebuilding the product to match"
		"$ROOT/scripts/build-product.sh" "${MAKE_ARGS[@]}" || fail "product rebuild failed"
	fi
else
	log "note: no $STAMP (archives predate flag stamping) — cannot verify the archives match these defs"
fi

case " $DEFS " in *" -DVC_ENABLE_HKF_SIMULATOR "*) HAVE_SIM=1;; *) HAVE_SIM=0;; esac
case " $DEFS " in *" -DVC_ENABLE_ARGON2_PARAMS "*) HAVE_A2P=1;; *) HAVE_A2P=0;; esac

# --- 3. compile + link the harness against the real archives ----------------------------------------
INC="-I$SRC -I$SRC/Crypto -I$SRC/Crypto/Argon2/include -I$SRC/PKCS11"
BASE="-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES -DARGON2_NO_THREADS -DTC_ARCH_X64"
BIN="$(mktemp -d)/open_roundtrip"
log "compiling harness ($CXX)"
$CXX -O2 -std=c++17 -Wall $BASE $DEFS $INC -c "$HERE/open_roundtrip.cpp" -o "$BIN.o" || fail "harness compile failed"
$CXX -o "$BIN" "$BIN.o" \
	-Wl,--start-group "${ARCHIVES[@]}" -Wl,--end-group \
	$(pkg-config fuse --libs 2>/dev/null || pkg-config fuse3 --libs 2>/dev/null) \
	$(wx-config --libs base 2>/dev/null) -lpthread || fail "harness link failed"
log "harness built: $BIN"

# --- 4. run the assertion matrix --------------------------------------------------------------------
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK" "$(dirname "$BIN")"' EXIT
export VC_OPEN_KDF="HMAC-SHA-512"        # volumes below are created with --hash=SHA-512; pin => fast rejects
PW="open-roundtrip-pw-2FA"
SEC="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
BAD="ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

mkvol() { # $1=path  $2..=extra create flags
	local v="$1"; shift
	"$VC" --text --create "$v" --size=10M --password="$PW" --pim=0 --keyfiles="" \
		--encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal \
		--random-source=/dev/urandom "$@" >"$WORK/create.log" 2>&1
}

pass=0; failc=0
check() { # $1=label  $2=expected-exit  $3..=harness args
	local label="$1" want="$2"; shift 2
	timeout 120 "$BIN" "$@" >/"$WORK/h.out" 2>&1; local rc=$?
	if [ "$rc" = "$want" ]; then echo "  ok   $label"; pass=$((pass+1));
	else echo "  FAIL $label (exit $rc, wanted $want)"; sed 's/^/       /' "$WORK/h.out"; failc=$((failc+1)); fi
}

log "=== plain volume (no factor) ==="
mkvol "$WORK/plain.hc" || fail "plain create failed ($(tail -1 "$WORK/create.log"))"
check "plain: correct password opens + master non-trivial" 0 must_open   "$WORK/plain.hc" "$PW"
check "plain: wrong password rejected"                      0 must_reject "$WORK/plain.hc" "wrong-$PW"

if [ "$HAVE_SIM" = 1 ]; then
	log "=== factored volume (simulator, salt-bound derivation) ==="
	mkvol "$WORK/factored.hc" --hkf-backend=simulator --hkf-sim-secret="$SEC" \
		|| fail "factored create failed ($(tail -1 "$WORK/create.log"))"
	check "factor: correct password + correct factor opens" 0 must_open   "$WORK/factored.hc" "$PW" "$SEC" 1
	check "factor: correct password + WRONG factor rejected" 0 must_reject "$WORK/factored.hc" "$PW" "$BAD" 1
	check "factor: password ALONE rejected (2FA property)"    0 must_reject "$WORK/factored.hc" "$PW"
else
	log "=== factor probes skipped (built without HKF_SIMULATOR) ==="
fi

if [ "$HAVE_A2P" = 1 ]; then
	# Explicit Argon2id parameters are NOT stored in the header — like PIM, the same values must be
	# supplied at mount as at create. So the create->mount round-trip is the only thing that proves the
	# parameters genuinely shape the volume key rather than being silently ignored. The positive control
	# comes first on purpose: if it fails, every negative below rejects for free and proves nothing.
	log "=== explicit Argon2id params (create with -> open with) ==="
	A2MEM=16; A2IT=3; A2PAR=4                # CLI takes MiB; the library override takes KiB
	A2KIB=$((A2MEM * 1024))
	mkvol_a2() {
		"$VC" --text --create "$1" --size=10M --password="$PW" --pim=0 --keyfiles="" \
			--encryption=AES --hash=Argon2id --filesystem=none --volume-type=normal \
			--random-source=/dev/urandom \
			--argon2-memory "$A2MEM" --argon2-iterations "$A2IT" --argon2-parallelism "$A2PAR" \
			>"$WORK/create.log" 2>&1
	}
	mkvol_a2 "$WORK/argon2.hc" || fail "argon2 create failed ($(tail -1 "$WORK/create.log"))"

	a2check() { # $1=label $2=mode $3=VC_OPEN_ARGON2 value ("" => no override) $4=password
		local label="$1" mode="$2" a2="$3" pw="${4:-$PW}"
		if [ -z "$a2" ]; then unset VC_OPEN_ARGON2; else export VC_OPEN_ARGON2="$a2"; fi
		export VC_OPEN_KDF="Argon2id"
		check "$label" 0 "$mode" "$WORK/argon2.hc" "$pw"
		export VC_OPEN_KDF="HMAC-SHA-512"
	}
	a2check "argon2: SAME params open (positive control)"  must_open   "$A2KIB,$A2IT,$A2PAR"
	a2check "argon2: wrong memory rejected"                must_reject "$((A2KIB * 2)),$A2IT,$A2PAR"
	a2check "argon2: wrong iterations rejected"            must_reject "$A2KIB,$((A2IT + 1)),$A2PAR"
	a2check "argon2: wrong parallelism rejected"           must_reject "$A2KIB,$A2IT,1"
	a2check "argon2: no override (PIM default) rejected"   must_reject ""
	a2check "argon2: right params + wrong password"        must_reject "$A2KIB,$A2IT,$A2PAR" "wrong-$PW"
	unset VC_OPEN_ARGON2
else
	log "=== Argon2-param probes skipped (built without ARGON2PARAMS) ==="
fi

echo ""
log "result: $pass passed, $failc failed"
[ "$failc" = 0 ] || exit 1
log "PASS — in-process Volume::Open round-trip verified against the real product"
