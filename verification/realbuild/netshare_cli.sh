#!/bin/bash
# netshare_cli.sh — end-to-end proof of the --ns-* CLI against a real MR server.
#
# Step [102] proves src/Common/NetShare.c in isolation (RFC 8032 anchors + protocol properties) with an
# in-process transport. This is the other half: the ACTUAL veracrypt binary, over a real TCP socket, to
# a server built from the same shipping NetShareServerRespond — create a volume whose key depends on a
# network-recovered share, then open it, and confirm the ways it must FAIL.
#
# What it asserts:
#   1. enrol writes a credential of exactly NETSHARE_CRED_LEN bytes;
#   2. a volume created with the network share OPENS when the server is reachable (positive control);
#   3. OFF-NETWORK (server stopped) the same command fails, and says "could not be reached" rather than
#      "incorrect password" — the distinction this feature exists to preserve;
#   4. a WRONG SERVER (different secret, reachable) does NOT open the volume;
#   5. the credential alone, with no server, does not open it.
#
# Usage: bash verification/realbuild/netshare_cli.sh [make feature args]
# Needs a product built with NETSHARE=1; builds one if absent (VC_NS_SKIP_BUILD=1 to require prebuilt).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/src"
VC="$SRC/Main/veracrypt"
: "${CC:=clang}"

MAKE_ARGS=("$@")
[ "${#MAKE_ARGS[@]}" -eq 0 ] && MAKE_ARGS=(NOGUI=1 HKF=1 NETSHARE=1)

log()  { echo "[netshare-cli] $*"; }
fail() { echo "[netshare-cli] FAIL: $*" >&2; exit 1; }

# --- build the product if needed -------------------------------------------------------------------
if [ ! -x "$VC" ]; then
	[ "${VC_NS_SKIP_BUILD:-0}" = 1 ] && fail "veracrypt not built and VC_NS_SKIP_BUILD=1"
	log "building product: scripts/build-product.sh ${MAKE_ARGS[*]}"
	"$ROOT/scripts/build-product.sh" "${MAKE_ARGS[@]}" >/tmp/ns_cli_build.log 2>&1 \
		|| fail "product build failed (see /tmp/ns_cli_build.log)"
fi

# The binary must actually carry the feature; otherwise --ns-server is an unknown option and every
# assertion below would "fail" for the wrong reason.
if ! "$VC" --help 2>&1 | grep -q -- "--ns-server"; then
	fail "this veracrypt was built without NETSHARE=1 (no --ns-server option) — rebuild with NETSHARE=1"
fi

WORK="$(mktemp -d)"
SRV_PID=""; WRONG_PID=""
cleanup() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null; [ -n "$WRONG_PID" ] && kill "$WRONG_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# --- reference server (speaks the shipping compressed format) ---------------------------------------
log "building the reference MR server"
$CC -O2 -DVC_ENABLE_NETSHARE -I"$SRC" -I"$SRC/Common" -I"$SRC/Crypto" \
	-DCRYPTOPP_DISABLE_ASM -DCRYPTOPP_DISABLE_SSE2 -DCRYPTOPP_DISABLE_SSSE3 \
	"$HERE/../netshare_server.c" "$SRC/Common/NetShare.c" "$SRC/Crypto/Sha2.c" \
	-o "$WORK/nssrv" 2>/tmp/ns_srv.log || fail "server build failed (see /tmp/ns_srv.log)"

PORT=47210; WPORT=47211; DEADPORT=47219
S_HEX="$("$WORK/nssrv" --pubkey)"        || fail "could not derive server public key"
[ ${#S_HEX} = 64 ] || fail "server public key is not 64 hex chars: $S_HEX"
log "server public S (pinned via --ns-server-key): $S_HEX"

"$WORK/nssrv" --serve $PORT  >/dev/null 2>&1 & SRV_PID=$!
"$WORK/nssrv" --serve $WPORT --wrong >/dev/null 2>&1 & WRONG_PID=$!
sleep 1
kill -0 $SRV_PID 2>/dev/null   || fail "reference server did not start"

PW="netshare-cli-pw"
CRED="$WORK/vol.nsc"
VOL="$WORK/vol.hc"
pass=0; failc=0
ok()  { echo "  ok   $1"; pass=$((pass+1)); }
bad() { echo "  FAIL $1"; failc=$((failc+1)); }

# --- 1. enrol ---------------------------------------------------------------------------------------
log "=== enrol ==="
"$VC" --text --create "$VOL" --size=10M --password="$PW" --pim=0 --keyfiles="" \
	--encryption=AES --hash=SHA-512 --filesystem=none --volume-type=normal --random-source=/dev/urandom \
	--ns-enroll --ns-server "127.0.0.1:$PORT" --ns-server-key "$S_HEX" --ns-cred "$CRED" \
	>"$WORK/create.log" 2>&1
crc=$?
if [ $crc = 0 ] && [ -f "$CRED" ]; then ok "enrol + create succeeded"; else bad "enrol + create failed"; sed 's/^/       /' "$WORK/create.log"; fi
credsz=$(stat -c%s "$CRED" 2>/dev/null || echo 0)
[ "$credsz" = 72 ] && ok "credential is 72 bytes (NSC||ver||S||C||cksum)" || bad "credential size is $credsz, expected 72"

# --- classify a mount attempt (acceptance.sh's convention) ------------------------------------------
# VeraCrypt derives the header key and authenticates the header BEFORE it calls dmsetup, so the failure
# POINT is diagnostic in a container with no device-mapper: a device-mapper error means the key was
# CORRECT and only the kernel table load is missing; "Incorrect password" means the derived key was
# wrong. Returns 0 mounted, 2 key-correct-but-no-dm, 3 wrong key, 1 other.
classify () {
	local log="$1"
	grep -qiE "device-mapper|dmsetup|/dev/mapper/control" "$log" && return 2
	grep -qiE "Incorrect password|Incorrect PRF" "$log" && return 3
	return 1
}

try_open () {   # $1=logfile, rest = extra veracrypt args
	local log="$1"; shift
	"$VC" --text --mount "$VOL" "$WORK/mnt" --password="$PW" --pim=0 --keyfiles="" \
		--protect-hidden=no --slot=1 --non-interactive "$@" >"$log" 2>&1
	local rc=$?
	if [ $rc = 0 ]; then "$VC" --text --dismount "$VOL" >/dev/null 2>&1; return 0; fi
	classify "$log"; return $?
}

# --- 2. POSITIVE CONTROL: the key is recoverable WITH the server ------------------------------------
# This runs first on purpose. If it fails, every negative below rejects for free and proves nothing.
log "=== unlock (positive control) ==="
mkdir -p "$WORK/mnt"
try_open "$WORK/open.log" --ns-server "127.0.0.1:$PORT" --ns-cred "$CRED"
oc=$?
POSITIVE_OK=0
case $oc in
	0) ok "POSITIVE CONTROL: volume mounts with the server reachable"; POSITIVE_OK=1;;
	2) ok "POSITIVE CONTROL: key recovered + header authenticated (stopped at dm-crypt; no kernel dm here)"; POSITIVE_OK=1;;
	3) bad "server reachable but the derived key was WRONG";;
	*) bad "server reachable but the open failed for an unrecognised reason"; sed 's/^/       /' "$WORK/open.log";;
esac

if [ "$POSITIVE_OK" != 1 ]; then
	echo ""
	log "positive control FAILED — refusing to run the negative probes."
	log "With no working open, every negative 'passes' for free and proves nothing."
	exit 1
fi

# --- 3. off-network must be a DIFFERENT failure than a wrong key ------------------------------------
log "=== off-network ==="
try_open "$WORK/dead.log" --ns-server "127.0.0.1:$DEADPORT" --ns-cred "$CRED"
[ $? != 0 ] && ok "off-network does not open the volume" || bad "off-network unexpectedly opened it"
if grep -qi "could not be reached" "$WORK/dead.log"; then
	ok "off-network says 'could not be reached', NOT 'incorrect password'"
else
	bad "off-network message does not distinguish transport from a bad key"; sed 's/^/       /' "$WORK/dead.log"
fi
if grep -qi "incorrect password" "$WORK/dead.log"; then
	bad "off-network was reported as an incorrect password — the exact conflation this must avoid"
else
	ok "off-network is not reported as an incorrect password"
fi

# --- 4. wrong server: reachable, answers, but with a different secret -------------------------------
log "=== wrong server ==="
try_open "$WORK/wrong.log" --ns-server "127.0.0.1:$WPORT" --ns-cred "$CRED"
wc_=$?
case $wc_ in
	0|2) bad "WRONG SERVER recovered a working key — the share is not actually server-bound";;
	3)   ok "wrong server yields a wrong key (rejected as an incorrect password, correctly)";;
	*)   ok "wrong server does not open the volume";;
esac

# --- 5. no network factor at all --------------------------------------------------------------------
log "=== password alone (no --ns-*) ==="
try_open "$WORK/nofactor.log"
nc_=$?
case $nc_ in
	0|2) bad "volume opened WITHOUT the network share — the factor is not gating the key";;
	3)   ok "password alone is rejected (the network share genuinely gates the key)";;
	*)   ok "password alone does not open it";;
esac

echo ""
log "result: $pass passed, $failc failed"
[ "$failc" = 0 ] || exit 1
log "PASS — the --ns-* CLI enrols and unlocks against a real server, and fails correctly without one"
