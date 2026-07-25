#!/usr/bin/env bash
# keyslot_timing.sh — guarded PRE/POST wall-clock comparison for the parallel keyslot auto-search.
#
# WHY THE GUARD: timing a binary while that same path is being rebuilt yields ~0.01s crash samples that
# are indistinguishable from a real speedup — this actually happened in the session that wrote this change
# (a background serial run against $REPO/src/Main/veracrypt while the product was being rebuilt gave a
# bimodal 0.01-85s spread and a meaningless 43.63s mean). So: sha256 BOTH binaries before AND after; if
# either changed mid-run, ABORT with both hashes instead of emitting numbers. Record exit status + stderr
# per sample, not just seconds, so a 0.01s success and a 0.01s crash can never be conflated again. This is
# the .build-flags stamp idea with a clock attached (docs/CANT-CLAIMS-AUDIT.md "A claim of mine that expired").
#
# Non-destructive: a file container inside a mktemp dir; nothing writes to a real block device.
#
# Usage: keyslot_timing.sh <pre-binary> <post-binary> <mode> [N=5] [lastslot=62]
#   mode=autosearch : wrong-password MOUNT -> keyslot auto-search (KeyslotOpenParallel; the speedup claim). needs root.
#   mode=serialopen : --keyslot-open with the CORRECT native --password (so Core->OpenVolume accepts the
#                     native header FAST and does NOT trigger its own auto-search) + a WRONG --new-password,
#                     so the only heavy work is the handler's direct serial KeyslotOpen scan (pf==NULL) —
#                     the "unchanged" claim. NB: using a wrong --password here would ALSO run OpenVolume's
#                     auto-search (parallel in POST), confounding the serial measurement with the speedup.
set -u
PRE="${1:?pre-binary}"; POST="${2:?post-binary}"; MODE="${3:?mode}"; N="${4:-5}"; LAST="${5:-62}"
[ -x "$PRE" ] && [ -x "$POST" ] || { echo "ABORT: missing binary (pre=$PRE post=$POST)"; exit 2; }
h(){ sha256sum "$1" | cut -d' ' -f1; }
PRE_H0=$(h "$PRE"); POST_H0=$(h "$POST")
now(){ date +%s.%N; }
SUDO=""; [ "$MODE" = autosearch ] && SUDO="sudo"
W=$(mktemp -d); VOL="$W/t.hc"; MNT="$W/m"; mkdir -p "$MNT"
trap '$SUDO "'"$POST"'" --text --dismount "'"$VOL"'" >/dev/null 2>&1; $SUDO dmsetup ls 2>/dev/null | grep -qi veracrypt && $SUDO dmsetup remove_all 2>/dev/null; rm -rf "'"$W"'"' EXIT
"$POST" --text --create "$VOL" --size=10M --password="np" --pim=0 --keyfiles="" \
  --encryption=AES --hash=SHA-512 --filesystem=fat --volume-type=normal --random-source=/dev/urandom >/dev/null 2>&1
for k in $(seq 0 "$LAST"); do "$POST" --text --keyslot-add "$VOL" --password="np" --new-password="kspass-$k" --pim=0 --keyfiles="" >/dev/null 2>&1; done
echo "mode=$MODE slots=$((LAST+1)) N=$N"
echo "PRE  = $PRE  ($PRE_H0)"
echo "POST = $POST ($POST_H0)"

run_one(){ local b="$1" err="$W/e"; local t0 t1 rc
  if [ "$MODE" = autosearch ]; then
    t0=$(now); $SUDO "$b" --text --mount "$VOL" "$MNT" --password="wrong-probe" --pim=0 --keyfiles="" \
      --protect-hidden=no --non-interactive --slot=40 --hash=SHA-512 >/dev/null 2>"$err"; rc=$?; t1=$(now)
    $SUDO "$b" --text --dismount "$VOL" >/dev/null 2>&1
  else
    t0=$(now); "$b" --text --keyslot-open "$VOL" --password="np" --new-password="wrong-probe" --pim=0 --keyfiles="" >/dev/null 2>"$err"; rc=$?; t1=$(now)
  fi
  printf '%s %s %s' "$(echo "$t1-$t0"|bc)" "$rc" "$(tr '\n' ' ' <"$err" | head -c 70)"
}

PRES=""; POSTS=""
for r in $(seq 1 "$N"); do
  o=$(run_one "$PRE");  echo "  rep$r PRE  : $o"; PRES="$PRES ${o%% *}"
  o=$(run_one "$POST"); echo "  rep$r POST : $o"; POSTS="$POSTS ${o%% *}"
done

PRE_H1=$(h "$PRE"); POST_H1=$(h "$POST")
if [ "$PRE_H0" != "$PRE_H1" ] || [ "$POST_H0" != "$POST_H1" ]; then
  echo "ABORT: a binary CHANGED during the run (concurrent build?) — numbers DISCARDED."
  echo "  PRE  $PRE_H0 -> $PRE_H1"
  echo "  POST $POST_H0 -> $POST_H1"
  exit 3
fi
stats(){ echo "$1"|tr ' ' '\n'|grep -E '^[0-9]'|awk '{n++;s+=$1;if(mn==""||$1<mn)mn=$1;if($1>mx)mx=$1}END{printf "mean=%.3fs min=%.3fs max=%.3fs spread=%.3fs (n=%d)",s/n,mn,mx,mx-mn,n}'; }
echo "RESULT PRE  : $(stats "$PRES")"
echo "RESULT POST : $(stats "$POSTS")"
echo "TIMINGDONE"
