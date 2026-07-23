#!/usr/bin/env bash
# coverage_report.sh — verification-coverage display (ROI-TOP-50 item 19).
#
# Directly addresses the "all green" problem: it separates what is MACHINE-VERIFIED in this repo from
# what is only DOCUMENTED / needs a real environment, so a reader never mistakes a claim that rests on
# prose for one a test actually exercises.
#
#   Section A (machine-verified): derived LIVE from build_and_verify.sh — one line per suite step, so
#     it cannot drift out of sync with the suite. (Run `./build_and_verify.sh --strict` to prove they
#     currently pass; this report lists what is covered, the suite proves it is green.)
#   Section B (documented, NOT machine-verified here): a curated list of claims that require a real
#     token / wx GUI-CLI / kernel dm-crypt / real media / multi-snapshot setup, taken from the honest
#     limitations in the docs. These are NOT failures — they are the edge of what a sandbox can prove.
#
# `--check` runs a self-test of the classifier (used as a suite step, with its own negative control):
# it asserts the machine-verified count equals the suite's step count AND that a known documented-only
# claim is NOT sitting in the machine-verified list.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SUITE="$HERE/build_and_verify.sh"

# --- Section A: machine-verified, straight from the suite -------------------------------------------
verified_lines() { grep -E '^echo "\[[0-9]+\]' "$SUITE" | sed -E 's/^echo "//; s/"$//'; }
VERIFIED_COUNT="$(verified_lines | wc -l | tr -d ' ')"

# --- Section B: documented, needs a real environment (curated from the docs' honest limitations) ----
DOCUMENTED_ONLY=(
"Hardware backends (YubiKey HMAC / FIDO2 hmac-secret) against a REAL device — verification/ links the real libs and shows fail-safe with no device; a present-token round-trip needs hardware."
"KeyScrub OS triggers: logind screen-lock and udev device-connect firing a scrub on a real session (docs/MEMORY-SCRUB.md)."
"Kernel-side dm-crypt master-key scrub — the mounted key lives in the kernel device-mapper, out of user-space reach (docs/THREAT-MODEL.md)."
"wx GUI/CLI orchestration: --duress-dismount, --keyslot-* management, per-slot policy CLI, --verbose logging — the C cores are proven; the wx wiring is not sandbox-buildable (no libpcsclite here)."
"Argon2id / duress / keyslot CREATE->MOUNT round-trip on real media (docs/REAL-BUILD-VALIDATION.md)."
"Deniability limits stated, not defeated: multi-snapshot diff, SSD wear-levelling, imaged-first, share-distribution (docs/THREAT-MODEL.md)."
"max-attempts lockout is rollback-defeatable without a TPM/secure-element monotonic counter — DEMONSTRATED in step [53], not claimed robust (docs/KEYSLOT-POLICY-DESIGN.md)."
"Swap/hibernation WARNING firing in a live mounted-volume session — the detector + message are proven (step [6] [J]); the emission path is wx."
)

print_report() {
	echo "==================================================================================="
	echo " VERIFICATION COVERAGE  —  machine-verified vs. documented"
	echo "==================================================================================="
	echo ""
	echo "A. MACHINE-VERIFIED IN THIS REPO ($VERIFIED_COUNT suite steps; run ./build_and_verify.sh --strict to prove green)"
	echo "-----------------------------------------------------------------------------------"
	verified_lines | sed 's/^/  [verified] /'
	echo ""
	echo "B. DOCUMENTED, NOT MACHINE-VERIFIED HERE (${#DOCUMENTED_ONLY[@]} — need real hardware / wx / kernel / media)"
	echo "-----------------------------------------------------------------------------------"
	local d
	for d in "${DOCUMENTED_ONLY[@]}"; do echo "  [docs-only] $d"; done
	echo ""
	echo "SUMMARY: $VERIFIED_COUNT machine-verified suite steps, ${#DOCUMENTED_ONLY[@]} documented-only claims."
	echo "         'Green' means A is proven. B is the honest edge of a sandbox, not a pass."
}

self_check() {
	local rc=0
	# 1. the machine-verified count must equal the suite's actual step count (no hand-maintained drift)
	local steps; steps="$(grep -cE '^echo "\[[0-9]+\]' "$SUITE")"
	if [ "$VERIFIED_COUNT" != "$steps" ]; then
		echo "  FAIL: verified count $VERIFIED_COUNT != suite step count $steps"; rc=1
	else
		echo "  OK: machine-verified list ($VERIFIED_COUNT) is derived live from the suite ($steps steps)"
	fi
	# 2. negative control: a known documented-only claim (hardware tokens) must NOT appear as verified
	if verified_lines | grep -qiE "against a REAL device|dm-crypt master-key"; then
		echo "  FAIL: a documented-only claim leaked into the machine-verified list"; rc=1
	else
		echo "  OK: documented-only claims (real hardware, kernel dm-crypt) are NOT listed as verified"
	fi
	return $rc
}

# Negative control: build a synthetic suite that (wrongly) lists a real-hardware claim as a step, and
# assert the classifier flags it — proving the "documented-only must not appear as verified" check has
# teeth, rather than passing because the real suite happens to be clean.
check_negctl() {
	local tmp; tmp="$(mktemp)"
	{ grep -E '^echo "\[[0-9]+\]' "$SUITE"; echo 'echo "[99] YubiKey HMAC against a REAL device"'; } > "$tmp"
	if grep -E '^echo "\[[0-9]+\]' "$tmp" | sed -E 's/^echo "//; s/"$//' | grep -qiE "against a REAL device"; then
		rm -f "$tmp"; echo "  OK (neg-control): a real-hardware claim injected as a step IS detected as documented-only"; return 0
	fi
	rm -f "$tmp"; echo "  FAIL (neg-control): classifier did not detect the injected hardware claim"; return 1
}

case "${1:-}" in
	--check)         self_check; exit $? ;;
	--check-negctl)  check_negctl; exit $? ;;
	*)               print_report ;;
esac
