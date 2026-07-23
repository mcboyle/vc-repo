#!/usr/bin/env bash
# secrets-scan.sh — pattern-based secret scanner (ROI-TOP-50 item 38).
#
# Mechanically prevents credentials from being committed: private keys, cloud/service tokens, and
# high-confidence credential assignments. Deliberately pattern-based (NOT generic entropy) so it does
# not drown in the repo's many legitimate crypto test vectors / KAT anchors. No external dependency —
# safe to run from a pre-commit hook (.githooks/pre-commit) and from CI.
#
# Usage:
#   secrets-scan.sh [file ...]     scan the given files, or (with none) every git-tracked text file
#   secrets-scan.sh --self-test    positive+negative control: a planted secret is caught, clean text is not
#
# Exit 0 = clean, 1 = a secret was found (matches printed with the value masked), 2 = usage error.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"

# High-confidence secret patterns (extended regex). Prefixes/formats, not entropy.
PATTERNS=(
	'-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'
	'-----BEGIN PGP PRIVATE KEY BLOCK-----'
	'AKIA[0-9A-Z]{16}'                                   # AWS access key id
	'aws_secret_access_key[[:space:]]*=[[:space:]]*[A-Za-z0-9/+]{40}'
	'ghp_[A-Za-z0-9]{36}'                                # GitHub personal access token
	'github_pat_[A-Za-z0-9_]{60,}'
	'xox[baprs]-[A-Za-z0-9-]{10,}'                       # Slack token
	'AIza[0-9A-Za-z_-]{35}'                              # Google API key
	'sk_live_[0-9A-Za-z]{24,}'                           # Stripe live secret key
	'-----BEGIN OPENSSH PRIVATE KEY-----'
)

# Paths never scanned: the scanner itself (contains the patterns) and binary-ish trees.
is_excluded() {
	case "$1" in
		scripts/secrets-scan.sh) return 0;;
		*.png|*.jpg|*.jpeg|*.gif|*.pdf|*.o|*.a|*.bin) return 0;;
		*) return 1;;
	esac
}

scan_files() {
	local rc=0 f p
	for f in "$@"; do
		[ -f "$f" ] || continue
		is_excluded "$f" && continue
		for p in "${PATTERNS[@]}"; do
			if grep -nE "$p" "$f" >/dev/null 2>&1; then
				# print the file:line with the matched value masked
				grep -nE "$p" "$f" | sed -E 's/(.{0,8}).*/\1********  [secret pattern] '"$f"'/' | head -3
				rc=1
			fi
		done
	done
	return $rc
}

self_test() {
	local tmp dirty clean rc=0
	tmp="$(mktemp -d)"; dirty="$tmp/dirty.txt"; clean="$tmp/clean.txt"
	printf 'token = AKIA%s\n' 'ABCDEFGHIJKLMNOP' > "$dirty"      # a well-formed AWS-key-shaped secret
	printf 'this file has crypto KAT vectors like 628882be and a68b717f but no credentials\n' > "$clean"
	if scan_files "$dirty" >/dev/null 2>&1; then echo "  FAIL: planted secret was NOT detected"; rc=1
	else echo "  OK: planted AWS-key-shaped secret is detected (positive control)"; fi
	if scan_files "$clean" >/dev/null 2>&1; then echo "  OK: a file of crypto KAT hex is NOT flagged (negative control — no false positive)"
	else echo "  FAIL: clean crypto-vector file was flagged as a secret"; rc=1; fi
	rm -rf "$tmp"; return $rc
}

case "${1:-}" in
	--self-test) self_test; exit $? ;;
	'' )         cd "$ROOT"; mapfile -t FILES < <(git ls-files 2>/dev/null); scan_files "${FILES[@]}"; exit $? ;;
	* )          scan_files "$@"; exit $? ;;
esac
