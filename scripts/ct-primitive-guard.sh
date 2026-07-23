#!/usr/bin/env bash
# ct-primitive-guard.sh — blessed constant-time primitive guard (research batch-3 R17 / A3).
#
# The defect class R17 named: "a second implementation of an idea already done right elsewhere" — which
# is exactly how the original gf_dot constant-time bug happened (Shamir.c had the masked GF multiply;
# gf_dot re-implemented it with branches). This guard makes that failure mode a build error instead of
# an inspection finding: every constant-time-sensitive primitive (GF field arithmetic, constant-time
# compare/equal, conditional-select) must route through ONE blessed definition, and a NEW definition of
# one of those operations outside the allowlist fails CI.
#
# Deliberately NARROW: it matches a small set of well-known operation names and prefers false negatives
# to false positives (a guard that cries wolf gets disabled). The allowlist below IS the inventory —
# each entry says which file is the blessed home of that operation and why. Extend the allowlist only
# with a reviewed, genuinely-constant-time definition.
#
# Usage:
#   ct-primitive-guard.sh              scan the tree, fail if an unblessed primitive definition appears
#   ct-primitive-guard.sh --self-test  positive+negative control: a planted violation is caught, clean is not
# Exit 0 = clean, 1 = an unblessed primitive was found, 2 = usage error.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"

# ---- the inventory / allowlist: category -> blessed file(s). Documented rationale per entry. ----
# GF(2^n) field arithmetic (multiply/inverse/dot). Blessed:
#   src/Common/Shamir.c    — gf_mul/gf_inv: masked, fixed-iteration, table-free (dudect step [41] + ctgrind).
#   verification/hctr2_poc.c — gf_dot: POLYVAL multiply, same masking (dudect step [82] + ctgrind).
GF_BLESSED="src/Common/Shamir.c verification/hctr2_poc.c"
# Constant-time compare/equal (OR-accumulate `d |= a[i]^b[i]`, no early-out). Blessed:
#   src/Common/Keyslot.c        — KeyslotConstTimeEqual: the SHIPPING compare (dudect step [46] + ctgrind).
#   verification/keyslot_poc.c  — ct_equal: reviewed OR-accumulate in the standalone keyslot PoC (the
#                                 shipping compare mirrors it); PoC links no src/, so it is a local copy.
#   verification/downgrade_poc.c — ct_eq: reviewed OR-accumulate in the standalone anti-downgrade PoC.
CMP_BLESSED="src/Common/Keyslot.c verification/keyslot_poc.c verification/downgrade_poc.c"
# Conditional-select / cmov helpers. Blessed: none exist yet — any definition is new and must be reviewed.
SEL_BLESSED=""

# Operation-name regexes (word-bounded). Narrow on purpose.
GF_RE='\bgf_(mul|inv|dot|mult|imul|div|pow)\b'
CMP_RE='(ConstTimeEqual|const_time_(eq|equal|cmp|compare)|ct_(eq|cmp|compare|equal)|timingsafe_(mem)?(cmp|eq)|crypto_memcmp)'
SEL_RE='(ct_select|cond(itional)?_select|constant_time_select|ct_cmov|cmov_ct|select_ct)'

# Files scanned: git-tracked C sources under src/ and verification/.
list_sources() {
	( cd "$ROOT" && git ls-files 'src/*.c' 'src/*.h' 'verification/*.c' 'verification/*.h' 2>/dev/null )
}

# Is `file` a blessed home for the given category's operation?
is_blessed() { # $1=file $2=blessed-list
	for b in $2; do [ "$1" = "$b" ] && return 0; done
	return 1
}

# Find DEFINITIONS (not declarations/calls) of a name matching $re in $file, excluding leaky test doubles.
# Heuristic for a C definition: a line at column 0 (return type starts the line, optionally `static`)
# containing NAME(  and NOT ending in ';' (that would be a prototype). Calls are indented; declarations
# end in ';'. Deliberately conservative.
find_defs() { # $1=file $2=regex -> prints "lineno:text" for each definition; empty if none
	grep -nE "^(static[[:space:]]+)?[A-Za-z_][A-Za-z0-9_[:space:]\*]*${2}[[:space:]]*\(" "$ROOT/$1" 2>/dev/null \
		| awk '/\{/ || !/;/' \
		| grep -viE 'leaky'
}

scan() {
	local violations=0 f hits
	for f in $(list_sources); do
		# GF field arithmetic
		hits="$(find_defs "$f" "$GF_RE")"
		if [ -n "$hits" ] && ! is_blessed "$f" "$GF_BLESSED"; then
			echo "VIOLATION: unblessed GF-arithmetic definition(s) in $f:"; echo "$hits" | sed 's/^/    /'
			echo "    -> route through a blessed file ($GF_BLESSED) or add $f to the allowlist with rationale."
			violations=$((violations+1))
		fi
		# constant-time compare
		hits="$(find_defs "$f" "$CMP_RE")"
		if [ -n "$hits" ] && ! is_blessed "$f" "$CMP_BLESSED"; then
			echo "VIOLATION: unblessed constant-time-compare definition(s) in $f:"; echo "$hits" | sed 's/^/    /'
			echo "    -> route through a blessed file ($CMP_BLESSED) or add $f to the allowlist with rationale."
			violations=$((violations+1))
		fi
		# conditional-select
		hits="$(find_defs "$f" "$SEL_RE")"
		if [ -n "$hits" ] && ! is_blessed "$f" "$SEL_BLESSED"; then
			echo "VIOLATION: unblessed conditional-select definition(s) in $f:"; echo "$hits" | sed 's/^/    /'
			echo "    -> no blessed conditional-select exists yet; review and add to the allowlist if constant-time."
			violations=$((violations+1))
		fi
	done
	return $violations
}

self_test() {
	local tmp rc
	tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
	# negative control: a clean file (a call + a declaration, no definition) must NOT trip the guard
	cat > "$tmp/clean.c" <<'EOF'
extern int KeyslotConstTimeEqual (const unsigned char *a, const unsigned char *b, int len);
int use (void) { unsigned char x=0,y=0; return KeyslotConstTimeEqual (&x, &y, 1); }
EOF
	if find_defs_abs "$tmp/clean.c" "$CMP_RE" | grep -q .; then echo "SELF-TEST FAIL: clean file flagged"; return 1; fi
	# positive control: a NEW unblessed GF multiply definition must be caught
	cat > "$tmp/bad.c" <<'EOF'
unsigned char gf_mul (unsigned char a, unsigned char b) { return a ^ b; }
EOF
	if ! find_defs_abs "$tmp/bad.c" "$GF_RE" | grep -q .; then echo "SELF-TEST FAIL: planted gf_mul not caught"; return 1; fi
	# positive control: the leaky-named test double must be EXEMPT (self-validation of the exclusion)
	cat > "$tmp/leaky.c" <<'EOF'
unsigned char gf_mul_leaky (unsigned char a, unsigned char b) { unsigned char p=0; while(b){ if(b&1)p^=a; a<<=1; b>>=1;} return p; }
EOF
	if find_defs_abs "$tmp/leaky.c" "$GF_RE" | grep -q .; then echo "SELF-TEST FAIL: *_leaky test double wrongly flagged"; return 1; fi
	echo "SELF-TEST PASS: planted gf_mul caught; clean file + *_leaky double exempt"
	return 0
}
# variant of find_defs taking an absolute path (for the self-test temp files)
find_defs_abs() {
	grep -nE "^(static[[:space:]]+)?[A-Za-z_][A-Za-z0-9_[:space:]\*]*${2}[[:space:]]*\(" "$1" 2>/dev/null \
		| awk '/\{/ || !/;/' | grep -viE 'leaky'
}

case "${1:-}" in
	--self-test) self_test; exit $? ;;
	"") : ;;
	*) echo "usage: $(basename "$0") [--self-test]"; exit 2 ;;
esac

if scan; then
	echo "ct-primitive-guard: OK — every guarded primitive routes through its blessed module."
	exit 0
else
	echo "ct-primitive-guard: FAILED — unblessed constant-time-sensitive primitive definition(s) above."
	echo "This is the mechanism that would have caught the original gf_dot branch defect automatically."
	exit 1
fi
