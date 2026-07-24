#!/usr/bin/env bash
# ct-primitive-guard.sh — blessed constant-time primitive guard (research batch-3 R17 / A3).
#
# The defect class R17 named: "a second implementation of an idea already done right elsewhere" — how the
# original gf_dot constant-time bug happened (Shamir.c had the masked GF multiply; gf_dot re-implemented
# it with branches). This guard makes that failure mode a build error: every constant-time-sensitive
# primitive (GF field arithmetic, constant-time compare/equal, conditional-select) must route through ONE
# blessed definition, and a NEW definition of one of those operations outside the allowlist fails CI.
#
# SCOPE — read this. This is a *location* guard: it checks WHERE a primitive is defined, not WHETHER the
# implementation is constant-time. Once a file is on the allowlist it is exempt, so a regression *inside*
# an already-blessed file (e.g. re-introducing a branch into gf_dot) is NOT caught here — that is
# ctgrind/dudect's job (docs/CT-HARDENING-R17.md). What this guard genuinely does is force a review of any
# second implementation *at the moment the file is introduced*, before it can be allowlisted.
#
# Deliberately NARROW: matches a small set of well-known operation names and prefers false negatives to
# false positives (a guard that cries wolf gets disabled). The allowlist below IS the inventory — each
# entry names the blessed home of that operation and why. Extend it only with a reviewed definition.
#
# Usage:
#   ct-primitive-guard.sh              scan the tree, fail if an unblessed primitive definition appears
#   ct-primitive-guard.sh --self-test  positive+negative controls incl. the real scan() path
# Exit 0 = clean, 1 = an unblessed primitive was found, 2 = usage error.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"

# ---- the inventory / allowlist: category -> blessed file(s) (repo-relative). Rationale per entry. ----
# GF(2^n) field arithmetic (multiply/inverse/dot). Blessed:
#   src/Common/Shamir.c      — gf_mul/gf_inv: masked, fixed-iteration, table-free (dudect step [41] + ctgrind).
#   verification/hctr2_poc.c — gf_dot: POLYVAL multiply, same masking (dudect step [82] + ctgrind).
GF_BLESSED="src/Common/Shamir.c verification/hctr2_poc.c"
# Constant-time compare/equal (OR-accumulate `d |= a[i]^b[i]`, no early-out). Blessed:
#   src/Common/Keyslot.c         — KeyslotConstTimeEqual: the SHIPPING compare (dudect step [46] + ctgrind).
#   verification/keyslot_poc.c   — ct_equal: reviewed OR-accumulate in the standalone keyslot PoC.
#   verification/downgrade_poc.c — ct_eq: reviewed OR-accumulate in the standalone anti-downgrade PoC.
#   verification/v2format_poc.c  — ct_eq: reviewed OR-accumulate (d |= a^b, no early-out) for the v2
#                                  per-sector-MAC / mode-discrimination tag compare (suite step [84]).
CMP_BLESSED="src/Common/Keyslot.c verification/keyslot_poc.c verification/downgrade_poc.c verification/v2format_poc.c"
# Conditional-select / cmov helpers. Blessed: none exist yet — any definition is new and must be reviewed.
SEL_BLESSED=""

# Operation-name regexes (word-bounded). Narrow on purpose.
GF_RE='\bgf_(mul|inv|dot|mult|imul|div|pow)\b'
CMP_RE='(ConstTimeEqual|const_time_(eq|equal|cmp|compare)|ct_(eq|cmp|compare|equal)|timingsafe_(mem)?(cmp|eq)|crypto_memcmp)'
SEL_RE='(ct_select|cond(itional)?_select|constant_time_select|ct_cmov|cmov_ct|select_ct)'

# Git-tracked C sources under src/ and verification/, emitted as absolute paths.
list_sources() {
	( cd "$ROOT" && git ls-files 'src/*.c' 'src/*.h' 'verification/*.c' 'verification/*.h' 2>/dev/null \
		| sed "s|^|$ROOT/|" )
}

# rel path of an absolute path within the repo (for allowlist comparison)
relpath() { printf '%s\n' "${1#"$ROOT"/}"; }

# Is `relfile` a blessed home for this category?
is_blessed() { # $1=relfile $2=blessed-list
	for b in $2; do [ "$1" = "$b" ] && return 0; done
	return 1
}

# Find DEFINITIONS (not declarations/calls) of a guarded name in an ABSOLUTE-path file.
# Heuristic for a C definition: a line at column 0 (return type, optionally `static`) containing NAME( ,
# and — to exclude prototypes — the line has an opening brace OR no semicolon (a declaration ends in ';'
# with no brace). The leaky exclusion is scoped to the IDENTIFIER (an identifier containing "leaky"
# immediately before the '('), so "leaky" in a trailing comment no longer exempts a real definition.
find_defs() { # $1=absfile $2=regex -> "lineno:text" per definition; empty if none
	grep -nE "^(static[[:space:]]+)?[A-Za-z_][A-Za-z0-9_[:space:]\*]*${2}[[:space:]]*\(" "$1" 2>/dev/null \
		| awk '/\{/ || !/;/' \
		| grep -vE '[A-Za-z0-9_]*leaky[A-Za-z0-9_]*[[:space:]]*\('
}

# scan [absfile...]  — scans the given files, or list_sources by default. Prints violations.
# Returns 0 (clean) / 1 (>=1 violation) as a BOOLEAN, so a large violation count cannot wrap to 0.
scan() {
	local violations=0 f rel hits files
	if [ "$#" -gt 0 ]; then files="$*"; else files="$(list_sources)"; fi
	for f in $files; do
		rel="$(relpath "$f")"
		hits="$(find_defs "$f" "$GF_RE")"
		if [ -n "$hits" ] && ! is_blessed "$rel" "$GF_BLESSED"; then
			echo "VIOLATION: unblessed GF-arithmetic definition(s) in $rel:"; echo "$hits" | sed 's/^/    /'
			echo "    -> route through a blessed file ($GF_BLESSED) or add $rel to the allowlist with rationale."
			violations=$((violations+1))
		fi
		hits="$(find_defs "$f" "$CMP_RE")"
		if [ -n "$hits" ] && ! is_blessed "$rel" "$CMP_BLESSED"; then
			echo "VIOLATION: unblessed constant-time-compare definition(s) in $rel:"; echo "$hits" | sed 's/^/    /'
			echo "    -> route through a blessed file ($CMP_BLESSED) or add $rel to the allowlist with rationale."
			violations=$((violations+1))
		fi
		hits="$(find_defs "$f" "$SEL_RE")"
		if [ -n "$hits" ] && ! is_blessed "$rel" "$SEL_BLESSED"; then
			echo "VIOLATION: unblessed conditional-select definition(s) in $rel:"; echo "$hits" | sed 's/^/    /'
			echo "    -> no blessed conditional-select exists yet; review and add to the allowlist if constant-time."
			violations=$((violations+1))
		fi
	done
	[ "$violations" -eq 0 ]
}

self_test() {
	local tmp ok=1
	tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN

	# (a) heuristic negative control: a call + a declaration (no definition) trips nothing
	printf 'extern int KeyslotConstTimeEqual (const unsigned char *a, const unsigned char *b, int len);\nint use (void){unsigned char x=0,y=0;return KeyslotConstTimeEqual(&x,&y,1);}\n' > "$tmp/clean.c"
	if find_defs "$tmp/clean.c" "$CMP_RE" | grep -q .; then echo "SELF-TEST FAIL: clean file flagged"; ok=0; fi

	# (b) heuristic positive control: a NEW gf_mul definition is a definition
	printf 'unsigned char gf_mul (unsigned char a, unsigned char b){return a^b;}\n' > "$tmp/bad.c"
	if ! find_defs "$tmp/bad.c" "$GF_RE" | grep -q .; then echo "SELF-TEST FAIL: planted gf_mul not caught"; ok=0; fi

	# (c) leaky exclusion is scoped to the identifier: a *_leaky double is exempt...
	printf 'unsigned char gf_mul_leaky (unsigned char a, unsigned char b){unsigned char p=0;while(b){if(b&1)p^=a;a<<=1;b>>=1;}return p;}\n' > "$tmp/leaky.c"
	if find_defs "$tmp/leaky.c" "$GF_RE" | grep -q .; then echo "SELF-TEST FAIL: *_leaky double wrongly flagged"; ok=0; fi
	# ...but "leaky" in a COMMENT must NOT exempt a real definition (the item-2 bypass)
	printf 'unsigned char gf_mul (unsigned char a, unsigned char b){ /* not leaky at all */ return a^b; }\n' > "$tmp/comment.c"
	if ! find_defs "$tmp/comment.c" "$GF_RE" | grep -q .; then echo "SELF-TEST FAIL: 'leaky' in a comment exempted a real gf_mul"; ok=0; fi

	# (d) the REAL scan() path (not just the heuristic): an unblessed planted file must make scan() FAIL,
	# and a blessed-named-but-relocated one still fails (location guard). Uses absolute paths outside ROOT
	# so relpath() leaves them non-blessed.
	printf 'unsigned char gf_mul (unsigned char a, unsigned char b){return a^b;}\n' > "$tmp/unblessed.c"
	if scan "$tmp/unblessed.c" >/dev/null 2>&1; then echo "SELF-TEST FAIL: scan() passed an unblessed gf_mul definition"; ok=0; fi
	# scan() clean control: an allowlisted real file scanned alone must pass
	if ! scan "$ROOT/src/Common/Shamir.c" >/dev/null 2>&1; then echo "SELF-TEST FAIL: scan() flagged the blessed Shamir.c"; ok=0; fi

	if [ "$ok" = 1 ]; then
		echo "SELF-TEST PASS: heuristic (def/decl/leaky-ident/comment) + real scan() path (unblessed caught, blessed clean)"
		return 0
	fi
	return 1
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
	echo "This is the mechanism that would have forced a review of the second gf_dot when it was introduced."
	echo "(It is a LOCATION guard, not a correctness one: a branch regression inside a blessed file is caught by ctgrind/dudect, not here.)"
	exit 1
fi
