#!/usr/bin/env bash
# systemd_hardening_lint.sh — verify the shipped systemd units are actually hardened
# (ROI-TOP-50 item 49).
#
# The network-share unlock server (dist/systemd/vc-netshared.service) is a secret-bearing,
# network-facing daemon; its unit file is only useful if it really drops privilege. This
# lints the unit TWO independent ways:
#   1. a required-directive check (this script): every directive in REQUIRED must be present
#      with an approved value — a missing/loosened line fails.
#   2. `systemd-analyze security --offline=true` (systemd's own scorer, when present): the
#      overall exposure level must be <= MAX_EXPOSURE.
#
# NEGATIVE CONTROL (proves the lint has teeth): a weakened copy of the unit with the
# hardening block stripped MUST fail check (1) and, where systemd-analyze is present, score
# a much worse exposure than the real unit. A lint that passes the weakened unit is broken.
#
# Exit 0 = all units pass; non-zero = a unit is under-hardened or the negative control did
# not fire. Dependency-free except the optional systemd-analyze cross-check.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
UNITDIR="$HERE/../dist/systemd"
MAX_EXPOSURE="3.0"       # real unit scores ~1.2; give headroom but stay well inside "OK" (<5)

# Directives that MUST appear, each with a regex of approved value(s).
# (yes/true accepted where systemd treats them as booleans.)
REQUIRED=(
	'NoNewPrivileges=(yes|true)'
	'ProtectSystem=strict'
	'ProtectHome=(yes|true|read-only)'
	'PrivateTmp=(yes|true)'
	'PrivateDevices=(yes|true)'
	'ProtectKernelTunables=(yes|true)'
	'ProtectKernelModules=(yes|true)'
	'ProtectKernelLogs=(yes|true)'
	'ProtectControlGroups=(yes|true)'
	'ProtectClock=(yes|true)'
	'ProtectHostname=(yes|true)'
	'ProtectProc=(invisible|noaccess|ptraceable)'
	'RestrictNamespaces=(yes|true)'
	'RestrictRealtime=(yes|true)'
	'RestrictSUIDSGID=(yes|true)'
	'LockPersonality=(yes|true)'
	'MemoryDenyWriteExecute=(yes|true)'
	'RestrictAddressFamilies=AF_'
	'SystemCallArchitectures=native'
	'SystemCallFilter=@system-service'
	'CapabilityBoundingSet='          # must be present; empty value = drop all
	'KeyringMode=private'
)

fail=0
pass_count=0

# --- required-directive check on one unit file ------------------------------------------
lint_unit () {
	local f="$1" quiet="${2:-}" missing=0 d
	for d in "${REQUIRED[@]}"; do
		# Match "Directive=value" allowing leading spaces; value regex is the part after '='.
		local key="${d%%=*}" val="${d#*=}"
		if ! grep -Eq "^[[:space:]]*${key}=${val}" "$f"; then
			[ -z "$quiet" ] && echo "    MISSING/loose: ${key}=${val}"
			missing=$((missing+1))
		fi
	done
	# CapabilityBoundingSet must be EMPTY (drop all) — reject a non-empty grant.
	if grep -Eq "^[[:space:]]*CapabilityBoundingSet=[^[:space:]]" "$f"; then
		[ -z "$quiet" ] && echo "    CapabilityBoundingSet is non-empty (must drop all caps)"
		missing=$((missing+1))
	fi
	return $missing
}

# --- optional systemd-analyze exposure gate ---------------------------------------------
exposure_of () {  # prints the numeric overall exposure, or empty if tool absent/failed
	command -v systemd-analyze >/dev/null 2>&1 || return 0
	systemd-analyze security --offline=true --no-pager "$1" 2>/dev/null \
		| grep -oE 'exposure level for .*: [0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+$'
}

echo "== systemd hardening lint =="
have_analyze=0; command -v systemd-analyze >/dev/null 2>&1 && have_analyze=1
[ "$have_analyze" = 1 ] && echo "  systemd-analyze present — exposure gate active (max ${MAX_EXPOSURE})" \
                        || echo "  note: systemd-analyze absent — directive check only (CI has it)"

shopt -s nullglob
services=("$UNITDIR"/*.service)
if [ ${#services[@]} -eq 0 ]; then echo "  no .service units found in $UNITDIR"; exit 2; fi

for f in "${services[@]}"; do
	name="$(basename "$f")"
	echo "  [unit] $name"
	if lint_unit "$f"; then
		echo "    directives: PASS (all ${#REQUIRED[@]} required present)"
	else
		echo "    directives: FAIL"; fail=1; continue
	fi
	if [ "$have_analyze" = 1 ]; then
		exp="$(exposure_of "$f")"
		if [ -n "$exp" ] && awk "BEGIN{exit !($exp <= $MAX_EXPOSURE)}"; then
			echo "    systemd-analyze exposure: $exp <= $MAX_EXPOSURE  PASS"
		else
			echo "    systemd-analyze exposure: ${exp:-?} > $MAX_EXPOSURE  FAIL"; fail=1
		fi
	fi
	pass_count=$((pass_count+1))
done

# --- NEGATIVE CONTROL -------------------------------------------------------------------
echo "  [negative control] a unit with the hardening block stripped must FAIL"
weak="$(mktemp --suffix=.service)"; trap 'rm -f "$weak"' EXIT
# Keep only [Unit]/[Service] skeleton + ExecStart; drop every hardening directive.
{
	echo "[Unit]"; echo "Description=weakened control (no hardening)"
	echo "[Service]"; echo "Type=simple"; echo "ExecStart=/usr/libexec/vc-netshared"
} > "$weak"
if lint_unit "$weak" quiet; then
	echo "    FAIL: the stripped unit PASSED the directive check — lint has no teeth"; fail=1
else
	echo "    directive check correctly REJECTS the stripped unit"
fi
if [ "$have_analyze" = 1 ]; then
	real_exp="$(exposure_of "${services[0]}")"; weak_exp="$(exposure_of "$weak")"
	if [ -n "$real_exp" ] && [ -n "$weak_exp" ] && awk "BEGIN{exit !($weak_exp > $real_exp)}"; then
		echo "    systemd-analyze: stripped exposure $weak_exp > hardened $real_exp  (hardening is load-bearing)"
	else
		echo "    FAIL: stripped unit did not score worse (real=${real_exp:-?} weak=${weak_exp:-?})"; fail=1
	fi
fi

echo ""
if [ "$fail" -eq 0 ]; then
	echo "SYSTEMD-LINT PASS: $pass_count unit(s) hardened; negative control fires"
	exit 0
else
	echo "SYSTEMD-LINT FAIL"
	exit 1
fi
