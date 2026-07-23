#!/usr/bin/env python3
"""sbom.py — generate and validate a CycloneDX Software Bill of Materials for the fork
(ROI-TOP-50 item 40).

A per-release SBOM lets a downstream consumer see exactly which components and third-party
dependencies went into the binary — necessary for vulnerability tracking and supply-chain review.
This emits a minimal CycloneDX 1.5 JSON document covering the fork's own gated Common modules plus
the external/bundled dependencies, and validates that the SBOM actually covers every fork module
present in the source tree (so the SBOM cannot silently drift out of date).

Usage:
  sbom.py generate                 # write the SBOM JSON to stdout
  sbom.py validate <sbom.json>     # check well-formedness + full fork-module coverage (exit!=0 on gap)
  sbom.py validate --negctl <f>    # expect validation to FAIL (used by the negative control)
"""
import sys, os, json

HERE = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.join(HERE, "..", "src", "Common")

# The fork's own gated modules (component name -> the VC_ENABLE_* feature it implements).
FORK_MODULES = {
    "HardwareKeyFactor": "VC_ENABLE_HKF",
    "KeyScrub":          "VC_ENABLE_KEYSCRUB",
    "DuressToken":       "VC_ENABLE_DURESS",
    "Keyslot":           "VC_ENABLE_KEYSLOTS",
    "KeyslotStore":      "VC_ENABLE_KEYSLOTS",
    "KeyslotKdf":        "VC_ENABLE_KEYSLOTS",
    "AfSplit":           "VC_ENABLE_KEYSLOTS",
    "KeyslotAreaFile":   "VC_ENABLE_KEYSLOTS",
    "Shamir":            "VC_ENABLE_HKF",
    "ShamirMac":         "VC_ENABLE_SHAMIR_MAC",
    "ShareCode":         "VC_ENABLE_SHARECODE",
    "SelfTest":          "VC_ENABLE_SELFTEST",
    "VcStatus":          "VC_ENABLE_STATUS",
    "VcJson":            "VC_ENABLE_JSON",
    "HeaderBackup":      "VC_ENABLE_HEADER_BACKUP",
    "HkfOrSet":          "VC_ENABLE_HKF_ORSET",
    "VcPosture":         "VC_ENABLE_POSTURE",
}

# External / bundled third-party dependencies.
EXTERNAL = [
    ("argon2",       "bundled", "src/Crypto/Argon2", "Argon2id memory-hard KDF (RFC 9106)"),
    ("wxWidgets",    "runtime", None, "GUI/CLI application framework"),
    ("libfido2",     "runtime", None, "FIDO2 hmac-secret hardware factor backend"),
    ("libykpers-1",  "runtime", None, "YubiKey HMAC-SHA1 challenge-response backend"),
    ("libpcsclite",  "runtime", None, "PC/SC smartcard access (PKCS#11 factor)"),
]

def fork_modules_present():
    """Fork modules that actually exist in the source tree (a .c file)."""
    return [m for m in FORK_MODULES if os.path.isfile(os.path.join(COMMON, m + ".c"))]

def generate():
    comps = []
    for m in fork_modules_present():
        comps.append({
            "type": "library", "name": m, "group": "vc-fork",
            "properties": [{"name": "vc:feature-flag", "value": FORK_MODULES[m]}],
        })
    for name, scope, path, desc in EXTERNAL:
        c = {"type": "library", "name": name, "scope": scope, "description": desc}
        if path: c["properties"] = [{"name": "vc:bundled-path", "value": path}]
        comps.append(c)
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "veracrypt-fork"}},
        "components": comps,
    }
    return bom

def validate(path, negctl=False):
    try:
        with open(path) as f: bom = json.load(f)
    except Exception as e:
        return _result(False, f"not valid JSON: {e}", negctl)
    errs = []
    if bom.get("bomFormat") != "CycloneDX": errs.append("bomFormat != CycloneDX")
    if not bom.get("specVersion"):          errs.append("missing specVersion")
    comps = bom.get("components") or []
    names = {c.get("name") for c in comps}
    if not comps: errs.append("no components")
    # coverage: every fork module present in the tree must appear in the SBOM
    for m in fork_modules_present():
        if m not in names: errs.append(f"fork module not in SBOM: {m}")
    # required external deps
    for name, *_ in EXTERNAL:
        if name not in names: errs.append(f"external dependency not in SBOM: {name}")
    ok = not errs
    return _result(ok, "; ".join(errs) if errs else "complete + well-formed", negctl)

def _result(ok, msg, negctl):
    if negctl:
        # negative control: we EXPECT validation to fail
        if ok:
            print("NEGCTL-FAIL: a tampered SBOM validated clean (validator has no teeth)"); return 1
        print(f"NEGCTL-OK: tampered SBOM correctly rejected ({msg})"); return 0
    if ok: print(f"SBOM-VALID: {msg}"); return 0
    print(f"SBOM-INVALID: {msg}"); return 1

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "generate":
        print(json.dumps(generate(), indent=2)); return 0
    if len(sys.argv) >= 3 and sys.argv[1] == "validate":
        if sys.argv[2] == "--negctl":
            return validate(sys.argv[3], negctl=True)
        return validate(sys.argv[2])
    sys.stderr.write(__doc__); return 2

if __name__ == "__main__":
    sys.exit(main())
