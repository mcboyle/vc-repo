#!/usr/bin/env bash
# Reproduce this fork from a stock VeraCrypt 1.26.29 source tree by applying the patch series and
# copying the new files. The repo already ships a full, buildable src/ — this script is for applying
# the changes onto a fresh/other upstream checkout, or for reviewing exactly what changed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM="${1:-}"
if [ -z "$UPSTREAM" ] || [ ! -d "$UPSTREAM/src" ]; then
  echo "usage: bootstrap.sh /path/to/stock/VeraCrypt-1.26.29   (must contain src/)"
  echo "get the source from https://www.veracrypt.fr/en/Downloads.html (1.26.29 source)"
  exit 1
fi
echo "Applying patch series to $UPSTREAM/src ..."
cd "$UPSTREAM/src"
for p in blake2b-prf sha3-prf volumes-hkf-hooks decoy-hkf-hooks cli-hkf-options; do
  f="$HERE/patches/$p.patch"
  [ -f "$f" ] || { echo "  skip (missing) $p"; continue; }
  echo "  patch: $p"
  patch -p2 < "$f"
done
echo "Copying new source files ..."
# (the new files are also embedded in the patches as additions; this is a belt-and-suspenders copy
#  from the bundled fork if present)
if [ -d "$HERE/src" ]; then
  for f in Common/HardwareKeyFactor.c Common/HardwareKeyFactor.h Common/Shamir.c Common/Shamir.h \
           Volume/HardwareKeyFactorMix.h Main/HardwareKeyFactorCli.h Crypto/Sha3.c Crypto/Sha3.h; do
    [ -f "$HERE/src/$f" ] && install -D "$HERE/src/$f" "$UPSTREAM/src/$f" && echo "  + $f"
  done
fi
echo "Done. Build per docs/HARDWARE-2FA.md (set the VC_ENABLE_* flags)."
