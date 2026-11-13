#!/usr/bin/env bash
# The OpenSSL Configure options that trim libcrypto for a shipped engine,
# from scripts/lib_openssl_trim.txt, for one class of target:
#
#   device    phones and the browser (iOS, Android, WebAssembly): the whole
#             list, elliptic curves included. P-256 there is the platform's
#             own, through DeviceFips.
#   desktop   desktop and server engines (the macOS slice and desktop dylib,
#             the sealed static archive, Linux): the list without no-ec and
#             no-ecdsa, so the engine carries P-256 ECDSA (docs/P256.md).
#             ECDH, binary curves and SM2 stay configured out.
#
# Usage: scripts/lib/openssl_trim.sh <device|desktop>
set -euo pipefail
LIST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib_openssl_trim.txt"
case "${1:-}" in
    device)  tr -s ' \n' ' ' < "$LIST" ;;
    desktop) tr -s ' \n' '\n' < "$LIST" | grep -vxE 'no-ec|no-ecdsa' | tr '\n' ' ' ;;
    *) echo "usage: $0 <device|desktop>" >&2; exit 2 ;;
esac
echo
