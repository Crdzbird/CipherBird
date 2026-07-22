#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# audit_symbols.sh — "no ambient authority" gate for the CryptoLib binary.
#
# A cryptography library should be a sealed compute unit: it takes bytes in and
# returns bytes out. It must never open a socket, spawn a process, or otherwise
# create a channel through which key material or plaintext could leak. This
# script proves that property mechanically by inspecting the linked binary's
# imported symbols, so a future change can never SILENTLY add an exfiltration
# path — the build fails instead.
#
# HARD gate (exit 1 if present): networking + process execution. No dependency
# we ship (libsodium, liboqs, blst, libcrypto, secp256k1, BLAKE3) legitimately
# references these; their presence means new, unaudited outbound capability.
#
# WATCH (reported, non-fatal): dynamic loading + environment reads. OpenSSL's
# libcrypto uses dlopen (providers) and getenv (OPENSSL_CONF) internally, so a
# hard ban would false-positive a fully-static build; we surface them instead so
# a reviewer can confirm they originate from a vetted dependency, not new code.
#
# Usage: scripts/audit_symbols.sh [path-to-lib]
#   default: build/release/libcryptolib_c.dylib (or .so on Linux)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="${1:-}"
if [[ -z "$LIB" ]]; then
  for cand in "$ROOT/build/release/libcryptolib_c.dylib" \
              "$ROOT/build/release/libcryptolib_c.so" \
              "$ROOT/build/test/libcryptolib_c.dylib"; do
    [[ -f "$cand" ]] && { LIB="$cand"; break; }
  done
fi
[[ -f "$LIB" ]] || { echo "audit: binary not found (pass a path or build first): $LIB" >&2; exit 2; }
command -v nm >/dev/null 2>&1 || { echo "audit: 'nm' not available" >&2; exit 2; }

echo "══ no-ambient-authority audit ══"
echo "   target: ${LIB#$ROOT/}"

# Imported (undefined) symbols. macOS mangles with a leading underscore; the
# regexes tolerate an optional leading '_' and match on a word boundary/end.
IMPORTS="$(nm -u "$LIB" 2>/dev/null || nm -D --undefined-only "$LIB" 2>/dev/null || true)"

HARD='_?(socket|connect|bind|listen|accept|send|sendto|sendmsg|recv|recvfrom|recvmsg|getaddrinfo|getnameinfo|gethostbyname|gethostbyaddr|inet_aton|inet_pton|system|popen|execl|execle|execlp|execv|execve|execvp|execvpe|posix_spawn|posix_spawnp|fork|vfork)$'
WATCH='_?(dlopen|dlmopen|dlsym|getenv|secure_getenv|setenv|putenv|unsetenv)$'

hard_hits="$(printf '%s\n' "$IMPORTS" | awk '{print $NF}' | grep -E "$HARD" | sort -u || true)"
watch_hits="$(printf '%s\n' "$IMPORTS" | awk '{print $NF}' | grep -E "$WATCH" | sort -u || true)"

if [[ -n "$watch_hits" ]]; then
  echo "   ── watch (non-fatal; confirm these come from a vetted dependency):"
  printf '        %s\n' $watch_hits
fi

if [[ -n "$hard_hits" ]]; then
  echo "   ✗ FORBIDDEN network/exec symbols imported:"
  printf '        %s\n' $hard_hits
  echo "   A crypto library must not reach the network or spawn processes."
  # On a FULLY-STATIC binary these are typically OpenSSL's libcrypto BIO-socket
  # objects (dormant — no CryptoLib path invokes them). The shared dylib is
  # clean because libcrypto is external there. To get a socket-free static
  # build, link an OpenSSL built with `no-sock no-dso`.
  if printf '%s\n' "$hard_hits" | grep -qE '_(socket|connect|sendto|recvmsg)$'; then
    echo "   NOTE: if this is a static binary, these are usually OpenSSL BIO"
    echo "         sockets — rebuild libcrypto with 'no-sock no-dso' to remove them."
  fi
  exit 1
fi
echo "   ✓ no networking or process-execution symbols imported"

# On macOS, also confirm the runtime dependency set stays within an allowlist —
# an unexpected new dylib (e.g. a network client) would defeat self-containment.
if command -v otool >/dev/null 2>&1; then
  # OS-provided libraries (/usr/lib, /System/Library frameworks) are SIP-protected
  # and not substitutable, so they don't defeat self-containment. Beyond those,
  # only our own lib and the known crypto dependencies are allowed — an
  # unexpected third-party dylib (e.g. a network client) would be flagged.
  ALLOW='^/usr/lib/|^/System/Library/|/(libcryptolib_c|libsodium|libblake3|libcrypto|libsecp256k1)\.'
  unexpected="$(otool -L "$LIB" 2>/dev/null | sed -n '2,$p' | awk '{print $1}' \
                | grep -vE "$ALLOW" || true)"
  if [[ -n "$unexpected" ]]; then
    echo "   ✗ unexpected dynamic dependency (not in the allowlist):"
    printf '        %s\n' $unexpected
    exit 1
  fi
  echo "   ✓ dynamic dependencies within allowlist"
fi

echo "══ audit passed ══"
