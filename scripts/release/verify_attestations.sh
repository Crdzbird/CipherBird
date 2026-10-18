#!/usr/bin/env bash
# Every binary a consumer receives must carry a build provenance attestation
# from this repository's engines workflow. Fails on the first blob that does
# not. Requires gh with access to the repository.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO="${GITHUB_REPOSITORY:-Crdzbird/CipherBird}"
status=0
while IFS= read -r blob; do
    [[ -z "$blob" ]] && continue
    if gh attestation verify "$ROOT/$blob" --repo "$REPO" > /dev/null 2>&1; then
        printf 'attested  %s\n' "$blob"
    else
        printf 'UNATTESTED  %s\n' "$blob"
        status=1
    fi
done < "$ROOT/scripts/release/shipped_blobs.txt"
exit $status
