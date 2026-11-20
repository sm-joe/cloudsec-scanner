#!/usr/bin/env bash
# Explicit one-time refresh. Do not generalize this into mutable release publishing.
set -euo pipefail
[[ "$GH_REPO" == sm-joe/cloudsec-scanner ]]
[[ "$ORIGINAL_SHA" == 673d2565a8f7529ac151eaeef3e8ed5459679e80 ]]
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ && "$RELEASE_SHA" != "$ORIGINAL_SHA" ]]
[[ "$(gh api "repos/$GH_REPO/git/ref/heads/main" --jq .object.sha)" == "$RELEASE_SHA" ]]
[[ "$(gh api "repos/$GH_REPO/git/ref/tags/v0.1.0" --jq .object.sha)" == "$ORIGINAL_SHA" ]]
# Ensure metadata has not changed since backup.
gh api "repos/$GH_REPO/releases/tags/v0.1.0" > current-release.json
python - <<'PY'
import json
from pathlib import Path
old = json.loads(Path("original-release/release.json").read_text())
now = json.loads(Path("current-release.json").read_text())
assert now == old, "release changed after backup"
PY
names=(cloudsec_scanner-0.1.0-py3-none-any.whl cloudsec_scanner-0.1.0.tar.gz runtime-sbom.json SHA256SUMS)
original=()
candidate=()
for name in "${names[@]}"; do
  original+=("original-release/$name")
  candidate+=("dist/$name")
done
(cd original-release && sha256sum -c original-digests.txt)
(cd dist && sha256sum -c SHA256SUMS)
# Replacement is not an atomic GitHub API operation. Keep a verified backup,
# and restore original bytes/tag/notes on any failed upload or verification.
rollback() {
  status=$?
  trap - EXIT
  if (( status != 0 )); then
    echo "Release refresh failed; attempting restoration of original release." >&2
    set +e
    gh release upload v0.1.0 "${original[@]}" --clobber
    gh api --method PATCH "repos/$GH_REPO/git/refs/tags/v0.1.0" -f sha="$ORIGINAL_SHA" -F force=true
    gh release edit v0.1.0 --target "$ORIGINAL_SHA" --notes-file original-release/notes.md
    mkdir -p restored-release
    gh release download v0.1.0 --dir restored-release --pattern '*'
    (cd restored-release && sha256sum -c ../original-release/original-digests.txt)
    if [[ $? != 0 ]]; then echo "RESTORATION REQUIRES MANUAL REVIEW" >&2; fi
  fi
  exit "$status"
}
trap rollback EXIT
gh release upload v0.1.0 "${candidate[@]}" --clobber
mkdir -p verified-release
gh release download v0.1.0 --dir verified-release --pattern '*'
for name in "${names[@]}"; do cmp "dist/$name" "verified-release/$name"; done
(cd verified-release && sha256sum -c SHA256SUMS)
[[ "$(gh api "repos/$GH_REPO/git/ref/heads/main" --jq .object.sha)" == "$RELEASE_SHA" ]]
gh api --method PATCH "repos/$GH_REPO/git/refs/tags/v0.1.0" -f sha="$RELEASE_SHA" -F force=true
gh release edit v0.1.0 --target "$RELEASE_SHA" --notes-file docs/releases/v0.1.0.md
[[ "$(gh api "repos/$GH_REPO/git/ref/tags/v0.1.0" --jq .object.sha)" == "$RELEASE_SHA" ]]
gh api "repos/$GH_REPO/releases/tags/v0.1.0" --jq '{id,tag_name,draft,prerelease,assets:[.assets[].name]}'
trap - EXIT
echo "Verified v0.1.0 refresh completed."
