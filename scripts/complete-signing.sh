#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077

usage() {
  cat >&2 <<'EOF'
Usage: scripts/complete-signing.sh \
  --archive /path/to/package.tar.gz \
  --repository entorn-scanner-dotnet|entorn-scanner-php \
  --asset-url https://github.com/Entorn-dev/... \
  --name "Scanner display name" \
  --catalog-version VERSION \
  --generated-at ISO-8601-UTC \
  --expected-catalog-sha256 SHA256 \
  --private-key /path/to/private-key.pem \
  [--replace-existing]

The command signs the package identity and complete catalog, verifies the
result, and changes only catalog.json. It never commits or pushes.
EOF
  exit 2
}

archive=""
repository=""
asset_url=""
name=""
catalog_version=""
generated_at=""
expected_catalog_sha256=""
private_key=""
replace_existing=false

while (($#)); do
  case "$1" in
    --archive|--repository|--asset-url|--name|--catalog-version|--generated-at|--expected-catalog-sha256|--private-key)
      (($# >= 2)) || usage
      option="${1#--}"
      option="${option//-/_}"
      printf -v "$option" '%s' "$2"
      shift 2
      ;;
    --replace-existing)
      replace_existing=true
      shift
      ;;
    *) usage ;;
  esac
done

[[ -n "$archive" && -n "$repository" && -n "$asset_url" && -n "$name" &&
   -n "$catalog_version" && -n "$generated_at" && -n "$expected_catalog_sha256" &&
   -n "$private_key" ]] || usage
[[ "$expected_catalog_sha256" =~ ^[a-f0-9]{64}$ ]] || {
  echo "--expected-catalog-sha256 must be a lowercase SHA-256 digest." >&2
  exit 2
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
archive="$(realpath "$archive")"
private_key="$(realpath "$private_key")"
[[ -f "$archive" ]] || { echo "Package archive was not found." >&2; exit 2; }
[[ -f "$private_key" ]] || { echo "Private key was not found." >&2; exit 2; }
[[ -d "$root/.git" ]] || { echo "Run the tracked script from an entorn-scanner-catalog clone." >&2; exit 2; }
[[ -z "$(git -C "$root" status --porcelain)" ]] || {
  echo "Catalog clone must have a clean worktree before signing." >&2
  exit 2
}
echo "$expected_catalog_sha256  $root/catalog.json" | sha256sum --check --status || {
  echo "catalog.json does not match --expected-catalog-sha256; update or inspect the clone before retrying." >&2
  exit 2
}

if [[ -n "${CATALOG_PYTHON:-}" ]]; then
  python="$CATALOG_PYTHON"
elif [[ -x "$root/.venv/bin/python" ]]; then
  python="$root/.venv/bin/python"
else
  python=python3
fi
"$python" -c 'import jsonschema' 2>/dev/null || {
  echo "Python jsonschema is unavailable. Install requirements.txt in .venv, then retry." >&2
  exit 2
}

signing="$(mktemp -d "${TMPDIR:-/tmp}/entorn-catalog-signing.XXXXXXXX")"
trap 'rm -rf "$signing"' EXIT

"$python" "$root/scripts/add-release.py" prepare \
  --archive "$archive" \
  --repository "$repository" \
  --asset-url "$asset_url" \
  --name "$name" \
  --template "$signing/release.json" \
  --signing-input "$signing/release-signing.bin"
"$python" "$root/scripts/sign.py" \
  --private-key "$private_key" \
  --input "$signing/release-signing.bin" \
  --output "$signing/release-signature.txt"

base_args=(
  base
  --catalog "$root/catalog.json"
  --payload "$signing/catalog-payload.json"
  --catalog-version "$catalog_version"
  --generated-at "$generated_at"
)
if $replace_existing; then
  base_args+=(--replace-from-template "$signing/release.json")
fi
"$python" "$root/scripts/add-release.py" "${base_args[@]}"
"$python" "$root/scripts/add-release.py" add \
  --template "$signing/release.json" \
  --signature "$signing/release-signature.txt" \
  --payload "$signing/catalog-payload.json" \
  --catalog-version "$catalog_version" \
  --generated-at "$generated_at"
"$python" "$root/scripts/sign.py" \
  --private-key "$private_key" \
  --input "$signing/catalog-payload.json" \
  --output "$signing/catalog-signature.txt"
"$python" "$root/scripts/add-release.py" envelope \
  --payload "$signing/catalog-payload.json" \
  --signature "$signing/catalog-signature.txt" \
  --output "$signing/catalog.json"
"$python" "$root/scripts/verify-catalog.py" "$signing/catalog.json"

mv "$signing/catalog.json" "$root/catalog.json"
[[ "$(git -C "$root" status --short)" == " M catalog.json" ]] || {
  echo "Refusing unexpected worktree changes after signing." >&2
  exit 1
}

echo "Signed catalog prepared and verified at $root/catalog.json"
echo "Review with: git -C $root diff -- catalog.json"
echo "No commit or push was performed."
