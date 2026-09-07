# Release operations

## Add a scanner release

1. Approve and publish the scanner repository's immutable GitHub Release archive.
2. Download that exact archive on the offline signing workstation.
3. On a clean, current catalog clone, record the exact digest with `sha256sum catalog.json`.
4. Run `scripts/complete-signing.sh` with the archive, final GitHub asset URL, release details, a new catalog version and timestamp, the recorded catalog digest, and the offline private-key path. Use `--replace-existing` only when all existing releases for that scanner ID must be removed.
5. Review the `catalog.json` diff and submit the signed catalog commit. CI verifies but cannot sign or replace it.

For example:

```bash
scripts/complete-signing.sh \
  --archive /media/offline/entorn-scanner-php-linux-x64-2.0.0.tar.gz \
  --repository entorn-scanner-php \
  --asset-url https://github.com/Entorn-dev/entorn-scanner-php/releases/download/v2.0.0/entorn-scanner-php-linux-x64-2.0.0.tar.gz \
  --name "Entorn PHP scanner" \
  --catalog-version 2026-09-07.1 \
  --generated-at 2026-09-07T05:14:42Z \
  --expected-catalog-sha256 178504dde4399832a434074a91b2e1ae3255d98c433e4d2e229eb625e87dba81 \
  --private-key /media/offline/entorn-scanner-signing-2026-01-private.pem \
  --replace-existing
```

The complete signer invokes OpenSSL locally twice: once for the immutable package identity and once for the complete catalog payload. An encrypted key may therefore request its passphrase twice. The script disables shell tracing, creates private temporary files, removes them on exit, verifies the current signed catalog and both new signatures, and refuses dirty or unexpected repository state. The private key is referenced by path; it is never copied, printed, committed, or included in the catalog. The script changes only `catalog.json` and never commits or pushes.

The lower-level `add-release.py`, `sign.py`, and `verify-catalog.py` commands remain available for inspection and recovery, but the complete signer is the normal release path.

## Rotation

Generate a new encrypted P-256 key offline, retain its public key and fingerprint, and add that public key to both this repository and an Entorn core release before signing with it. Keep the old public key trusted while supported releases or rollback packages use it. Record the new key ID, activation date, custodian, and retirement plan in this document.

## Revocation and compromise

If a scanner release is unsafe but the key remains trusted, set its signed catalog entry's `revoked` field to `true`, re-sign the complete payload, publish, and document the reason in release notes. Entorn warns but does not silently delete installed bytes.

If private-key confidentiality or integrity may be lost, stop all releases, remove the key from signing use, publish an Entorn core update that distrusts it and embeds a new approved public key, and only then resume catalog publication. Because an attacker holding the old key could sign a malicious catalog, DNS/repository rollback alone is not sufficient. Preserve incident evidence and rotate the encrypted offline backup.

## Backup

The primary custodian keeps the encrypted private key and a tested encrypted offline backup under their control. Recovery is tested without exposing key material. The catalog repository stores public keys only.
