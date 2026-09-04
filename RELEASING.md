# Release operations

## Add a scanner release

1. Approve and publish the scanner repository's immutable GitHub Release archive.
2. Download that exact archive on the offline signing workstation.
3. Run `add-release.py prepare` with its final GitHub asset URL and release name. Inspect the extracted metadata, SHA-256, size, and generated signing input.
4. Sign `release-signing.bin` with `sign.py`; add the resulting signature with `add-release.py add`.
5. Inspect the exact `catalog-payload.json`, sign it with `sign.py`, and build `catalog.json` with `add-release.py envelope`.
6. Run `verify-catalog.py`, review the diff, and submit the signed catalog commit. CI verifies but cannot sign or replace it.

The signing scripts invoke OpenSSL locally. A private-key path is accepted only by `sign.py`; it is never copied or printed.

## Rotation

Generate a new encrypted P-256 key offline, retain its public key and fingerprint, and add that public key to both this repository and an Entorn core release before signing with it. Keep the old public key trusted while supported releases or rollback packages use it. Record the new key ID, activation date, custodian, and retirement plan in this document.

## Revocation and compromise

If a scanner release is unsafe but the key remains trusted, set its signed catalog entry's `revoked` field to `true`, re-sign the complete payload, publish, and document the reason in release notes. Entorn warns but does not silently delete installed bytes.

If private-key confidentiality or integrity may be lost, stop all releases, remove the key from signing use, publish an Entorn core update that distrusts it and embeds a new approved public key, and only then resume catalog publication. Because an attacker holding the old key could sign a malicious catalog, DNS/repository rollback alone is not sufficient. Preserve incident evidence and rotate the encrypted offline backup.

## Backup

The primary custodian keeps the encrypted private key and a tested encrypted offline backup under their control. Recovery is tested without exposing key material. The catalog repository stores public keys only.
