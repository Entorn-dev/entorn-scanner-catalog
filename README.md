# Entorn scanner catalog

This repository publishes the signed first-party scanner catalog at `https://catalog.entorn.dev/catalog.json`. The catalog contains only immutable, directly addressed GitHub Release assets. Entorn never downloads a scanner while opening or scanning a repository; catalog access occurs only through explicit scanner lifecycle commands.

## Trust

- Algorithm: ECDSA P-256 with SHA-256.
- Active key ID: `entorn-scanner-signing-2026-01`.
- Public-key DER SHA-256: `68b93eb0151671e1d1742f06c3d69a25353679d521d861fc90a5f1395487431e`.
- The encrypted private key and backup remain offline with the primary custodian. They never enter GitHub, CI, scanner archives, or this repository.
- The custodian approves scanner releases, signs exact package identity/version/platform/architecture/digest bytes, and signs the exact catalog payload bytes.

See [RELEASING.md](RELEASING.md) for the release, rotation, and emergency-revocation procedure.

## Verify

```bash
python3 -m pip install -r requirements.txt
python3 scripts/verify-catalog.py catalog.json
python3 -m unittest discover -s tests
```

The schemas retain their existing `archie.dev` identifiers and released scanner IDs remain `archie.*` during the separately managed product rename. Changing wire identities requires a compatibility migration.

## License

Apache-2.0. Contributions use DCO sign-off; see [CONTRIBUTING.md](CONTRIBUTING.md).
