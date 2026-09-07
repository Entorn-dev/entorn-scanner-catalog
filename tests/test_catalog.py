import argparse
import base64
import hashlib
import importlib.util
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

import catalog_lib

spec = importlib.util.spec_from_file_location(
    "add_release", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "add-release.py")
assert spec is not None and spec.loader is not None
add_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(add_release)


class CatalogTests(unittest.TestCase):
    def test_signatures_round_trip_and_reject_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            content = root / "content.bin"
            content.write_bytes(b"exact catalog bytes")
            subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                            "ec_paramgen_curve:P-256", "-out", private_key], check=True)
            subprocess.run(["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key], check=True)

            signature = catalog_lib.sign(private_key, content)
            catalog_lib.verify(content.read_bytes(), signature, public_key)
            with self.assertRaisesRegex(ValueError, "verification failed"):
                catalog_lib.verify(b"changed", signature, public_key)

    def test_prepare_binds_exact_archive_and_release_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive = root / "entorn-scanner-dotnet-linux-x64-1.3.0.tar.gz"
            self._package(root)
            template = root / "release.json"
            signing_input = root / "release-signing.bin"
            asset_url = (
                "https://github.com/Entorn-dev/entorn-scanner-dotnet/releases/download/v1.3.0/"
                + archive.name)

            add_release.prepare(argparse.Namespace(
                archive=archive, repository="entorn-scanner-dotnet", asset_url=asset_url,
                name="Entorn .NET scanner", template=template, signing_input=signing_input))

            release = catalog_lib.load_json(template)
            self.assertEqual("archie.dotnet", release["id"])
            self.assertEqual(__import__("hashlib").sha256(archive.read_bytes()).hexdigest(), release["sha256"])
            self.assertEqual(catalog_lib.signing_bytes(release), signing_input.read_bytes())
            with self.assertRaisesRegex(ValueError, "Asset URL"):
                add_release.prepare(argparse.Namespace(
                    archive=archive, repository="entorn-scanner-dotnet", asset_url=asset_url + "?mutable=1",
                    name="Entorn .NET scanner", template=template, signing_input=signing_input))

    def test_add_release_orders_payload_and_rejects_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            payload = root / "payload.json"
            signature = root / "signature.txt"
            signature.write_text(__import__("base64").b64encode(bytes(64)).decode() + "\n")
            for scanner_id in ("archie.php", "archie.dotnet"):
                template = root / f"{scanner_id}.json"
                release = self._release(scanner_id)
                catalog_lib.write_json(template, release)
                add_release.add(argparse.Namespace(
                    template=template, signature=signature, payload=payload,
                    catalog_version="2026-09-04.1", generated_at="2026-09-04T00:00:00Z"))

            actual = catalog_lib.load_json(payload)["releases"]
            self.assertEqual(["archie.dotnet", "archie.php"], [item["id"] for item in actual])
            with self.assertRaisesRegex(ValueError, "already present"):
                add_release.add(argparse.Namespace(
                    template=root / "archie.dotnet.json", signature=signature, payload=payload,
                    catalog_version="2026-09-04.1", generated_at="2026-09-04T00:00:00Z"))

    def test_complete_signer_replaces_existing_scanner_and_only_changes_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            repository = root / "catalog"
            project_root = pathlib.Path(__file__).resolve().parents[1]
            shutil.copytree(project_root, repository, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))

            private_key = root / "private.pem"
            public_key = repository / "keys" / f"{catalog_lib.KEY_ID}-public.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                            "ec_paramgen_curve:P-256", "-out", private_key], check=True)
            subprocess.run(["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key], check=True)

            old_release = self._release("archie.dotnet")
            signing_input = root / "old-release.bin"
            signing_input.write_bytes(catalog_lib.signing_bytes(old_release))
            old_release["packageSignature"] = catalog_lib.sign(private_key, signing_input)
            payload_path = root / "payload.json"
            catalog_lib.write_json(payload_path, {
                "schemaVersion": "scanner-catalog/v1",
                "catalogVersion": "2026-09-04.1",
                "generatedAt": "2026-09-04T00:00:00Z",
                "releases": [old_release],
            })
            catalog_lib.write_json(repository / "catalog.json", {
                "schemaVersion": "signed-scanner-catalog/v1",
                "keyId": catalog_lib.KEY_ID,
                "payload": base64.b64encode(payload_path.read_bytes()).decode("ascii"),
                "signature": catalog_lib.sign(private_key, payload_path),
            })

            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "Catalog test"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "catalog-test@example.invalid"], cwd=repository, check=True)
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repository, check=True)

            self._package(root)
            archive = root / "entorn-scanner-dotnet-linux-x64-1.3.0.tar.gz"
            asset_url = (
                "https://github.com/Entorn-dev/entorn-scanner-dotnet/releases/download/v1.3.0/"
                + archive.name)
            command = [
                "bash", str(repository / "scripts" / "complete-signing.sh"),
                "--archive", str(archive),
                "--repository", "entorn-scanner-dotnet",
                "--asset-url", asset_url,
                "--name", "Entorn .NET scanner",
                "--catalog-version", "2026-09-07.1",
                "--generated-at", "2026-09-07T05:14:42Z",
                "--expected-catalog-sha256", "0" * 64,
                "--private-key", str(private_key),
                "--replace-existing",
            ]
            rejected = subprocess.run(command, cwd=repository, capture_output=True, text=True)
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("does not match", rejected.stderr)
            self.assertEqual("", subprocess.run(["git", "status", "--short"], cwd=repository,
                                                check=True, capture_output=True, text=True).stdout)

            command[command.index("0" * 64)] = hashlib.sha256((repository / "catalog.json").read_bytes()).hexdigest()
            subprocess.run(command, cwd=repository, check=True)

            payload = catalog_lib.verified_payload(repository / "catalog.json", public_key)
            self.assertEqual("2026-09-07.1", payload["catalogVersion"])
            self.assertEqual([("archie.dotnet", "1.3.0")],
                             [(release["id"], release["version"]) for release in payload["releases"]])
            status = subprocess.run(["git", "status", "--short"], cwd=repository,
                                    check=True, capture_output=True, text=True).stdout
            self.assertEqual(" M catalog.json\n", status)

    @staticmethod
    def _release(scanner_id: str) -> dict:
        repository = "entorn-scanner-dotnet" if scanner_id.endswith("dotnet") else "entorn-scanner-php"
        return {
            "id": scanner_id, "name": scanner_id, "version": "1.0.0", "channel": "stable",
            "sourceRepository": f"https://github.com/Entorn-dev/{repository}", "sourceTag": "v1.0.0",
            "platform": "linux", "architecture": "x64", "archieVersionRange": "[1.0.0,2.0.0)",
            "protocolVersion": "scanner/v1",
            "assetUrl": f"https://github.com/Entorn-dev/{repository}/releases/download/v1.0.0/package.tar.gz",
            "compressedBytes": 1, "expandedBytes": 1, "entryCount": 1, "sha256": "a" * 64,
            "signingKeyId": catalog_lib.KEY_ID, "packageSignature": "",
            "capabilities": ["source-ownership"],
            "permissions": {"readRepository": True, "network": False, "environment": False},
            "license": "Apache-2.0",
            "releaseNotesUrl": f"https://github.com/Entorn-dev/{repository}/releases/tag/v1.0.0",
            "revoked": False
        }

    @staticmethod
    def _package(root: pathlib.Path) -> dict:
        stage = root / "stage"
        stage.mkdir()
        (stage / "scanner.json").write_text("{}")
        package_path = stage / "PACKAGE.json"
        package = {
            "schemaVersion": "scanner-package/v1", "id": "archie.dotnet", "version": "1.3.0",
            "sourceRepository": "https://github.com/Entorn-dev/entorn-scanner-dotnet", "sourceTag": "v1.3.0",
            "platform": "linux", "architecture": "x64", "archieVersionRange": "[1.0.0,2.0.0)",
            "protocolVersion": "scanner/v1", "expandedBytes": 0, "entryCount": 2,
            "capabilities": ["source-ownership"],
            "permissions": {"readRepository": True, "network": False, "environment": False},
            "license": "Apache-2.0", "publisherKeyId": catalog_lib.KEY_ID
        }
        for _ in range(10):
            catalog_lib.write_json(package_path, package)
            size = sum(path.stat().st_size for path in stage.iterdir())
            if package["expandedBytes"] == size:
                break
            package["expandedBytes"] = size
        archive = root / "entorn-scanner-dotnet-linux-x64-1.3.0.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(package_path, arcname="PACKAGE.json")
            output.add(stage / "scanner.json", arcname="scanner.json")
        return package


if __name__ == "__main__":
    unittest.main()
