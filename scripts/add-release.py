#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import pathlib
import tarfile
from typing import Any

from catalog_lib import (
    KEY_ID,
    decode_signature,
    load_json,
    release_sort_key,
    signing_bytes,
    validate,
    verified_payload,
    write_json,
)


def prepare(args: argparse.Namespace) -> None:
    archive: pathlib.Path = args.archive
    if not archive.is_file() or archive.stat().st_size <= 0 or archive.stat().st_size > 1024**3:
        raise ValueError("Archive size is outside the catalog bounds.")
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
        if len(members) > 50_000:
            raise ValueError("Archive entry count exceeds the catalog bounds.")
        names = set()
        for member in members:
            normalized = member.name.replace("\\", "/").rstrip("/")
            parts = normalized.split("/")
            if (not normalized or normalized.startswith("/") or
                    len(parts[0]) >= 2 and parts[0][1] == ":" or
                    any(part in ("", ".", "..") for part in parts) or
                    normalized in names or not (member.isfile() or member.isdir())):
                raise ValueError("Archive contains an unsafe, duplicate, or unsupported entry.")
            names.add(normalized)
        metadata_members = [member for member in members if member.name == "PACKAGE.json" and member.isfile()]
        if len(metadata_members) != 1:
            raise ValueError("Archive must contain one regular root PACKAGE.json.")
        stream = package.extractfile(metadata_members[0])
        if stream is None:
            raise ValueError("PACKAGE.json is unreadable.")
        metadata = __import__("json").loads(stream.read(1024**2 + 1))
        expanded = sum(member.size for member in members if member.isfile())
        if expanded > 2 * 1024**3:
            raise ValueError("Archive expanded size exceeds the catalog bounds.")
    validate(metadata, "scanner-package.schema.json")
    if metadata["expandedBytes"] != expanded or metadata["entryCount"] != len(members):
        raise ValueError("Archive contents do not match PACKAGE.json bounds.")
    expected_repository = f"https://github.com/Entorn-dev/{args.repository}"
    expected_tag = f"v{metadata['version']}"
    expected_asset = f"{expected_repository}/releases/download/{expected_tag}/{archive.name}"
    if metadata["sourceRepository"] != expected_repository or metadata["sourceTag"] != expected_tag:
        raise ValueError("Package source metadata does not match the selected repository and tag.")
    if args.asset_url != expected_asset:
        raise ValueError(f"Asset URL must be {expected_asset}")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    release: dict[str, Any] = {
        "id": metadata["id"], "name": args.name, "version": metadata["version"], "channel": "stable",
        "sourceRepository": metadata["sourceRepository"], "sourceTag": metadata["sourceTag"],
        "platform": metadata["platform"], "architecture": metadata["architecture"],
        "archieVersionRange": metadata["archieVersionRange"], "protocolVersion": metadata["protocolVersion"],
        "assetUrl": args.asset_url, "compressedBytes": archive.stat().st_size,
        "expandedBytes": metadata["expandedBytes"], "entryCount": metadata["entryCount"], "sha256": digest,
        "signingKeyId": metadata["publisherKeyId"], "packageSignature": "",
        "capabilities": sorted(metadata["capabilities"]), "permissions": metadata["permissions"],
        "license": metadata["license"], "releaseNotesUrl": f"{expected_repository}/releases/tag/{expected_tag}",
        "revoked": False
    }
    if release["signingKeyId"] != KEY_ID:
        raise ValueError("Package publisher key does not match the active catalog key.")
    write_json(args.template, release)
    args.signing_input.write_bytes(signing_bytes(release))


def add(args: argparse.Namespace) -> None:
    release = load_json(args.template)
    signature = args.signature.read_text(encoding="ascii").strip()
    decode_signature(signature)
    release["packageSignature"] = signature
    payload = load_json(args.payload) if args.payload.exists() else {
        "schemaVersion": "scanner-catalog/v1", "catalogVersion": args.catalog_version,
        "generatedAt": args.generated_at, "releases": []
    }
    if payload["catalogVersion"] != args.catalog_version:
        raise ValueError("Existing payload has a different catalog version.")
    if any(release_sort_key(item) == release_sort_key(release) for item in payload["releases"]):
        raise ValueError("Release is already present in the catalog.")
    payload["generatedAt"] = args.generated_at
    payload["releases"].append(release)
    payload["releases"].sort(key=release_sort_key)
    validate(payload, "scanner-catalog.schema.json")
    write_json(args.payload, payload)


def base(args: argparse.Namespace) -> None:
    payload = verified_payload(args.catalog)
    if payload["catalogVersion"] == args.catalog_version:
        raise ValueError("The replacement catalog version must differ from the current version.")
    if args.replace_from_template:
        scanner_id = load_json(args.replace_from_template)["id"]
        payload["releases"] = [release for release in payload["releases"] if release["id"] != scanner_id]
    payload["catalogVersion"] = args.catalog_version
    payload["generatedAt"] = args.generated_at
    validate(payload, "scanner-catalog.schema.json")
    write_json(args.payload, payload)


def envelope(args: argparse.Namespace) -> None:
    payload = args.payload.read_bytes()
    signature = args.signature.read_text(encoding="ascii").strip()
    decode_signature(signature)
    write_json(args.output, {"schemaVersion": "signed-scanner-catalog/v1", "keyId": KEY_ID,
                             "payload": base64.b64encode(payload).decode("ascii"), "signature": signature})


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--archive", required=True, type=pathlib.Path)
    prepare_parser.add_argument("--repository", required=True, choices=["entorn-scanner-dotnet", "entorn-scanner-php"])
    prepare_parser.add_argument("--asset-url", required=True)
    prepare_parser.add_argument("--name", required=True)
    prepare_parser.add_argument("--template", required=True, type=pathlib.Path)
    prepare_parser.add_argument("--signing-input", required=True, type=pathlib.Path)
    prepare_parser.set_defaults(function=prepare)
    base_parser = commands.add_parser("base")
    base_parser.add_argument("--catalog", required=True, type=pathlib.Path)
    base_parser.add_argument("--payload", required=True, type=pathlib.Path)
    base_parser.add_argument("--catalog-version", required=True)
    base_parser.add_argument("--generated-at", required=True)
    base_parser.add_argument("--replace-from-template", type=pathlib.Path)
    base_parser.set_defaults(function=base)
    add_parser = commands.add_parser("add")
    add_parser.add_argument("--template", required=True, type=pathlib.Path)
    add_parser.add_argument("--signature", required=True, type=pathlib.Path)
    add_parser.add_argument("--payload", required=True, type=pathlib.Path)
    add_parser.add_argument("--catalog-version", required=True)
    add_parser.add_argument("--generated-at", required=True)
    add_parser.set_defaults(function=add)
    envelope_parser = commands.add_parser("envelope")
    envelope_parser.add_argument("--payload", required=True, type=pathlib.Path)
    envelope_parser.add_argument("--signature", required=True, type=pathlib.Path)
    envelope_parser.add_argument("--output", required=True, type=pathlib.Path)
    envelope_parser.set_defaults(function=envelope)
    arguments = parser.parse_args()
    arguments.function(arguments)


if __name__ == "__main__":
    main()
