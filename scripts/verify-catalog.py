#!/usr/bin/env python3
import argparse
import base64
import pathlib

from catalog_lib import KEY_ID, load_json, release_sort_key, signing_bytes, validate, verify

parser = argparse.ArgumentParser()
parser.add_argument("catalog", type=pathlib.Path)
args = parser.parse_args()

envelope = load_json(args.catalog)
validate(envelope, "signed-scanner-catalog.schema.json")
if envelope["keyId"] != KEY_ID:
    raise ValueError("Catalog uses an unknown key ID.")
payload_bytes = base64.b64decode(envelope["payload"], validate=True)
verify(payload_bytes, envelope["signature"])
payload = __import__("json").loads(payload_bytes)
validate(payload, "scanner-catalog.schema.json")
if payload["releases"] != sorted(payload["releases"], key=release_sort_key):
    raise ValueError("Catalog releases are not deterministically ordered.")
for release in payload["releases"]:
    if release["signingKeyId"] != KEY_ID or release["capabilities"] != sorted(release["capabilities"]):
        raise ValueError("Release key or capability ordering is invalid.")
    verify(signing_bytes(release), release["packageSignature"])
print(f"Verified {len(payload['releases'])} release(s) in {payload['catalogVersion']}.")
