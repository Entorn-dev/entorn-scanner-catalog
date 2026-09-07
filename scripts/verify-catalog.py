#!/usr/bin/env python3
import argparse
import pathlib

from catalog_lib import verified_payload

parser = argparse.ArgumentParser()
parser.add_argument("catalog", type=pathlib.Path)
args = parser.parse_args()

payload = verified_payload(args.catalog)
print(f"Verified {len(payload['releases'])} release(s) in {payload['catalogVersion']}.")
