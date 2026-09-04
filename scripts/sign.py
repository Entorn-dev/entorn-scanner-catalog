#!/usr/bin/env python3
import argparse
import pathlib

from catalog_lib import sign

parser = argparse.ArgumentParser(description="Sign exact bytes with the offline Entorn ECDSA P-256 key.")
parser.add_argument("--private-key", required=True, type=pathlib.Path)
parser.add_argument("--input", required=True, type=pathlib.Path)
parser.add_argument("--output", required=True, type=pathlib.Path)
args = parser.parse_args()

args.output.write_text(sign(args.private_key, args.input) + "\n", encoding="ascii")
print(args.output)
