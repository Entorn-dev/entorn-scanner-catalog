from __future__ import annotations

import base64
import json
import pathlib
import struct
import subprocess
import tempfile
from typing import Any

import jsonschema
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas" / "v1"
KEYS = ROOT / "keys"
KEY_ID = "entorn-scanner-signing-2026-01"
KEY_PATH = KEYS / f"{KEY_ID}-public.pem"


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, separators=(",", ": ")), encoding="utf-8")


def validate(value: Any, schema_name: str) -> None:
    schemas = {load_json(path)["$id"]: load_json(path) for path in SCHEMAS.glob("*.schema.json")}
    schema = load_json(SCHEMAS / schema_name)
    registry = Registry().with_resources(
        (identifier, Resource.from_contents(contents)) for identifier, contents in schemas.items())
    jsonschema.Draft202012Validator(schema, registry=registry,
        format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER).validate(value)


def decode_signature(value: str) -> bytes:
    signature = base64.b64decode(value, validate=True)
    if len(signature) != 64:
        raise ValueError("An ECDSA P-256 signature must be exactly 64 P1363 bytes.")
    return signature


def signing_bytes(release: dict[str, Any]) -> bytes:
    result = bytearray()
    for field in ("id", "version", "platform", "architecture", "sha256"):
        value = release[field].encode("utf-8")
        result.extend(struct.pack(">I", len(value)))
        result.extend(value)
    return bytes(result)


def _der_integer(value: bytes) -> bytes:
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return b"\x02" + bytes([len(value)]) + value


def p1363_to_der(signature: bytes) -> bytes:
    body = _der_integer(signature[:32]) + _der_integer(signature[32:])
    return b"\x30" + bytes([len(body)]) + body


def der_to_p1363(signature: bytes) -> bytes:
    position = 0

    def take(expected: int) -> bytes:
        nonlocal position
        if position + 2 > len(signature) or signature[position] != expected:
            raise ValueError("OpenSSL returned an invalid ECDSA signature.")
        length = signature[position + 1]
        position += 2
        if length & 0x80:
            count = length & 0x7f
            length = int.from_bytes(signature[position:position + count], "big")
            position += count
        value = signature[position:position + length]
        position += length
        return value

    sequence = take(0x30)
    if position != len(signature):
        raise ValueError("OpenSSL returned trailing signature bytes.")
    signature = sequence
    position = 0
    r = take(0x02).lstrip(b"\0")
    s = take(0x02).lstrip(b"\0")
    if position != len(signature) or len(r) > 32 or len(s) > 32:
        raise ValueError("OpenSSL returned an invalid P-256 signature.")
    return r.rjust(32, b"\0") + s.rjust(32, b"\0")


def sign(private_key: pathlib.Path, content: pathlib.Path) -> str:
    with tempfile.NamedTemporaryFile() as output:
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private_key),
                        "-out", output.name, str(content)], check=True)
        output.seek(0)
        return base64.b64encode(der_to_p1363(output.read())).decode("ascii")


def verify(content: bytes, signature: str, public_key: pathlib.Path = KEY_PATH) -> None:
    with tempfile.NamedTemporaryFile() as data, tempfile.NamedTemporaryFile() as sig:
        data.write(content)
        data.flush()
        sig.write(p1363_to_der(decode_signature(signature)))
        sig.flush()
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key),
                                 "-signature", sig.name, data.name], capture_output=True, text=True)
        if result.returncode != 0:
            raise ValueError("Signature verification failed.")


def release_sort_key(release: dict[str, Any]) -> tuple[str, str, str]:
    return release["id"], release["version"], release["sha256"]
