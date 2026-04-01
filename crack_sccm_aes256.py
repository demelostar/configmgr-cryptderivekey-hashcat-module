#!/usr/bin/env python3
"""Simple SCCM CryptDeriveKey AES-256 cracker.

Supports hash formats:
1) $sccm$aes256$<header32><algid8><header8><payload32>
2) $sccm$aes256$<header32>$<algid8>$<header8>$<payload32>
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

PREFIX = "$sccm$aes256$"
ALG_ID_AES256_LE_HEX = "10660000"  # 0x00006610 in little-endian
# Same 16-byte plaintext block used by the original hashcat kernels
PT_BLOCK = bytes.fromhex("3c003f0078006d006c00200076006500")


@dataclass
class ParsedHash:
    original: str
    header1: str
    algid: str
    header2: str
    payload: bytes


def parse_hash(line: str) -> ParsedHash:
    h = line.strip()

    if not h.startswith(PREFIX):
        raise ValueError("Unsupported hash prefix (expected $sccm$aes256$)")

    tail = h[len(PREFIX) :]

    # Canonical tokenized format
    if "$" in tail:
        parts = tail.split("$")
        if len(parts) != 4:
            raise ValueError("Invalid tokenized hash format")
        header1, algid, header2, payload_hex = parts
    else:
        # Compact format: header32 + algid8 + header8 + payload32 = 80 hex chars
        if len(tail) != 80:
            raise ValueError("Invalid compact hash length (expected 80 hex chars)")
        header1 = tail[0:32]
        algid = tail[32:40]
        header2 = tail[40:48]
        payload_hex = tail[48:80]

    for name, token, expected_len in (
        ("header1", header1, 32),
        ("algid", algid, 8),
        ("header2", header2, 8),
        ("payload", payload_hex, 32),
    ):
        if len(token) != expected_len:
            raise ValueError(f"Invalid {name} length")
        try:
            bytes.fromhex(token)
        except ValueError as exc:
            raise ValueError(f"{name} is not valid hex") from exc

    if algid.lower() != ALG_ID_AES256_LE_HEX:
        raise ValueError(
            f"Hash ALG_ID is {algid}, expected {ALG_ID_AES256_LE_HEX} for AES-256"
        )

    return ParsedHash(
        original=h,
        header1=header1.lower(),
        algid=algid.lower(),
        header2=header2.lower(),
        payload=bytes.fromhex(payload_hex),
    )


def derive_aes256_key(password: str) -> bytes:
    pwd_utf16le = password.encode("utf-16le")
    sha1_pwd = hashlib.sha1(pwd_utf16le).digest()

    buf = sha1_pwd + (b"\x00" * (64 - len(sha1_pwd)))

    ipad = bytes(b ^ 0x36 for b in buf)
    opad = bytes(b ^ 0x5C for b in buf)

    a = hashlib.sha1(ipad).digest()
    b = hashlib.sha1(opad).digest()

    return (a + b)[:32]


def aes256_encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    # Try PyCryptodome first
    try:
        from Crypto.Cipher import AES  # type: ignore

        return AES.new(key, AES.MODE_ECB).encrypt(plaintext)
    except Exception:
        pass

    # Fallback to openssl CLI
    with tempfile.NamedTemporaryFile(delete=False) as in_f:
        in_f.write(plaintext)
        in_path = Path(in_f.name)

    out_path = in_path.with_suffix(".out")

    try:
        cmd = [
            "openssl",
            "enc",
            "-aes-256-ecb",
            "-K",
            key.hex(),
            "-nopad",
            "-nosalt",
            "-in",
            str(in_path),
            "-out",
            str(out_path),
        ]
        subprocess.run(cmd, check=True, capture_output=True)

        return out_path.read_bytes()
    finally:
        in_path.unlink(missing_ok=True)
        out_path.unlink(missing_ok=True)


def iter_hashes(single_hash: Optional[str], hash_file: Optional[Path]) -> Iterable[str]:
    if single_hash:
        yield single_hash.strip()
        return

    assert hash_file is not None
    for line in hash_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        yield line


def crack_one(parsed: ParsedHash, wordlist: Path, encoding: str) -> Optional[str]:
    with wordlist.open("r", encoding=encoding, errors="ignore") as f:
        for line in f:
            candidate = line.rstrip("\r\n")
            if candidate == "":
                continue

            key = derive_aes256_key(candidate)
            ct = aes256_encrypt_block(key, PT_BLOCK)

            if ct == parsed.payload:
                return candidate

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crack SCCM CryptDeriveKey AES-256 hashes with a wordlist"
    )
    parser.add_argument("-H", "--hash", dest="single_hash", help="Single hash string")
    parser.add_argument("-f", "--hash-file", type=Path, help="File containing hashes")
    parser.add_argument("-w", "--wordlist", type=Path, required=True, help="Wordlist file")
    parser.add_argument(
        "--encoding", default="utf-8", help="Wordlist encoding (default: utf-8)"
    )
    args = parser.parse_args()

    if not args.single_hash and not args.hash_file:
        parser.error("Provide --hash or --hash-file")

    if args.single_hash and args.hash_file:
        parser.error("Use either --hash or --hash-file, not both")

    if not args.wordlist.exists():
        parser.error(f"Wordlist not found: {args.wordlist}")

    found_any = False

    for raw in iter_hashes(args.single_hash, args.hash_file):
        try:
            parsed = parse_hash(raw)
        except ValueError as exc:
            print(f"[!] Invalid hash: {raw}\n    -> {exc}")
            continue

        password = crack_one(parsed, args.wordlist, args.encoding)

        if password is None:
            print(f"[-] NOT FOUND: {parsed.original}")
        else:
            found_any = True
            print(f"[+] FOUND: {parsed.original}:{password}")

    return 0 if found_any else 1


if __name__ == "__main__":
    raise SystemExit(main())
