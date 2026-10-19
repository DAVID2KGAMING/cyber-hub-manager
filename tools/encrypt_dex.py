#!/usr/bin/env python3
"""
Encrypts a compiled classes.dex with AES-256-GCM so it can be shipped as a
protected asset and loaded at runtime by DexProtector.java.

Requires: pip install cryptography

Usage:
    python tools/encrypt_dex.py <path-to-classes.dex> <output-asset-path> [hex_key]

Example:
    python tools/encrypt_dex.py \\
        core/build/intermediates/dex/release/mergeDexRelease/classes.dex \\
        app/src/main/assets/core.enc \\
        00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEE

The hex key MUST match AES_KEY_HEX in DexProtector.java exactly (64 hex
chars = 32 bytes = AES-256). Generate a real random one with:
    python -c "import secrets; print(secrets.token_hex(32))"
and update both this command and DexProtector.java together.
"""
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Missing dependency. Run: pip install cryptography --break-system-packages")

DEFAULT_KEY_HEX = "6b45548bbe17bc3460b9dc9b0d0939dbd3fcc8a65990bf7332c98b6cbf95ab7d"
# This MUST stay identical to DexProtector.AES_KEY_HEX in the app. If you ever
# rotate this key, generate a new one with:
#   python -c "import secrets; print(secrets.token_hex(32))"
# and update BOTH this value and DexProtector.AES_KEY_HEX together.


def encrypt_dex(dex_path: Path, out_path: Path, key_hex: str) -> None:
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        sys.exit(f"Key must be 32 bytes (64 hex chars), got {len(key)} bytes")

    plaintext = dex_path.read_bytes()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt() returns ciphertext with the 16-byte GCM tag already
    # appended at the end — same layout javax.crypto.Cipher produces in GCM mode.
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Layout: 12-byte nonce || ciphertext || 16-byte GCM tag
    # (matches what DexProtector.decrypt() expects: nonce + (ciphertext+tag))
    out_path.write_bytes(nonce + ciphertext_and_tag)
    print(f"Encrypted {dex_path} ({len(plaintext)} bytes) -> {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    dex_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    key_hex = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_KEY_HEX
    if not dex_path.is_file():
        sys.exit(f"Not found: {dex_path}")
    encrypt_dex(dex_path, out_path, key_hex)
