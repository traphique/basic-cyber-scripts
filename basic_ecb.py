import socket

HOST = "recruit.osiris.sh"
PORT = 41001

def send_option(s, option: int):
    s.sendall(f"{option:02d}".encode())          # exactly 2 bytes, e.g. b"01"

def send_length_and_data(s, data: bytes):
    length_str = f"{len(data):05d}".encode()     # e.g. b"00032"
    s.sendall(length_str)
    s.sendall(data)                               # the actual padding

def read_response(s) -> bytes:
    # Read 4 ASCII digits length
    len_str = s.recv(4).decode()
    if not len_str.isdigit():
        raise ValueError(f"Bad length prefix: {len_str!r}")
    ct_len = int(len_str)
    
    # Read exactly ct_len bytes
    ciphertext = b""
    while len(ciphertext) < ct_len:
        chunk = s.recv(ct_len - len(ciphertext))
        if not chunk:
            raise ConnectionError("Server closed connection")
        ciphertext += chunk
    return ciphertext

def query(padding: str | bytes) -> bytes:
    if isinstance(padding, str):
        padding = padding.encode()
        
    with socket.create_connection((HOST, PORT)) as s:
        send_option(s, 1)                       # option 1 = Get the Flag
        send_length_and_data(s, padding)
        return read_response(s)

# ────────────────────────────────────────────────
# Try it
if __name__ == "__main__":
    pad = "A" * 32
    ct = query(pad)
    print(f"Length: {len(ct)} bytes ({len(ct)//16} blocks)")
    print("Hex: " + ct.hex())
    print("ASCII (printable only): " + "".join(c if 32 <= c <= 126 else '.' for c in ct))
