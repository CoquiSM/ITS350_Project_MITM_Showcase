# bob_dh_aes.py
import socket
import random
import hashlib
import binascii
from Crypto.Cipher import AES

HOST = "0.0.0.0"
PORT = 5000

p = 23
g = 5

def recv_line(conn):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed while reading line")
        data += chunk
    return data.decode().strip()

def send_line(conn, text: str):
    conn.sendall((text + "\n").encode())

def derive_aes_key(shared_int: int) -> bytes:
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    return hashlib.sha256(shared_bytes).digest()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Bob DH+AES] Listening on {HOST}:{PORT} ...")
        conn, addr = s.accept()
        with conn:
            print("[Bob DH+AES] Connected by", addr)

            b = random.randint(2, p - 2)
            B = pow(g, b, p)
            print(f"[Bob DH+AES] Using p={p}, g={g}")
            print(f"[Bob DH+AES] Private b={b}, Public B={B}")

            send_line(conn, f"{p},{g},{B}")

            A_str = recv_line(conn)
            A = int(A_str)
            print("[Bob DH+AES] Received A:", A)

            shared = pow(A, b, p)
            print("[Bob DH+AES] DH shared integer =", shared)

            aes_key = derive_aes_key(shared)
            print("[Bob DH+AES] AES key (hex) =", aes_key.hex())

            iv_hex = recv_line(conn)
            ct_hex = recv_line(conn)
            print("[Bob DH+AES] IV (hex):", iv_hex)
            print("[Bob DH+AES] Ciphertext (hex):", ct_hex)

            iv = binascii.unhexlify(iv_hex)
            ciphertext = binascii.unhexlify(ct_hex)

            cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
            plaintext_bytes = cipher.decrypt(ciphertext)

            try:
                plaintext = plaintext_bytes.decode()
            except UnicodeDecodeError:
                plaintext = plaintext_bytes.decode(errors="replace")

            print("[Bob DH+AES] Decrypted message:", plaintext)

if __name__ == "__main__":
    main()