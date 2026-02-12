import socket
import random
import hashlib
import binascii
from Crypto.Cipher import AES

HOST = "0.0.0.0"
PORT = 5000

p = 23
g = 5

MAC_KEY = b"very_secret_mac_key"

def recv_line(conn):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data.decode().strip()

def send_line(conn, text):
    conn.sendall((text + "\n").encode())

def derive_key(shared):
    shared_bytes = shared.to_bytes((shared.bit_length() + 7)//8, "big")
    return hashlib.sha256(shared_bytes).digest()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("[Bob+HASH] Listening...")

        conn, addr = s.accept()
        with conn:
            print("[Bob+HASH] Connected:", addr)

            # ---- Diffie–Hellman step ----
            b = random.randint(2, p - 2)
            B = pow(g, b, p)
            send_line(conn, f"{p},{g},{B}")

            A = int(recv_line(conn))
            shared = pow(A, b, p)
            aes_key = derive_key(shared)

            # ---- Receive IV, ciphertext, and digest ----
            iv_hex = recv_line(conn)
            ct_hex = recv_line(conn)
            recv_digest = recv_line(conn)

            iv = binascii.unhexlify(iv_hex)
            ct = binascii.unhexlify(ct_hex)

            # ---- Decrypt ----
            cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
            plaintext_bytes = cipher.decrypt(ct)
            plaintext = plaintext_bytes.decode(errors="replace")

            print("[Bob+HASH] Decrypted:", plaintext)

            # ---- Recompute integrity (MAC_KEY || plaintext) ----
            recomputed = hashlib.sha256(MAC_KEY + plaintext_bytes).hexdigest()
            print("[Bob+HASH] Received digest:", recv_digest)
            print("[Bob+HASH] Recomputed digest:", recomputed)

            if recomputed == recv_digest:
                print("[Bob DH+AES+HASH] INTEGRITY CHECK: OK ✅ (message not altered)")
                status = "INTEGRITY_OK"
            else:
                print("[Bob DH+AES+HASH] INTEGRITY CHECK: FAILED ❌ (message was modified!)")
                status = "INTEGRITY_FAIL"

            # ---- Send status back to Alice (through Sebastian) ----
            send_line(conn, status)
            print("[Bob DH+AES+HASH] Sent status back to client:", status)

if __name__ == "__main__":
    main()