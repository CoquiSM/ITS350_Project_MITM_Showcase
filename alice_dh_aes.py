import socket
import random
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BOB_HOST = "172.xxx.xxx.xxx"   # Sebastian (MITM)
BOB_PORT = 5000

MAC_KEY = b"very_secret_mac_key"  # shared only by Alice & Bob

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
        print("[Alice+HASH] Connecting to MITM (Sebastian)...")
        s.connect((BOB_HOST, BOB_PORT))

        # Receive p, g, B
        line = recv_line(s)
        p, g, B = map(int, line.split(","))
        print(f"[Alice+HASH] Received p={p}, g={g}, B={B}")

        # Generate DH public key
        a = random.randint(2, p - 2)
        A = pow(g, a, p)
        send_line(s, str(A))

        shared = pow(B, a, p)
        aes_key = derive_key(shared)

        message = "This is a super secret message"
        plaintext = message.encode()

        # Compute SHA-256 MAC
        digest = hashlib.sha256(MAC_KEY + plaintext).hexdigest()
        print("[Alice+HASH] Digest (hex):", digest)

        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
        ciphertext = cipher.encrypt(plaintext)

        iv_hex = binascii.hexlify(iv).decode()
        ct_hex = binascii.hexlify(ciphertext).decode()

        send_line(s, iv_hex)
        send_line(s, ct_hex)
        send_line(s, digest)

        print("[Alice+HASH] Sent IV, ciphertext, and digest")

        # ---- Wait for Bob's integrity status (via Sebastian) ----
        status = recv_line(s)
        if status == "INTEGRITY_OK":
            print("[Alice DH+AES+HASH] Bob reports: Message integrity VERIFIED ✅")
        elif status == "INTEGRITY_FAIL":
            print("[Alice DH+AES+HASH] Bob reports: Message integrity FAILED ❌")
        else:
            print("[Alice DH+AES+HASH] Bob returned unknown status:", status)

if __name__ == "__main__":
    main()
