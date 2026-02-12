import socket
import random
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

MITM_HOST = "0.0.0.0"
MITM_PORT = 5000

BOB_HOST = "xxx.xxx.xxx.131"
BOB_PORT = 5000

def recv_line(conn):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Closed")
        data += chunk
    return data.decode().strip()

def send_line(conn, text):
    conn.sendall((text + "\n").encode())

def derive_key(shared):
    shared_bytes = shared.to_bytes((shared.bit_length() + 7)//8, "big")
    return hashlib.sha256(shared_bytes).digest()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((MITM_HOST, MITM_PORT))
        listener.listen(1)
        print("[MITM+HASH] Waiting for Alice...")

        alice_conn, alice_addr = listener.accept()
        with alice_conn:
            print("[MITM+HASH] Alice connected:", alice_addr)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_conn:
                bob_conn.connect((BOB_HOST, BOB_PORT))
                print("[MITM+HASH] Connected to Bob")

                # Step 1 — get p,g,B from Bob
                line = recv_line(bob_conn)
                p_str, g_str, B_orig_str = line.split(",")
                p, g, B_orig = int(p_str), int(g_str), int(B_orig_str)

                # MITM fake key for Alice
                sA = random.randint(2, p - 2)
                B_for_Alice = pow(g, sA, p)
                send_line(alice_conn, f"{p},{g},{B_for_Alice}")

                A_from_Alice = int(recv_line(alice_conn))

                # MITM fake key for Bob
                sB = random.randint(2, p - 2)
                A_for_Bob = pow(g, sB, p)
                send_line(bob_conn, str(A_for_Bob))

                # Derive keys
                key_A = derive_key(pow(A_from_Alice, sA, p))
                key_B = derive_key(pow(B_orig, sB, p))

                # Get from Alice: IV, ciphertext, digest
                iv_hex = recv_line(alice_conn)
                ct_hex = recv_line(alice_conn)
                digest_hex = recv_line(alice_conn)

                iv_A = binascii.unhexlify(iv_hex)
                ct_A = binascii.unhexlify(ct_hex)

                # Decrypt with Alice’s key
                cipher_A = AES.new(key_A, AES.MODE_CFB, iv=iv_A)
                plaintext = cipher_A.decrypt(ct_A).decode(errors="replace")

                print("[MITM+HASH] Original plaintext:", plaintext)

                # Modify message
                modified = plaintext + " [MODIFIED BY SEBASTIAN]"
                modified_bytes = modified.encode()

                # Encrypt for Bob
                iv_B = get_random_bytes(16)
                cipher_B = AES.new(key_B, AES.MODE_CFB, iv=iv_B)
                ct_B = cipher_B.encrypt(modified_bytes)

                # Send modified message + OLD digest to Bob
                send_line(bob_conn, binascii.hexlify(iv_B).decode())
                send_line(bob_conn, binascii.hexlify(ct_B).decode())
                send_line(bob_conn, digest_hex)

                print("[MITM+HASH] Forwarded modified message with WRONG digest --> Bob will detect tampering")

                # ---- Get Bob's integrity status ----
                status = recv_line(bob_conn)
                print("[MITM+HASH] Bob's status:", status)

                # ---- Forward status back to Alice ----
                send_line(alice_conn, status)
                print("[MITM+HASH] Forwarded status back to Alice.")

if __name__ == "__main__":
    main()