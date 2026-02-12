# test_server.py { USED FOR TESTING PURPOSES }
import socket

HOST = "0.0.0.0"
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Bob TEST] Listening on {HOST}:{PORT}")
    conn, addr = s.accept()
    with conn:
        print("[Bob TEST] Connected by", addr)
        data = conn.recv(1024)
        print("[Bob TEST] Got data:", data)