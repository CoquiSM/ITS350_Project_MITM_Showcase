import socket

HOST = "0.0.0.0"   # listen on all interfaces
PORT = 5000        # port Bob will listen on

def main():
    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[Bob] Listening on {HOST}:{PORT} ...")

        conn, addr = s.accept()
        with conn:
            print("[Bob] Connected by", addr)

            # Receive up to 1024 bytes
            data = conn.recv(1024)
            if not data:
                print("[Bob] No data received.")
                return

            message = data.decode(errors="replace")
            print("[Bob] Received message:", message)

if __name__ == "__main__":
    main()