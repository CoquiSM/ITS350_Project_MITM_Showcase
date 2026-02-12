import socket

BOB_IP = "172.xxx.xxx.xxx"   # <-- Bob's IP
BOB_PORT = 5000 # Can be Any, port 5000 happens to be universally used for development

def main():
    # Create TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[Alice] Connecting to Bob at {BOB_IP}:{BOB_PORT} ...")
        s.connect((BOB_IP, BOB_PORT))

        message = "This is a super secret message."
        print("[Alice] Sending:", message)

        s.sendall(message.encode())
        print("[Alice] Done.")

if __name__ == "__main__":
    main()