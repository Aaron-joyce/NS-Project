import socket
import sys

def test_connection(ip, port):
    print(f"Attempting to connect to {ip}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        print("✅ Connection verified! Server accepted connection.")
        
        # Read the nonce to confirm protocol is alive
        nonce = s.recv(16)
        if len(nonce) == 16:
             print(f"✅ Received nonce: {nonce.hex()}")
        else:
             print("⚠️ Connected but didn't receive full nonce.")
             
        s.close()
    except Exception as e:
        print(f"❌ Connection FAILED: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_conn.py <IP_ADDRESS>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    test_connection(target_ip, 9999)
