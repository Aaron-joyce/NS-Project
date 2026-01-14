import socket
import hashlib
import os

HOST = '127.0.0.1'
PORT = 9999
PRE_SHARED_KEY = b'12345678901234567890123456789012'

def run_test():
    print("--- STARTING LIST TEST ---")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print("Connected to server.")

        # --- HANDSHAKE ---
        nonce = s.recv(16)
        pass_hash = hashlib.sha256(b'secure_password').hexdigest()
        token_input = pass_hash.encode('utf-8') + nonce
        auth_token = hashlib.sha256(token_input).hexdigest()
        msg = f"android_user|{auth_token}"
        s.sendall(msg.encode('utf-8'))
        
        resp = s.recv(1024).decode('utf-8')
        if "AUTH_OK" not in resp:
            print(f"Authentication failed: {resp}")
            return
        print("Authenticated.")

        # --- LIST COMMAND ---
        s.sendall(b"LIST")
        
        # Read response using file object to mimic readline() accurately
        # Note: socket.recv might read chunks. makefile wraps it.
        f = s.makefile('r', encoding='utf-8')
        
        # Read Count
        print("Waiting for count...")
        count_raw = f.readline()
        print(f"Raw Count Line: {repr(count_raw)}")
        
        if not count_raw:
             print("Received empty response for count.")
             return

        count = int(count_raw.strip())
        print(f"Count: {count}")
        
        if count > 0:
            print("Waiting for file list...")
            files_raw = f.readline()
            print(f"Raw File List Line: {repr(files_raw)}")
            if files_raw:
                print(f"Files: {files_raw.split('|')}")
            else:
                print("No file list line received (EOF?)")

        s.close()

    except Exception as e:
        print(f"Test Exception: {e}")

if __name__ == "__main__":
    run_test()
