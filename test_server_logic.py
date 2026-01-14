import socket
import hashlib
import os
import struct
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

HOST = '172.20.159.255'
PORT = 9999
PRE_SHARED_KEY = b'12345678901234567890123456789012' 

def encrypt_file_data(data):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(PRE_SHARED_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def run_test():
    print("--- STARTING TEST ---")
    
    # Create valid dummy file
    file_content = b"This is a secret file content for testing secure transfer."
    original_hash = hashlib.sha256(file_content).hexdigest()
    encrypted_data = encrypt_file_data(file_content)
    encrypted_size = len(encrypted_data)
    filename = "test_upload.txt"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print("Connected to server.")

        # --- STEP 1: HANDSHAKE ---
        nonce = s.recv(16)
        print(f"Received Nonce: {nonce.hex()}")

        # Username: 'android_user', Password: 'secure_password'
        # Server stores SHA256('secure_password')
        pass_hash = hashlib.sha256(b'secure_password').hexdigest()
        
        # Token = SHA256(pass_hash + Nonce)
        token_input = pass_hash.encode('utf-8') + nonce
        auth_token = hashlib.sha256(token_input).hexdigest()
        
        msg = f"android_user|{auth_token}"
        s.sendall(msg.encode('utf-8'))
        
        resp = s.recv(1024).decode('utf-8')
        print(f"Auth Response: {resp}")
        if resp != "AUTH_OK":
            print("Authentication failed!")
            return

        # --- STEP 2: HEADER ---
        header = f"{filename}|{original_hash}|{encrypted_size}"
        s.sendall(header.encode('utf-8'))
        
        resp = s.recv(1024).decode('utf-8')
        print(f"Header Response: {resp}")
        if resp != "READY":
             print("Server not ready!")
             return

        # --- STEP 3: TRANSFER ---
        s.sendall(encrypted_data)
        print("Sent encrypted data.")

        resp = s.recv(1024).decode('utf-8')
        print(f"Final Response: {resp}")
        
        if resp == "SUCCESS":
            print("TEST PASSED!")
        else:
            print("TEST FAILED!")

        s.close()
    except Exception as e:
        print(f"Test Exception: {e}")

if __name__ == "__main__":
    # Give server a moment to start if run immediately after
    time.sleep(1) 
    run_test()
