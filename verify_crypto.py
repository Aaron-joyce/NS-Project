
import socket
import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

HOST = '127.0.0.1'
PORT = 9999
USERNAME = 'testval_user'
PASSWORD = 'test_password'
# SHA256 of password
PASS_HASH = hashlib.sha256(PASSWORD.encode()).hexdigest()

def get_pub_key():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # Read Nonce first
        s.recv(16)
        
        s.sendall(b"GET_PUB_KEY")
        # Read all
        key_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            key_data += chunk
    
    return serialization.load_pem_public_key(key_data, backend=default_backend())

def register():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # Receive Nonce (ignore)
        s.recv(16)
        msg = f"REGISTER|{USERNAME}|{PASS_HASH}"
        s.sendall(msg.encode())
        resp = s.recv(1024)
        print(f"Register Response: {resp.decode()}")

def login_and_get_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    nonce = s.recv(16)
    
    token_input = PASS_HASH.encode() + nonce
    token = hashlib.sha256(token_input).hexdigest()
    
    auth_msg = f"{USERNAME}|{token}"
    s.sendall(auth_msg.encode())
    resp = s.recv(1024)
    if resp == b"AUTH_OK":
        return s
    else:
        print(f"Auth Failed: {resp}")
        s.close()
        return None

def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()

def test_flow():
    # 1. Register
    register()
    
    # 2. Get Pub Key
    pub_key = get_pub_key()
    print("Got Public Key")
    
    # 3. Upload
    s = login_and_get_socket()
    if not s: return
    
    s.sendall(b"UPLOAD")
    resp = s.recv(1024) # CMD_OK
    
    session_key = os.urandom(32)
    enc_session_key = pub_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    enc_session_key_b64 = base64.b64encode(enc_session_key).decode()
    
    file_content = b"Hello Secure World! This is a test file."
    original_hash = hashlib.sha256(file_content).hexdigest()
    encrypted_file = encrypt_aes(file_content, session_key)
    
    filename = "test_hybrid.txt"
    header = f"{filename}|{original_hash}|{len(encrypted_file)}|{enc_session_key_b64}"
    s.sendall(header.encode())
    
    resp = s.recv(1024) # READY
    s.sendall(encrypted_file)
    
    resp = s.recv(1024) # SUCCESS
    print(f"Upload Response: {resp.decode()}")
    s.close()
    
    # 4. Download
    s = login_and_get_socket()
    if not s: return
    
    session_key_dl = os.urandom(32)
    enc_session_key_dl = pub_key.encrypt(
        session_key_dl,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    enc_session_key_dl_b64 = base64.b64encode(enc_session_key_dl).decode()
    
    cmd = f"DOWNLOAD|{filename}|{enc_session_key_dl_b64}"
    s.sendall(cmd.encode())
    
    # Read Size (byte by byte to avoid over-reading into data)
    size_buffer = b""
    while True:
        b = s.recv(1)
        if b == b'\n': break
        size_buffer += b
        
    size = int(size_buffer.decode())
    print(f"Download Size: {size}")
    
    encrypted_data = b""
    while len(encrypted_data) < size:
        chunk = s.recv(4096)
        if not chunk: break
        encrypted_data += chunk
        
    decrypted_content = decrypt_aes(encrypted_data, session_key_dl)
    print(f"Downloaded Content: {decrypted_content.decode()}")
    
    if decrypted_content == file_content:
        print("VERIFICATION SUCCESSFUL!")
    else:
        print("VERIFICATION FAILED!")
        
    s.close()

if __name__ == "__main__":
    try:
        test_flow()
    except Exception as e:
        print(f"Test Failed: {e}")
