import socket
import threading
import sqlite3
import hashlib
import os
import struct
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [Thread-%(thread)d] - %(message)s'
)

# Configuration
HOST = '0.0.0.0'
PORT = 9999
DB_NAME = 'secure_vault.db'
PRIVATE_KEY_FILE = 'server_private.pem'
PUBLIC_KEY_FILE = 'server_public.pem'


class SecureVaultServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.load_or_generate_keys()
        self.init_db()

    def load_or_generate_keys(self):
        """Loads RSA keys from file or generates them if missing."""
        if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
             try:
                 with open(PRIVATE_KEY_FILE, "rb") as key_file:
                     self.private_key = serialization.load_pem_private_key(
                         key_file.read(),
                         password=None,
                         backend=default_backend()
                     )
                 with open(PUBLIC_KEY_FILE, "rb") as key_file:
                     self.public_key_bytes = key_file.read()
                 logging.info("RSA Keys loaded successfully.")
             except Exception as e:
                 logging.error(f"Failed to load keys: {e}")
                 # Fallback to generate
                 self.generate_keys()
        else:
             self.generate_keys()

    def generate_keys(self):
        """Generates new RSA 2048-bit key pair."""
        logging.info("Generating new RSA keys...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Save Private
        pem_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(pem_private)
            
        # Save Public
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(self.public_key_bytes)
            
        logging.info("RSA Keys generated and saved.")

    def init_db(self):
        """Initializes the SQLite database with users and audit logs."""
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            
            # Create Users Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )
            ''')
            
            # Create Audit Logs Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT,
                    details TEXT
                )
            ''')
            
            # Insert a demo user if not exists (username: 'android_user', password: 'secure_password')
            # Storing hash of 'secure_password' for simulation
            demo_pass_hash = hashlib.sha256(b'secure_password').hexdigest()
            try:
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ('android_user', demo_pass_hash))
                logging.info("Created demo user 'android_user'")
            except sqlite3.IntegrityError:
                pass # User already exists

            conn.commit()
            conn.close()
            logging.info("Database initialized successfully.")
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")

    def log_audit(self, event_type, details):
        """Logs security events to the database."""
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO audit_logs (event_type, details) VALUES (?, ?)", (event_type, details))
            conn.commit()
            conn.close()
            logging.info(f"AUDIT: {event_type} - {details}")
        except Exception as e:
            logging.error(f"Failed to log audit: {e}")

    def get_user_password_hash(self, username):
        """Retrieves user password hash from DB."""
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
            result = cursor.fetchone()
            conn.close()
            return result[0] if result else None
        except Exception as e:
            logging.error(f"DB Error: {e}")
            return None

    def decrypt_file(self, encrypted_data, session_key):
        """
        Decrypts AES-256-CBC encrypted data using the session key.
        Assumes the first 16 bytes are the IV.
        """
        try:
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            return None

    def verify_integrity(self, file_data, original_hash):
        """Calculates SHA-256 of decrypted data and compares with original hash."""
        calculated_hash = hashlib.sha256(file_data).hexdigest()
        logging.info(f"Calculated Hash: {calculated_hash}")
        logging.info(f"Original Hash:   {original_hash}")
        return calculated_hash == original_hash

    def handle_client(self, client_socket, addr):
        """Main protocol state machine for handling a client."""
        logging.info(f"Connected to {addr}")
        
        try:
            # --- STEP 1: HANDSHAKE & AUTH ---
            
            # 1. Generate Nonce
            nonce = os.urandom(16)
            client_socket.sendall(nonce)
            logging.info("Sent Nonce.")

            # 2. Receive Auth Data (Username|AuthToken) OR Register Command (REGISTER|Username|PasswordHash)
            # Assuming max length for this message is 1024 bytes
            auth_data_bytes = client_socket.recv(1024)
            logging.info(f"DEBUG: Raw auth bytes received: {auth_data_bytes}")
            
            auth_data = auth_data_bytes.decode('utf-8').strip()
            logging.info(f"DEBUG: Decoded auth string: '{auth_data}'")
            
            if not auth_data:
                logging.warning("Empty auth data received.")
                return

            if auth_data == "GET_PUB_KEY":
                client_socket.sendall(self.public_key_bytes)
                logging.info(f"Sent public key to {addr}")
                client_socket.close()
                return

            # --- REGISTRATION HANDLING ---
            if auth_data.startswith("REGISTER|"):
                try:
                    _, reg_username, reg_pass_hash = auth_data.split('|')
                    
                    # Insert into DB
                    conn = sqlite3.connect(DB_NAME)
                    cursor = conn.cursor()
                    try:
                        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (reg_username, reg_pass_hash))
                        conn.commit()
                        logging.info(f"Registered new user: {reg_username}")
                        self.log_audit("USER_REGISTERED", f"User: {reg_username}, IP: {addr[0]}")
                        client_socket.sendall(b"REG_OK")
                    except sqlite3.IntegrityError:
                        logging.warning(f"Registration failed: User {reg_username} already exists.")
                        client_socket.sendall(b"REG_FAIL_EXISTS")
                    finally:
                        conn.close()
                except ValueError:
                    logging.error("Invalid registration format.")
                    client_socket.sendall(b"REG_FAIL_FORMAT")
                
                # Close connection after registration attempt (Client should reconnect to login)
                client_socket.close()
                return
            # -----------------------------

            try:
                if '|' not in auth_data:
                     logging.error(f"Missing delimiter '|' in auth_data: '{auth_data}'")
                     raise ValueError("Missing delimiter")
                
                parts = auth_data.split('|')
                if len(parts) != 2:
                     logging.error(f"Invalid split count {len(parts)} for auth_data: '{auth_data}'")
                     raise ValueError("Invalid split")

                username, client_auth_token = parts
            except ValueError:
                logging.error("Invalid auth format.")
                client_socket.close()
                return

            # 3. Verify Auth Token
            stored_pass_hash = self.get_user_password_hash(username)
            if not stored_pass_hash:
                logging.warning(f"User {username} not found.")
                client_socket.sendall(b"AUTH_FAIL")
                client_socket.close()
                return

            # Server Calculation: SHA256(UserPasswordHash + Nonce)
            # Note: UserPasswordHash is hex string in DB, Nonce is bytes. 
            
            expected_token_input = stored_pass_hash.encode('utf-8') + nonce
            expected_token = hashlib.sha256(expected_token_input).hexdigest()

            if client_auth_token == expected_token:
                client_socket.sendall(b"AUTH_OK")
                logging.info(f"User {username} authenticated successfully.")
                self.log_audit("LOGIN_SUCCESS", f"User: {username}, IP: {addr[0]}")
            else:
                logging.warning(f"Auth token mismatch for {username}.")
                client_socket.sendall(b"AUTH_FAIL")
                self.log_audit("LOGIN_FAILED", f"User: {username}, IP: {addr[0]}")
                client_socket.close()
                return

            # --- STEP 2: COMMAND WAIT ---
            command_data = client_socket.recv(1024).decode('utf-8').strip()
            logging.info(f"Command received: {command_data}")
            
            
            if command_data == "UPLOAD":
                self.handle_upload(client_socket, username)
            elif command_data == "LIST":
                self.handle_list(client_socket, username)
            elif command_data.startswith("DOWNLOAD|"):
                try:
                    parts = command_data.split('|')
                    if len(parts) == 3:
                         _, filename, encrypted_session_key_b64 = parts
                         self.handle_download(client_socket, filename, username, encrypted_session_key_b64)
                    else:
                         # Backward compatibility or error
                         logging.error("DOWNLOAD command missing session key")
                         client_socket.sendall(b"ERROR_ARGS")
                except Exception as e:
                    client_socket.sendall(b"ERROR_ARGS")
            else:
                logging.error(f"Unknown command: {command_data}")
                client_socket.sendall(b"ERROR_CMD")

        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
            self.log_audit("ERROR", str(e))
        finally:
            client_socket.close()

    def handle_upload(self, client_socket, username):
        try:
            client_socket.sendall(b"CMD_OK") # Acknowledge command

            # --- STEP 3: SECURE HEADER ---
            
            # Receive Metadata: Filename|OriginalFileHash|EncryptedFileSize
            # Receive Metadata: Filename|OriginalFileHash|EncryptedFileSize|EncryptedSessionKeyBase64
            header_data = client_socket.recv(8192).decode('utf-8').strip() # Increased buffer for longer header
            filename, original_file_hash, encrypted_file_size_str, enc_session_key_b64 = header_data.split('|')
            encrypted_file_size = int(encrypted_file_size_str)
            
            # Decrypt Session Key
            encrypted_id = base64.b64decode(enc_session_key_b64)
            session_key = self.decrypt_rsa(encrypted_id)
            if not session_key:
                 logging.error("Failed to decrypt session key.")
                 client_socket.sendall(b"ERROR_KEY")
                 return

            logging.info(f"Header Received: File={filename}, Size={encrypted_file_size}")
            client_socket.sendall(b"READY")

            # --- STEP 4: ENCRYPTED TRANSFER ---
            
            # Receive raw encrypted bytes
            received_data = b""
            remaining = encrypted_file_size
            while remaining > 0:
                chunk = client_socket.recv(min(4096, remaining))
                if not chunk:
                    break
                received_data += chunk
                remaining -= len(chunk)

            if len(received_data) != encrypted_file_size:
                logging.error("Incomplete file transfer.")
                self.log_audit("TRANSFER_ERROR", "Incomplete data received.")
                return

            # Decrypt
            decrypted_data = self.decrypt_file(received_data, session_key)
            if decrypted_data is None:
                logging.error("Decryption failed.")
                self.log_audit("DECRYPTION_FAIL", f"File: {filename}")
                client_socket.sendall(b"ERROR_DECRYPT")
                return

            # Integrity Check
            if self.verify_integrity(decrypted_data, original_file_hash):
                # Save to disk
                user_dir = os.path.join("uploads", username)
                os.makedirs(user_dir, exist_ok=True)
                save_path = os.path.join(user_dir, filename)
                
                with open(save_path, "wb") as f:
                    f.write(decrypted_data)
                
                logging.info(f"File saved to {save_path}")
                self.log_audit("INTEGRITY_VERIFIED", f"File: {filename} uploaded by {username}")
                client_socket.sendall(b"SUCCESS")
            else:
                logging.error("Integrity check failed!")
                self.log_audit("TAMPERING_DETECTED", f"File: {filename}, User: {username}")
                client_socket.sendall(b"INTEGRITY_FAIL")
        except Exception as e:
            logging.error(f"Upload error: {e}")
            client_socket.sendall(b"ERROR_UPLOAD")

    def handle_list(self, client_socket, username):
        try:
            user_dir = os.path.join("uploads", username)
            if not os.path.exists(user_dir):
                client_socket.sendall(b"0")
                return

            files = [f for f in os.listdir(user_dir) if os.path.isfile(os.path.join(user_dir, f))]
            count = len(files)
            client_socket.sendall(f"{count}".encode('utf-8'))
            
            if count > 0:
                client_socket.sendall(b"\n") # Delimiter for count
                
                file_list_str = "|".join(files)
                client_socket.sendall((file_list_str + "\n").encode('utf-8'))
                
            logging.info(f"Sent list of {count} files for user {username}.")
        except Exception as e:
            logging.error(f"List error: {e}")

    def decrypt_rsa(self, encrypted_data):
        """Decrypts data using the server's private key."""
        try:
            return self.private_key.decrypt(
                encrypted_data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            logging.error(f"RSA Decryption failed: {e}")
            return None

    def handle_download(self, client_socket, filename, username, encrypted_session_key_b64):
        try:
            # Security: Prevent directory traversal
            filename = os.path.basename(filename) 
            user_dir = os.path.join("uploads", username)
            file_path = os.path.join(user_dir, filename)
            if not os.path.exists(file_path):
                logging.error(f"File not found: {filename}")
                client_socket.sendall(b"ERROR_NOT_FOUND")
                return

            # Read file
            with open(file_path, "rb") as f:
                file_data = f.read()

            # Encrypt for transport
            # Use same key/iv generation as client? 
            # Client: IV + Encrypted.
            # Server: IV + Encrypted.
            
            # Decrypt Session Key
            enc_session_key = base64.b64decode(encrypted_session_key_b64)
            session_key = self.decrypt_rsa(enc_session_key)
            if not session_key:
                 logging.error("Failed to decrypt session key for download.")
                 client_socket.sendall(b"ERROR_KEY")
                 return

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(file_data) + padder.finalize()
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            final_payload = iv + encrypted_data
            
            # Send Size
            size = len(final_payload)
            client_socket.sendall(f"{size}".encode('utf-8'))
            client_socket.sendall(b"\n") # Delimiter
            
            # Send Data
            client_socket.sendall(final_payload)
            logging.info(f"Sent file {filename} ({size} bytes encrypted)")
            
        except Exception as e:
            logging.error(f"Download error: {e}")
            client_socket.sendall(b"ERROR_DOWNLOAD")

    def start(self):
        """Starts the main server loop."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        logging.info(f"Server listening on {self.host}:{self.port}")

        try:
            while True:
                print("DEBUG: Waiting for incoming connections...", flush=True)
                client_sock, addr = server.accept()
                print(f"DEBUG: Accepted connection from {addr}", flush=True)
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr)
                )
                client_handler.start()
        except KeyboardInterrupt:
            logging.info("Server stopping...")
        finally:
            server.close()

if __name__ == "__main__":
    server = SecureVaultServer(HOST, PORT)
    server.start()
