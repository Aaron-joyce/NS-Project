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

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [Thread-%(thread)d] - %(message)s'
)

# Configuration
HOST = '0.0.0.0'
PORT = 9999
DB_NAME = 'secure_vault.db'
# HARDCODED AES KEY (For Demonstration Only - DO NOT USE IN PRODUCTION)
# Key must be 32 bytes for AES-256
PRE_SHARED_KEY = b'12345678901234567890123456789012' 

class SecureVaultServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.init_db()

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

    def decrypt_file(self, encrypted_data):
        """
        Decrypts AES-256-CBC encrypted data.
        Assumes the first 16 bytes are the IV.
        """
        try:
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            cipher = Cipher(algorithms.AES(PRE_SHARED_KEY), modes.CBC(iv), backend=default_backend())
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

            # 2. Receive Auth Data (Username|AuthToken)
            # Assuming max length for this message is 1024 bytes
            auth_data_bytes = client_socket.recv(1024)
            logging.info(f"DEBUG: Raw auth bytes received: {auth_data_bytes}")
            
            auth_data = auth_data_bytes.decode('utf-8').strip()
            logging.info(f"DEBUG: Decoded auth string: '{auth_data}'")
            
            if not auth_data:
                logging.warning("Empty auth data received.")
                return

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
            # Protocol: SHA256(UserPasswordHash(as hex string) + Nonce(bytes))?
            # Or SHA256(UserPasswordHash(bytes) + Nonce(bytes))?
            # Let's assume UserPasswordHash is treated as string bytes for simplicity in concatenation, 
            # or usually, we decode the hex.
            # Let's stick to: SHA256( hex_string_of_hash.encode() + nonce_bytes )
            
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
                self.handle_list(client_socket)
            elif command_data.startswith("DOWNLOAD|"):
                _, filename = command_data.split('|', 1)
                self.handle_download(client_socket, filename)
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
            header_data = client_socket.recv(4096).decode('utf-8').strip()
            filename, original_file_hash, encrypted_file_size_str = header_data.split('|')
            encrypted_file_size = int(encrypted_file_size_str)
            
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
            decrypted_data = self.decrypt_file(received_data)
            if decrypted_data is None:
                logging.error("Decryption failed.")
                self.log_audit("DECRYPTION_FAIL", f"File: {filename}")
                client_socket.sendall(b"ERROR_DECRYPT")
                return

            # Integrity Check
            if self.verify_integrity(decrypted_data, original_file_hash):
                # Save to disk
                save_path = f"uploads/{filename}"
                os.makedirs("uploads", exist_ok=True)
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

    def handle_list(self, client_socket):
        try:
            if not os.path.exists("uploads"):
                client_socket.sendall(b"0")
                return

            files = [f for f in os.listdir("uploads") if os.path.isfile(os.path.join("uploads", f))]
            count = len(files)
            client_socket.sendall(f"{count}".encode('utf-8'))
            
            # Protocol: Send count, wait for ack? Or just send list?
            # Let's send list as "file1|file2|file3"
            # If large list, might need chunking. Assuming small for demo.
            if count > 0:
                # Wait for client to be ready to receive list? 
                # Simplest: Just send it after a short pause or receive an ACK.
                # Let's verify client logic. Client will read count, then read rest.
                # To distinguish boundaries, let's use a delimiter for list.
                # Or: Send Count -> Client receives -> Client sends "READY_LIST" -> Server sends Names.
                
                # Let's go with: Send Count (with newline for safety) -> Client readsLine
                client_socket.sendall(b"\n") # Delimiter for count
                
                file_list_str = "|".join(files)
                client_socket.sendall((file_list_str + "\n").encode('utf-8'))
                
            logging.info(f"Sent list of {count} files.")
        except Exception as e:
            logging.error(f"List error: {e}")

    def handle_download(self, client_socket, filename):
        try:
            file_path = os.path.join("uploads", filename)
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
            
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(PRE_SHARED_KEY), modes.CBC(iv), backend=default_backend())
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
