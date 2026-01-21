# SecureVault Application Flow & Technical Documentation

This document explains the operational flow and technical details of the SecureVault file transfer system, focusing on socket communication, server logic, and client implementation.

## 1. Simple Steps: How the App Works

1.  **Connect**: The Android app connects to the Python server using the Server IP (default port 9999).
2.  **Key Exchange**: The app requests the server's RSA Public Key (`GET_PUB_KEY`).
3.  **Authenticate/Register**:
    *   **Register**: New users can create an account (`REGISTER`).
    *   **Login**: The app authenticates using a pre-configured username and password hash.
4.  **List Files**: On the "View Files" tab, the app requests a list of available files from the server.
5.  **Upload**:
    *   User selects a file from their device.
    *   **Hybrid Encryption**: The app generates a one-time AES session key, encrypts it with the server's Public Key, and then encrypts the file with the AES key.
    *   The encrypted session key and encrypted file are sent to the server.
    *   The server decrypts the session key (using its Private Key), then decrypts the file, verifies integrity, and saves it to the user's isolated folder.
6.  **View/Download**:
    *   User taps a file in the list.
    *   **Download**: The server sends the file (encrypted with a new session key).
    *   **Text/Image**: The file opens directly in the app.
    *   **Others**: The file is downloaded and opened in an external viewer.

## 2. Socket Communication & Custom Protocol

The system uses standard TCP sockets for reliable data transfer. A custom protocol ensures security and state management.

### Protocol Phases
1.  **Handshake**:
    *   **Client** connects.
    *   **Server** sends a random 16-byte `Nonce`.
    *   **Client** sends Auth Data or Command:
        *   `GET_PUB_KEY`: Server sends RSA Public Key.
        *   `REGISTER|Username|PasswordHash`: Server registers new user.
        *   `Username|AuthToken`: Client proves identity (`AuthToken = SHA256(PasswordHash + Nonce)`).
    *   **Server** verifies token. Sends `AUTH_OK`.

2.  **Command Execution**:
    *   Client sends a text command (e.g., `LIST`, `UPLOAD`, `DOWNLOAD|filename|EncryptedSessionKey`).
    *   Server responds accordingly.

### Socket Usage Details
*   **Blocking I/O**: The system primarily uses blocking sockets with thread-per-client architecture on the server.
*   **Buffering Handling**:
    *   **Fixed-size reads**: Used for nonces (16 bytes).
    *   **Line-based reads**: Used for commands and metadata (checking for `\n`).
    *   **Raw Byte streams**: Used for encrypted file transfer to ensure no byte corruption.

## 3. Server-Side Code (`server.py`)

The server is built with Python.

*   **Libraries**: `socket` (networking), `threading` (concurrency), `sqlite3` (audit logs/users), `cryptography` (RSA+AES-256).
*   **Key Components**:
    *   `SecureVaultServer`: Main class.
    *   `load_or_generate_keys()`: Manages RSA 2048-bit key pair (`server_private.pem`, `server_public.pem`).
    *   `handle_client(socket, addr)`: Manages the protocol state machine (Handshake -> Auth/Register -> Command).
    *   `decrypt_rsa(data)`: Decrypts client session keys using the server's Private Key.
    *   `encrypt/decrypt_file`: Uses AES-256-CBC with the session key.
    *   `verify_integrity`: Compares SHA-256 hashes of decrypted data vs. original hashes.
    *   **User Isolation**: Files are stored in `uploads/<username>/` to prevent access to other users' files.
    *   **Database**: `secure_vault.db` stores user credentials and audit logs.

## 4. Client-Side Code (Android/Kotlin)

The client is a native Android application.

*   **`NetworkManager.kt`**:
    *   The core networking engine.
    *   Handles socket creation, RSA encryption of session keys, AES file encryption, and protocol adherence.
    *   **Crucial Logic**:
        *   Fetches Server Public Key on first connect.
        *   Generates random AES Session Key for each transfer.
        *   implements `readUnbufferedLine` to safely read text commands.
*   **`MainActivity.kt`**:
    *   Hosts the Tab layout (`Upload` and `View Files`).
*   **`FilesFragment.kt`**:
    *   Displays the file list.
    *   Determines if a file should be viewed internally or externally.
*   **`FileViewerDialogFragment.kt`**:
    *   A custom UI component to display text and images directly within the app.
*   **`UploadFragment.kt`**:
    *   Manages file selection and initiates the secure upload process.
