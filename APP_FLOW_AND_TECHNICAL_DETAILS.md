# SecureVault Application Flow & Technical Documentation

This document explains the operational flow and technical details of the SecureVault file transfer system, focusing on socket communication, server logic, and client implementation.

## 1. Simply Steps: How the App Works

1.  **Connect**: The Android app connects to the Python server using the Server IP (default port 9999).
2.  **Authenticate**: The app automatically authenticates using a pre-configured username and password hash.
3.  **List Files**: On the "View Files" tab, the app requests a list of available files from the server.
4.  **Upload**:
    *   User selects a file from their device.
    *   The file is encrypted and sent to the server.
    *   The server receives, decrypts, verifies integrity, and saves the file.
5.  **View/Download**:
    *   User taps a file in the list.
    *   **Text/Image**: The file opens directly in the app.
    *   **Others**: The file is downloaded and opened in an external viewer.

## 2. Socket Communication & Custom Protocol

The system uses standard TCP sockets for reliable data transfer. A custom protocol ensures security and state management.

### Protocol Phases
1.  **Handshake**:
    *   **Client** connects.
    *   **Server** sends a random 16-byte `Nonce`.
    *   **Client** calculates `AuthToken = SHA256(PasswordHash + Nonce)`.
    *   **Client** sends `Username|AuthToken`.
    *   **Server** verifies tokens match. Sends `AUTH_OK`.

2.  **Command Execution**:
    *   Client sends a text command (e.g., `LIST`, `UPLOAD`, `DOWNLOAD|filename`).
    *   Server responds accordingly.

### Socket Usage Details
*   **Blocking I/O**: The system primarily uses blocking sockets with thread-per-client architecture on the server.
*   **Buffering Handling**:
    *   **Fixed-size reads**: Used for nonces (16 bytes).
    *   **Line-based reads**: Used for commands and metadata (checking for `\n`).
    *   **Raw Byte streams**: Used for encrypted file transfer to ensure no byte corruption.

## 3. Server-Side Code (`server.py`)

The server is built with Python.

*   **Libraries**: `socket` (networking), `threading` (concurrency), `sqlite3` (audit logs), `cryptography` (AES-256).
*   **Key Components**:
    *   `SecureVaultServer`: Main class.
    *   `handle_client(socket, addr)`: A function running in a separate thread for every connected user. It manages the protocol state machine (Auth -> Command -> Data).
    *   `encrypt/decrypt_file`: Uses AES-256-CBC with PKCS7 padding.
    *   `verify_integrity`: Compares SHA-256 hashes of received data vs. original hashes sent in headers.
    *   **Database**: Stores user credentials and logs every event (LOGIN, UPLOAD, ERROR) to `secure_vault.db`.

## 4. Client-Side Code (Android/Kotlin)

The client is a native Android application.

*   **`NetworkManager.kt`**:
    *   The core networking engine.
    *   Handles socket creation, raw byte streams, and protocol adherence.
    *   **Crucial Logic**: Implements `readUnbufferedLine` to safely read text commands (like file size) without removing subsequent binary file data from the stream.
*   **`MainActivity.kt`**:
    *   Hosts the Tab layout (`Upload` and `View Files`).
*   **`FilesFragment.kt`**:
    *   Displays the file list.
    *   Determines if a file should be viewed internally (Text/Image) or externally.
*   **`FileViewerDialogFragment.kt`**:
    *   A custom UI component to display text and images directly within the app, providing a seamless user experience.
*   **`UploadFragment.kt`**:
    *   Manages file selection and initiates the upload process via `NetworkManager`.
