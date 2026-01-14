# SecureVault

**SecureVault** is a secure file transfer system responsible for uploading files from an Android client to a Python server. It implements 3 key security pillars:
1.  **Authentication**: Verifies user identity without sending passwords over the network.
2.  **Confidentiality**: Encrypts files using AES-256 so only the server can read them.
3.  **Integrity**: Uses SHA-256 to ensure files haven't been changed during transit.

## Project Structure & Explanation

*   **`server.py`** (The Server):
    *   This is the "receiver". It sits on a computer and waits for the Android app to connect.
    *   It manages a database of users and logs every action.
    *   It decrypts incoming files and checks if they are safe/authentic.

*   **`client/NetworkManager.kt`** (The Client Logic):
    *   This is the "messenger" for the Android app.
    *   It takes a file, encrypts it (locks it), and calculates a hash (digital fingerprint).
    *   It connects to the server and handles the secure delivery.

*   **`client/MainActivity.kt` & `client/activity_main.xml`** (The UI):
    *   A simple Android screen to select a file and enter the server IP.
    *   Demonstrates how to use the `NetworkManager` in a real app.

*   **`requirements.txt`**:
    *   A list of tools (libraries) the Python server needs to work (specifically `cryptography`).

*   **`test_server_logic.py`**:
    *   A test script that pretends to be the Android app. It's used to check if the server is working correctly without needing the actual phone app.

## Setup Instructions

1.  **Install Requirements**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Server**:
    ```bash
    python server.py
    ```

3.  **Client Usage (Android)**:
    Call the `uploadFile` function in your activity:
    ```kotlin
    val serverIp = "192.168.1.100" // Replace with your PC's IP address
    NetworkManager.uploadFile(myFile, serverIp, 9999, "android_user", "hashed_password")
    ```
