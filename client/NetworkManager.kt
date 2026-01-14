import java.io.*
import java.net.Socket
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object NetworkManager {

    private const val PRE_SHARED_KEY = "12345678901234567890123456789012" // 32 bytes for AES-256
    private const val ALGORITHM = "AES/CBC/PKCS5Padding"

    fun uploadFile(file: File, host: String, port: Int, username: String, passwordHash: String, remoteFilename: String) {
        try {
            val socket = Socket(host, port)
            val outputStream = socket.getOutputStream()
            val inputStream = socket.getInputStream()
            val reader = BufferedReader(InputStreamReader(inputStream))

            // --- STEP 1: HANDSHAKE & AUTH ---
            
            // 1. Receive Nonce (16 bytes)
            val nonce = ByteArray(16)
            var bytesRead = inputStream.read(nonce)
            if (bytesRead != 16) throw IOException("Failed to read nonce")

            // 2. Calculate AuthToken = SHA256(UserPasswordHash + Nonce)
            // Note: In Python server we did: sha256(passwordHash.encode() + nonce)
            // passwordHash is expected to be the SHA256 hex string of the password.
            val authTokenInput = passwordHash.toByteArray(Charsets.UTF_8) + nonce
            val authToken = sha256(authTokenInput)
            
            // 3. Send Username|AuthToken
            val authMessage = "$username|$authToken"
            outputStream.write(authMessage.toByteArray(Charsets.UTF_8))
            outputStream.flush()

            // 4. Wait for AUTH_OK
            # NOTE: BufferedReader might block if there is no newline, but our server sends raw bytes "AUTH_OK".
            # It's safer to read exact bytes or use a buffer.
            # For simplicity let's wrap in BufferedInputStream if we want or just read small buffer.
            val authResponse = ByteArray(7) // "AUTH_OK" is 7 bytes
            inputStream.read(authResponse)
            val authResponseStr = String(authResponse, Charsets.UTF_8)
            
            if (authResponseStr != "AUTH_OK") {
                println("Authentication Failed: $authResponseStr")
                socket.close()
                return
            }
            println("Authentication Successful")

            // --- STEP 2: SEND COMMAND ---
            val command = "UPLOAD"
            outputStream.write(command.toByteArray(Charsets.UTF_8))
            outputStream.flush()
            
            // Wait for CMD_OK
            val cmdResponse = ByteArray(6) // "CMD_OK"
            inputStream.read(cmdResponse)
            if (String(cmdResponse, Charsets.UTF_8) != "CMD_OK") {
                println("Command Rejected")
                socket.close()
                return
            }

            // --- STEP 3: SECURE HEADER ---

            // 1. Calculate Original File Hash
            val originalFileHash = hashFile(file)

            // 2. Encrypt File
            val encryptedData = encryptFile(file)
            val encryptedFileSize = encryptedData.size

            // 3. Send Metadata: Filename|OriginalFileHash|EncryptedFileSize
            val header = "$remoteFilename|$originalFileHash|$encryptedFileSize"
            outputStream.write(header.toByteArray(Charsets.UTF_8))
            outputStream.flush()

            // 4. Wait for READY
            val readyResponse = ByteArray(5) // "READY"
            inputStream.read(readyResponse)
            if (String(readyResponse, Charsets.UTF_8) != "READY") {
                println("Server not ready")
                socket.close()
                return
            }

            // --- STEP 4: ENCRYPTED TRANSFER ---
            outputStream.write(encryptedData)
            outputStream.flush()
            println("Encrypted file sent. Waiting for verification...")

            // Wait for SUCCESS
            val finalResponseBuffer = ByteArray(1024)
            val len = inputStream.read(finalResponseBuffer)
            val finalResponse = String(finalResponseBuffer, 0, len, Charsets.UTF_8)
            
            if (finalResponse == "SUCCESS") {
                println("File uploaded and integrity verified successfully!")
            } else {
                println("Upload failed: $finalResponse")
            }

            socket.close()

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun listFiles(host: String, port: Int, username: String, passwordHash: String): List<String> {
        val fileList = mutableListOf<String>()
        try {
            val socket = Socket(host, port)
            val outputStream = socket.getOutputStream()
            val inputStream = socket.getInputStream()

            // Auth
            if (!authenticate(socket, inputStream, outputStream, username, passwordHash)) {
                return emptyList()
            }

            // Send Command
            val command = "LIST"
            outputStream.write(command.toByteArray(Charsets.UTF_8))
            outputStream.flush()
            
            // Read Count (terminated by newline)
            val reader = BufferedReader(InputStreamReader(inputStream))
            val countStr = reader.readLine()
            if (countStr == null || countStr == "0") {
                 socket.close()
                 return emptyList()
            }
            
            val count = countStr.toIntOrNull() ?: 0
            if (count > 0) {
                 val listStr = reader.readLine()
                 if (listStr != null) {
                     fileList.addAll(listStr.split("|"))
                 }
            }
            socket.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return fileList
    }

    fun downloadFile(host: String, port: Int, username: String, passwordHash: String, filename: String, destFile: File): Boolean {
        try {
            val socket = Socket(host, port)
            val outputStream = socket.getOutputStream()
            val inputStream = socket.getInputStream()
            // Removed BufferedReader to avoid buffering binary data


            // Auth
            if (!authenticate(socket, inputStream, outputStream, username, passwordHash)) {
                return false
            }

            // Send Command
            val command = "DOWNLOAD|$filename"
            outputStream.write(command.toByteArray(Charsets.UTF_8))
            outputStream.flush()

            // Read Response byte-by-byte to avoid buffering overread
            // Response format: SIZE\nDATA
            
            val sizeStr = readUnbufferedLine(inputStream)
            if (sizeStr == null || sizeStr.startsWith("ERROR")) {
                println("Download failed: $sizeStr")
                socket.close()
                return false
            }
            
            val encryptedSize = sizeStr.toIntOrNull()
            if (encryptedSize == null) {
                socket.close()
                return false
            }

            // Read Encrypted Data
            val encryptedData = ByteArray(encryptedSize)
            var totalRead = 0
            while (totalRead < encryptedSize) {
                val read = inputStream.read(encryptedData, totalRead, encryptedSize - totalRead)
                if (read == -1) break
                totalRead += read
            }

            if (totalRead != encryptedSize) {
                println("Incomplete download")
                socket.close()
                return false
            }

            // Decrypt
            // Server encrypts: IV + Encrypted Data
            val decrypted = decryptData(encryptedData)
            
            if (decrypted != null) {
                destFile.writeBytes(decrypted)
                println("File downloaded to ${destFile.absolutePath}")
                socket.close()
                return true
            } else {
                println("Decryption failed")
            }

            socket.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    private fun authenticate(socket: Socket, inputStream: InputStream, outputStream: OutputStream, username: String, passwordHash: String): Boolean {
        try {
            // 1. Receive Nonce
            val nonce = ByteArray(16)
            var bytesRead = inputStream.read(nonce)
            if (bytesRead != 16) return false

            // 2. Calc Token
            val authTokenInput = passwordHash.toByteArray(Charsets.UTF_8) + nonce
            val authToken = sha256(authTokenInput)
            
            // 3. Send
            val authMessage = "$username|$authToken"
            outputStream.write(authMessage.toByteArray(Charsets.UTF_8))
            outputStream.flush()

            // 4. Response
            val authResponse = ByteArray(7)
            inputStream.read(authResponse)
            val authResponseStr = String(authResponse, Charsets.UTF_8)
            
            return authResponseStr == "AUTH_OK"
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }
    
    private fun decryptData(encryptedData: ByteArray): ByteArray? {
        try {
            if (encryptedData.size < 16) return null
            
            val iv = encryptedData.copyOfRange(0, 16)
            val ciphertext = encryptedData.copyOfRange(16, encryptedData.size)
            
            val ivSpec = IvParameterSpec(iv)
            val keySpec = SecretKeySpec(PRE_SHARED_KEY.toByteArray(Charsets.UTF_8), "AES")
            
            val cipher = Cipher.getInstance(ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            
            return cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    // Helper: Read line byte-by-byte to avoid buffering
    private fun readUnbufferedLine(inputStream: InputStream): String? {
        val lineBuffer = ByteArrayOutputStream()
        var byteRead: Int
        while (inputStream.read().also { byteRead = it } != -1) {
            if (byteRead == '\n'.code) {
                return lineBuffer.toString("UTF-8").trim()
            }
            lineBuffer.write(byteRead)
        }
        return if (lineBuffer.size() > 0) lineBuffer.toString("UTF-8").trim() else null
    }

    // Helper: SHA-256 for byte array
    private fun sha256(input: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input)
        return hash.joinToString("") { "%02x".format(it) }
    }

    // Helper: SHA-256 for file
    private fun hashFile(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val fis = FileInputStream(file)
        val buffer = ByteArray(8192)
        var bytesRead: Int
        while (fis.read(buffer).also { bytesRead = it } != -1) {
            digest.update(buffer, 0, bytesRead)
        }
        fis.close()
        val hash = digest.digest()
        return hash.joinToString("") { "%02x".format(it) }
    }

    // Helper: AES-256-CBC Encryption
    private fun encryptFile(file: File): ByteArray {
        val fileBytes = file.readBytes()
        val iv = ByteArray(16).apply { java.util.Random().nextBytes(this) }
        val ivSpec = IvParameterSpec(iv)
        val keySpec = SecretKeySpec(PRE_SHARED_KEY.toByteArray(Charsets.UTF_8), "AES")

        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        
        val encrypted = cipher.doFinal(fileBytes)
        
        // Prepend IV to ciphertext
        return iv + encrypted
    }
}
