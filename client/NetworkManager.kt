import java.io.*
import java.net.Socket
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import java.security.spec.MGF1ParameterSpec

object NetworkManager {

    // private const val PRE_SHARED_KEY = "..." // REMOVED
    private const val ALGORITHM_AES = "AES/CBC/PKCS5Padding"
    private const val ALGORITHM_RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

    fun login(host: String, port: Int, username: String, passwordHash: String): Boolean {
        try {
            val socket = Socket(host, port)
            val outputStream = socket.getOutputStream()
            val inputStream = socket.getInputStream()

            val success = authenticate(socket, inputStream, outputStream, username, passwordHash)
            socket.close()
            return success
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }

    fun register(host: String, port: Int, username: String, passwordHash: String): String {
        try {
            val socket = Socket(host, port)
            val outputStream = socket.getOutputStream()
            val inputStream = socket.getInputStream()
            
            // --- HANDSHAKE ---
            // Receive Nonce (16 bytes) - We receive it but don't need it for registration hashing in this simplified flow
            val nonce = ByteArray(16)
            inputStream.read(nonce)

            // --- SEND REGISTER COMMAND ---
            // Format: REGISTER|username|passwordHash
            val msg = "REGISTER|$username|$passwordHash"
            outputStream.write(msg.toByteArray(Charsets.UTF_8))
            outputStream.flush()

            // --- READ RESPONSE ---
            val responseBuffer = ByteArray(1024)
            val len = inputStream.read(responseBuffer)
            val response = String(responseBuffer, 0, len, Charsets.UTF_8)
            
            socket.close()
            return response // "REG_OK", "REG_FAIL_EXISTS", etc.
        } catch (e: Exception) {
            return "ERROR: ${e.message}"
        }
    }

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
            
            // 0. Get Server Public Key First (New Connection)
            val serverPubKey = getServerPublicKey(host, port)
            if (serverPubKey == null) {
                println("Failed to get server public key")
                socket.close()
                return
            }
            
            // 1. Generate AES Session Key
            val sessionKey = generateSessionKey()
            
            // 2. Encrypt Session Key with RSA
            val encryptedSessionKey = encryptSessionKey(sessionKey, serverPubKey)

            // 3. Calculate Original File Hash
            val originalFileHash = hashFile(file)

            // 4. Encrypt File with Session Key
            val encryptedData = encryptFile(file, sessionKey)
            val encryptedFileSize = encryptedData.size

            // 5. Send Metadata: Filename|OriginalFileHash|EncryptedFileSize|EncryptedSessionKey
            val header = "$remoteFilename|$originalFileHash|$encryptedFileSize|$encryptedSessionKey"
            outputStream.write(header.toByteArray(Charsets.UTF_8))
            outputStream.flush()

            // 6. Wait for READY
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

            // Get Public Key
            val serverPubKey = getServerPublicKey(host, port)
            if (serverPubKey == null) {
                println("Failed to fetch public key")
                socket.close()
                return false
            }
            
            // Gen Session Key
            val sessionKey = generateSessionKey()
            val encSessionKey = encryptSessionKey(sessionKey, serverPubKey)

            // Send Command: DOWNLOAD|filename|encSessionKey
            val command = "DOWNLOAD|$filename|$encSessionKey"
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
            // Server encrypts: IV + Encrypted Data using sessionKey
            val decrypted = decryptData(encryptedData, sessionKey)
            
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
    
    private fun decryptData(encryptedData: ByteArray, sessionKey: SecretKey): ByteArray? {
        try {
            if (encryptedData.size < 16) return null
            
            val iv = encryptedData.copyOfRange(0, 16)
            val ciphertext = encryptedData.copyOfRange(16, encryptedData.size)
            
            val ivSpec = IvParameterSpec(iv)
            val ivSpec = IvParameterSpec(iv)
            
            val cipher = Cipher.getInstance(ALGORITHM_AES)
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec)
            
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

    // Helper: AES-256-CBC Encryption with dynamic key
    private fun encryptFile(file: File, sessionKey: SecretKey): ByteArray {
        val fileBytes = file.readBytes()
        val iv = ByteArray(16).apply { java.util.Random().nextBytes(this) }
        val ivSpec = IvParameterSpec(iv)
        
        val cipher = Cipher.getInstance(ALGORITHM_AES)
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec)
        
        val encrypted = cipher.doFinal(fileBytes)
        
        // Prepend IV to ciphertext
        return iv + encrypted
    }

    // Helper: Get Server Public Key
    private fun getServerPublicKey(host: String, port: Int): PublicKey? {
        try {
            val socket = Socket(host, port)
            val outputStream = socket.getOutputStream()
            val inputStream = socket.getInputStream()
            
            // Read 16-byte Nonce (ignore it)
            val nonce = ByteArray(16)
            inputStream.read(nonce)
            
            // Send Command
            val command = "GET_PUB_KEY"
            outputStream.write(command.toByteArray(Charsets.UTF_8))
            outputStream.flush()
            
            // Read Public Key Bytes
            // We need to read until end because it's a raw PEM or DER transfer? 
            // The server sends `self.public_key_bytes` which is PEM format.
            // But Socket.read() might return partial. Let's read fully.
            
            val buffer = ByteArrayOutputStream()
            val data = ByteArray(4096)
            var nRead: Int
            while (inputStream.read(data, 0, data.size).also { nRead = it } != -1) {
                buffer.write(data, 0, nRead)
            }
            socket.close()
            
            val keyBytes = buffer.toByteArray()
            if (keyBytes.isEmpty()) return null
            
            // Convert PEM to PublicKey object
            // Java's X509EncodedKeySpec expects DER (binary), so we need to strip PEM headers if it's PEM.
            // ... Actually server sends PEM.
            
            val keyString = String(keyBytes, Charsets.UTF_8)
            val pemHeader = "-----BEGIN PUBLIC KEY-----"
            val pemFooter = "-----END PUBLIC KEY-----"
            
            val pemContent = keyString
                .replace(pemHeader, "")
                .replace(pemFooter, "")
                .replace("\\s".toRegex(), "") // Remove newlines
                
            val decoded = Base64.getDecoder().decode(pemContent)
            val spec = X509EncodedKeySpec(decoded)
            val kf = KeyFactory.getInstance("RSA")
            return kf.generatePublic(spec)
            
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    // Helper: Generate AES Session Key
    private fun generateSessionKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        return keyGen.generateKey()
    }

    // Helper: Encrypt Session Key with RSA
    private fun encryptSessionKey(sessionKey: SecretKey, publicKey: PublicKey): String {
        val cipher = Cipher.getInstance(ALGORITHM_RSA)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        
        // We use OAEP with SHA-256 MGF1 as defined in server:
        // asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        // In Java "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" should work.
        
        val encryptedBytes = cipher.doFinal(sessionKey.encoded)
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }
}
