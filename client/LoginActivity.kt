import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.security.MessageDigest
import kotlin.concurrent.thread

class LoginActivity : AppCompatActivity() {

    private lateinit var etServerIp: EditText
    private lateinit var etUsername: EditText
    private lateinit var etPassword: EditText
    private lateinit var btnLogin: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        etServerIp = findViewById(R.id.etServerIp)
        etUsername = findViewById(R.id.etUsername)
        etPassword = findViewById(R.id.etPassword)
        btnLogin = findViewById(R.id.btnLogin)
        val btnRegister: Button = findViewById(R.id.btnRegister)

        btnLogin.setOnClickListener {
            handleLogin()
        }

        btnRegister.setOnClickListener {
            val intent = Intent(this, RegisterActivity::class.java)
            startActivity(intent)
        }
    }

    private fun handleLogin() {
        val rawIp = etServerIp.text.toString().trim()
        val username = etUsername.text.toString().trim()
        val password = etPassword.text.toString().trim()

        if (rawIp.isEmpty() || username.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, "Please fill all fields", Toast.LENGTH_SHORT).show()
            return
        }

        btnLogin.isEnabled = false
        btnLogin.text = "Connecting..."

        thread {
            try {
                // Parse IP/Port
                val parts = rawIp.split(":")
                val host = parts[0]
                val port = if (parts.size > 1) parts[1].toInt() else 9999

                // Hash Password
                val passwordHash = sha256(password)

                // Verify with Server
                val success = NetworkManager.login(host, port, username, passwordHash)

                runOnUiThread {
                    if (success) {
                        // Save Session
                        SessionManager.serverIp = host
                        SessionManager.serverPort = port
                        SessionManager.username = username
                        SessionManager.passwordHash = passwordHash

                        Toast.makeText(this, "Login Successful!", Toast.LENGTH_SHORT).show()
                        
                        // Launch Main Activity
                        val intent = Intent(this, MainActivity::class.java)
                        startActivity(intent)
                        finish() // Close Login Activity
                    } else {
                        Toast.makeText(this, "Login Failed. Check credentials/server.", Toast.LENGTH_LONG).show()
                        btnLogin.isEnabled = true
                        btnLogin.text = "Connect & Login"
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                    btnLogin.isEnabled = true
                    btnLogin.text = "Connect & Login"
                }
            }
        }
    }

    private fun sha256(input: String): String {
        val bytes = input.toByteArray(Charsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(bytes)
        return hash.joinToString("") { "%02x".format(it) }
    }
}
