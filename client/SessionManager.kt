object SessionManager {
    var serverIp: String = "192.168.1.39"
    var serverPort: Int = 9999
    var username: String = ""
    var passwordHash: String = ""

    fun isLoggedIn(): Boolean {
        return username.isNotEmpty() && passwordHash.isNotEmpty()
    }

    fun clearSession() {
        username = ""
        passwordHash = ""
    }
}
