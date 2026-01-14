import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.fragment.app.Fragment
import java.io.File
import java.io.FileOutputStream
import kotlin.concurrent.thread

class UploadFragment : Fragment() {

    private lateinit var btnSelectFile: Button
    private lateinit var btnUpload: Button
    private lateinit var tvSelectedFile: TextView
    private lateinit var tvLog: TextView

    private var selectedFile: File? = null
    private var selectedFileName: String = "unknown"

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_upload, container, false)

        btnSelectFile = view.findViewById(R.id.btnSelectFile)
        btnUpload = view.findViewById(R.id.btnUpload)
        tvSelectedFile = view.findViewById(R.id.tvSelectedFile)
        tvLog = view.findViewById(R.id.tvLog)

        btnSelectFile.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.type = "*/*"
            startActivityForResult(intent, 100)
        }

        btnUpload.setOnClickListener {
            if (selectedFile != null) {
                val host = SessionManager.serverIp
                val port = SessionManager.serverPort
                val username = SessionManager.username
                val passHash = SessionManager.passwordHash

                log("Starting upload to $host...")
                thread {
                    try {
                        NetworkManager.uploadFile(selectedFile!!, host, port, username, passHash, selectedFileName)
                        
                        activity?.runOnUiThread { log("Upload process finished (Check logs for success/fail)") }
                    } catch (e: Exception) {
                        activity?.runOnUiThread { log("Error: ${e.message}") }
                    }
                }
            }
        }

        return view
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 100 && resultCode == Activity.RESULT_OK) {
            data?.data?.let { uri ->
                val file = getFileFromUri(uri)
                selectedFile = file
                selectedFileName = getFileName(uri) ?: file?.name ?: "unknown"
                tvSelectedFile.text = "Selected: $selectedFileName"
                btnUpload.isEnabled = true
                log("File selected: ${file?.absolutePath} (Original: $selectedFileName)")
            }
        }
    }

    private fun log(message: String) {
        tvLog.append("\n$message")
    }

    private fun getFileFromUri(uri: Uri): File? {
        try {
            val inputStream = requireContext().contentResolver.openInputStream(uri)
            val tempFile = File.createTempFile("upload", ".tmp", requireContext().cacheDir)
            val outputStream = FileOutputStream(tempFile)
            inputStream?.copyTo(outputStream)
            inputStream?.close()
            outputStream.close()
            return tempFile
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
    
    private fun getFileName(uri: Uri): String? {
        var result: String? = null
        if (uri.scheme == "content") {
            val cursor = requireContext().contentResolver.query(uri, null, null, null, null)
            try {
                if (cursor != null && cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (index >= 0) {
                        result = cursor.getString(index)
                    }
                }
            } finally {
                cursor?.close()
            }
        }
        if (result == null) {
            result = uri.path
            val cut = result?.lastIndexOf('/') ?: -1
            if (cut != -1) {
                result = result?.substring(cut + 1)
            }
        }
        return result
    }
}
