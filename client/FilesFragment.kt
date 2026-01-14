import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.StrictMode
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.core.content.FileProvider
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import java.io.File
import kotlin.concurrent.thread

class FilesFragment : Fragment() {

    private lateinit var etServerIp: EditText
    private lateinit var btnRefresh: Button
    private lateinit var swipeRefresh: SwipeRefreshLayout
    private lateinit var recyclerView: RecyclerView
    private lateinit var adapter: FileAdapter

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_files, container, false)

        etServerIp = view.findViewById(R.id.etServerIp)
        btnRefresh = view.findViewById(R.id.btnRefresh)
        swipeRefresh = view.findViewById(R.id.swipeRefresh)
        recyclerView = view.findViewById(R.id.recyclerView)

        recyclerView.layoutManager = LinearLayoutManager(context)
        adapter = FileAdapter(emptyList()) { filename ->
            downloadAndOpen(filename)
        }
        recyclerView.adapter = adapter

        btnRefresh.setOnClickListener {
            refreshList()
        }

        swipeRefresh.setOnRefreshListener {
            refreshList()
        }

        // Hack for file exposure if FileProvider not fully set up
        val builder = StrictMode.VmPolicy.Builder()
        StrictMode.setVmPolicy(builder.build())

        return view
    }

    private fun refreshList() {
        val rawIp = etServerIp.text.toString().trim()
        if (rawIp.isEmpty()) {
            swipeRefresh.isRefreshing = false
            return
        }

        swipeRefresh.isRefreshing = true
        thread {
            try {
                val passHash = "ff2f12ec5c6a2e9ef6b61c958ed701c327469190a18075fd909ec2a9b42b94f2"
                val parts = rawIp.split(":")
                val host = parts[0]
                val port = if (parts.size > 1) parts[1].toInt() else 9999

                val files = NetworkManager.listFiles(host, port, "android_user", passHash)
                
                activity?.runOnUiThread {
                    adapter.updateList(files)
                    swipeRefresh.isRefreshing = false
                }
            } catch (e: Exception) {
                activity?.runOnUiThread {
                    Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                    swipeRefresh.isRefreshing = false
                }
            }
        }
    }

    private fun downloadAndOpen(filename: String) {
        val rawIp = etServerIp.text.toString().trim()
        if (rawIp.isEmpty()) return

        Toast.makeText(context, "Downloading $filename...", Toast.LENGTH_SHORT).show()
        
        thread {
            try {
                val passHash = "ff2f12ec5c6a2e9ef6b61c958ed701c327469190a18075fd909ec2a9b42b94f2"
                val parts = rawIp.split(":")
                val host = parts[0]
                val port = if (parts.size > 1) parts[1].toInt() else 9999

                val destFile = File(requireContext().getExternalFilesDir(null), filename)
                
                val success = NetworkManager.downloadFile(host, port, "android_user", passHash, filename, destFile)
                
                activity?.runOnUiThread {
                    if (success) {
                        openFile(destFile)
                    } else {
                        Toast.makeText(context, "Download failed", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                activity?.runOnUiThread {
                    Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun openFile(file: File) {
        val filename = file.name.lowercase()
        val isText = filename.endsWith(".txt") || filename.endsWith(".log") || 
                     filename.endsWith(".json") || filename.endsWith(".xml")
        val isImage = filename.endsWith(".jpg") || filename.endsWith(".jpeg") || 
                      filename.endsWith(".png") || filename.endsWith(".bmp")

        if (isText || isImage) {
            val dialog = FileViewerDialogFragment.newInstance(file.absolutePath)
            dialog.show(parentFragmentManager, "FileViewer")
        } else {
            try {
                val intent = Intent(Intent.ACTION_VIEW)
                val uri = Uri.fromFile(file)
                val mimeType = "*/*" 
                intent.setDataAndType(uri, mimeType)
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                startActivity(intent)
            } catch (e: Exception) {
                Toast.makeText(context, "Cannot open file: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
