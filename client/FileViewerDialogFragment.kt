import android.app.Dialog
import android.graphics.BitmapFactory
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.ImageView
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.DialogFragment
import java.io.File

class FileViewerDialogFragment : DialogFragment() {

    companion object {
        private const val ARG_FILE_PATH = "file_path"

        fun newInstance(filePath: String): FileViewerDialogFragment {
            val args = Bundle()
            args.putString(ARG_FILE_PATH, filePath)
            val fragment = FileViewerDialogFragment()
            fragment.arguments = args
            return fragment
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.dialog_file_viewer, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val filePath = arguments?.getString(ARG_FILE_PATH) ?: return
        val file = File(filePath)

        val tvTitle: TextView = view.findViewById(R.id.tvTitle)
        val tvContent: TextView = view.findViewById(R.id.tvContent)
        val ivContent: ImageView = view.findViewById(R.id.ivContent)
        val scrollView: ScrollView = view.findViewById(R.id.scrollView)
        val btnClose: Button = view.findViewById(R.id.btnClose)

        tvTitle.text = file.name

        if (isImageFile(file.name)) {
            scrollView.visibility = View.GONE
            ivContent.visibility = View.VISIBLE
            
            val bitmap = BitmapFactory.decodeFile(filePath)
            ivContent.setImageBitmap(bitmap)
        } else {
            scrollView.visibility = View.VISIBLE
            ivContent.visibility = View.GONE
            
            try {
                tvContent.text = file.readText()
            } catch (e: Exception) {
                tvContent.text = "Error reading file: ${e.message}"
            }
        }

        btnClose.setOnClickListener {
            dismiss()
        }
    }

    override fun onStart() {
        super.onStart()
        dialog?.window?.setLayout(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT
        )
    }

    private fun isImageFile(filename: String): Boolean {
        val ext = filename.substringAfterLast('.', "").lowercase()
        return ext in listOf("jpg", "jpeg", "png", "bmp", "webp")
    }
}
