import os, tempfile, subprocess
from flask import Flask, request, render_template, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "secret"

UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), "word_to_pdf_uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def convert_with_libreoffice(word_path, pdf_path):
    """Use LibreOffice to convert Word → PDF (works for doc & docx)."""
    folder = os.path.dirname(pdf_path)
    cmd = [
        "soffice",
        "--headless",
        "--convert-to", "pdf",
        "--outdir", folder,
        word_path
    ]
    subprocess.check_call(cmd)
    # output file has same basename but .pdf
    produced = os.path.join(folder, os.path.splitext(os.path.basename(word_path))[0] + ".pdf")
    os.replace(produced, pdf_path)

@app.route("/")
def index():
    return render_template("word-to-pdf.html")

@app.route("/convert-word-to-pdf", methods=["POST"])
def convert_word_to_pdf():
    if 'word_file' not in request.files:
        flash("File missing.")
        return redirect(url_for("index"))

    file = request.files['word_file']
    if file.filename == "":
        flash("File missing.")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    word_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(word_path)

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.splitext(filename)[0] + ".pdf")

    try:
        convert_with_libreoffice(word_path, pdf_path)
    except Exception as e:
        flash(f"Conversion failed: {e}")
        return redirect(url_for("index"))

    return send_file(pdf_path, as_attachment=True, download_name=os.path.basename(pdf_path))

if __name__ == "__main__":
    app.run(debug=True, port=5001)
