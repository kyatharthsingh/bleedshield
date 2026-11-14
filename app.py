from flask import Flask, render_template, request, send_file
import re
import io
from fpdf import FPDF

import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'), static_folder=os.path.join(BASE_DIR, 'static'))

VULN_DB = {
    "strcpy": {
        "problem": "strcpy() copies without checking length. If source is bigger than destination, buffer overflows.",
        "fix": "Use strncpy(dest, src, sizeof(dest)-1); and add dest[sizeof(dest)-1] = '\\0';"
    },
    "strcat": {
        "problem": "strcat() appends without checking remaining space. It can overflow the destination buffer.",
        "fix": "Use strncat(dest, src, sizeof(dest) - strlen(dest) - 1);"
    },
    "gets": {
        "problem": "gets() has NO length limit. It is the most dangerous function in C and caused the Morris Worm (1988).",
        "fix": "Use fgets(buffer, sizeof(buffer), stdin); instead of gets()."
    },
    "sprintf": {
        "problem": "sprintf() does not check output size. Long formatted string can overflow the buffer.",
        "fix": "Use snprintf(buffer, sizeof(buffer), format, ...);"
    },
    "scanf": {
        "problem": "scanf() with %s has no limit. User can input unlimited characters and overflow the buffer.",
        "fix": "Use scanf(\"%49s\", buffer); - always give a width limit. Or use fgets()."
    },
    "memcpy": {
        "problem": "memcpy() copies N bytes without checking if destination has that much space. If payload length is fake, it leaks memory (Heartbleed).",
        "fix": "Always check: if (length <= sizeof(dest)) memcpy(dest, src, length);"
    },
    "alloca": {
        "problem": "alloca() allocates on stack without checking size. Large size can crash the program.",
        "fix": "Use malloc() with size check, or use a fixed-size buffer."
    },
    "system": {
        "problem": "system() runs shell commands. If user input goes inside, attacker can run any command.",
        "fix": "Avoid system(). Use execv() with fixed arguments, never pass user input directly."
    }
}

def check_code(code):
    lines = code.split('\n')
    findings = []
    for i, line in enumerate(lines, start=1):
        line_lower = line.lower()
        if "heartbeat" in line_lower or "dtls1_process_heartbeat" in line_lower or "ssl3_read_bytes" in line_lower:
            findings.append({
                "line_no": i,
                "line": line.strip(),
                "func": "Heartbleed - Heartbeat",
                "problem": "Heartbeat handler without length validation. Attacker can claim large payload and read server memory (CVE-2014-0160).",
                "fix": "Check: if (payload_length > actual_data_length) return error; Only then do memcpy."
            })
        if "memcpy" in line_lower and "payload" in line_lower:
            findings.append({
                "line_no": i,
                "line": line.strip(),
                "func": "Heartbleed - memcpy + payload",
                "problem": "memcpy() with attacker-controlled payload length. This is exactly how Heartbleed leaked 64KB memory.",
                "fix": "Validate length first: if (payload_length <= sizeof(buffer)) memcpy(buffer, payload, payload_length);"
            })
        for func, info in VULN_DB.items():
            if re.search(r'\b' + func + r'\s*\(', line_lower):
                if func == "memcpy" and "payload" in line_lower:
                    continue
                findings.append({
                    "line_no": i,
                    "line": line.strip(),
                    "func": func,
                    "problem": info["problem"],
                    "fix": info["fix"]
                })
    if findings:
        return "Vulnerable", findings
    else:
        return "Safe", []

def make_pdf(code, result, findings):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_fill_color(10, 25, 49)
    pdf.rect(0, 0, 210, 45, 'F')
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 12, "BleedShield", ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(255, 193, 217)
    pdf.cell(0, 7, "C Code Security Report  |  Heartbleed & Buffer Overflow", ln=True, align="C")
    pdf.ln(20)
    pdf.set_text_color(10, 25, 49)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, f"Result: {result}", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Total Issues Found: {len(findings)}", ln=True)
    pdf.cell(0, 7, "GitHub: github.com/kyatharthsingh/bleedshield", ln=True)
    pdf.cell(0, 7, "WhatsApp Pro Order: +91 79916 37905", ln=True)
    pdf.ln(5)
    if result == "Vulnerable":
        for f in findings:
            pdf.set_fill_color(255, 251, 235)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, f"LINE {f['line_no']} - {f['func']}", ln=True, fill=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, f"Code: {f['line']}")
            pdf.multi_cell(0, 6, f"Problem: {f['problem']}")
            pdf.multi_cell(0, 6, f"Fix: {f['fix']}")
            pdf.ln(3)
    else:
        pdf.set_fill_color(236, 253, 245)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "No vulnerable lines found. Your code looks safe!", ln=True, fill=True)
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Scanned Code:", ln=True)
    pdf.set_font("Courier", "", 9)
    pdf.multi_cell(0, 5, code[:4000])
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, "Made by BleedShield - Allahabad, India | github.com/kyatharthsingh/bleedshield", align="C")
    out = io.BytesIO(pdf.output())
    out.seek(0)
    return out

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    source = ""
    code = ""
    findings = []
    if request.method == "POST":
        if request.form.get("code"):
            code = request.form.get("code")
            result, findings = check_code(code)
            source = "Pasted Code"
        elif "c_file" in request.files and request.files["c_file"].filename != "":
            f = request.files["c_file"]
            try:
                code = f.read().decode("utf-8", errors="ignore")
            except:
                code = ""
            result, findings = check_code(code)
            source = f"File: {f.filename}"
        elif "pdf_file" in request.files and request.files["pdf_file"].filename != "":
            f = request.files["pdf_file"]
            source = f"PDF: {f.filename}"
            try:
                import PyPDF2
                reader = PyPDF2.PdfReader(f)
                text = ""
                for page in reader.pages:
                    text += page.extract_text() or ""
                code = text[:5000]
                result, findings = check_code(text)
            except:
                result = "Vulnerable"
                findings = [{"line_no": "-", "line": "PDF Upload", "func": "Manual Review", "problem": "PDF uploaded - manual review needed.", "fix": "Review PDF content manually."}]
    return render_template("index.html", result=result, source=source, code=code, findings=findings)

@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    code = request.form.get("code", "")
    result, findings = check_code(code)
    pdf_file = make_pdf(code, result, findings)
    return send_file(pdf_file, mimetype="application/pdf", as_attachment=True, download_name="BleedShield-Report.pdf")

if __name__ == "__main__":
    app.run(debug=True)