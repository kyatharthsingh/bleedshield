# BleedShield 🛡️
### Your C Code is Bleeding. We Stop It.

Detect dangerous bugs like Heartbleed and Buffer Overflow in seconds. Paste your code, upload a file, and scan. No login required.

**Live Demo:** https://bleedshield.onrender.com
**GitHub:** https://github.com/kyatharthsingh/bleedshield
**Made for:** Veritas Hackathon | Secure Coding for Students

---

## 🚨 The Problem

A single `strcpy` or `gets` can leak your entire server memory.

- **Heartbleed (2014)** - Leaked data from 17% of the world's servers
- **Morris Worm (1988)** - `gets()` crashed 10% of the internet
- **WannaCry (2017)** - Buffer overflow shut down hospitals

Students learn C, but no one teaches them how to write it safely. Existing tools are complex, paid, or made for big companies.

## 💡 Our Solution

BleedShield is a simple, free, browser-based scanner. Paste your C code, get instant line-by-line report in plain English.

- Which line is vulnerable?
- Why is it a problem?
- How to fix it? - With ready-to-copy safe code

## ✨ Features

- **Line-by-Line Scan** - strcpy, gets, memcpy, sprintf, scanf, system, Heartbleed pattern
- **Problem + Fix in Simple English** - No jargon
- **Upload .c File / PDF File** - Scan full lab files
- **Download PDF Report - Free**
- **AI / ML Detection Model** - Pattern-based ML Classifier, 87.5% Accuracy on 200 samples
- **BleedShield Pro** - Auto-Fix, PDF Report with your name, Severity Score, Safe Certificate, Viva Q&A
- **100% Open Source** - MIT License

## 🤖 ML Model

- **Model:** Pattern-based ML Classifier
- **Accuracy:** 87.5% - Tested on 200 samples
- **Training Data:** 160 Safe + 40 Vulnerable samples
- **Live Demo:** Try `strcpy(buffer, input);` in ML Model box on the site

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **PDF:** PyPDF2, fpdf2
- **Deployment:** Render
- **ML:** Pattern-based Classifier (JavaScript)

## 🚀 How to Run

```bash
git clone https://github.com/kyatharthsingh/bleedshield.git
cd bleedshield
pip install Flask PyPDF2 Werkzeug fpdf2
python app.py
