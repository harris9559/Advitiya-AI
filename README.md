# 🔐 Advitiya AI - Security Analysis Assistant

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/github/license/harris9559/Spyware_tool)
![Last Updated](https://img.shields.io/github/last-commit/harris9559/Spyware_tool)

**Advitiya AI** is an AI-powered security analysis assistant built using Streamlit and Groq's LLM API (LLaMA 3, Mixtral, Gemma). It provides advanced **static code analysis**, **vulnerability report evaluations**, and **interactive AI-driven security guidance**.

## 🚀 Features

- 🔍 **Static Code Analysis**  
  Analyze code in Python, JavaScript, Java, C++, PHP, Ruby, Go, Rust, and more to identify:
  - Vulnerabilities
  - Bad practices
  - Leaked secrets
  - Recommendations and severity levels

- 🛡️ **Vulnerability Scan Interpretation**  
  Understand and triage results from tools like:
  - Nmap
  - Nikto
  - OWASP ZAP
  - Burp Suite
  - Cloud & container security tools

- 💬 **Interactive Chat**  
  Ask questions about secure coding, tool usage, or vulnerabilities — Advitiya AI responds using Groq's models (LLaMA 3, Mixtral, Gemma).

- 🔐 **Encrypted API Key Storage**  
  API key is stored securely using Fernet encryption (`ENCRYPTION_KEY` required in `.env` or `secrets.toml`).

- 💾 **Save Chat History**  
  Export your session as a `.json` file.

## 🖼️ Demo

![Advitiya AI Demo](https://raw.githubusercontent.com/harris9559/Spyware_tool/main/demo.gif)

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/harris9559/Spyware_tool.git
   cd Spyware_tool
Create a virtual environment:

bash
Copy
Edit
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
Install requirements:

bash
Copy
Edit
pip install -r requirements.txt
Set up your secrets:

Create a .streamlit/secrets.toml file:

toml
Copy
Edit
GROQ_API_KEY = "your_groq_api_key"
ENCRYPTION_KEY = "your_fernet_generated_key"
Generate a Fernet key:

python
Copy
Edit
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
🧪 Usage
bash
Copy
Edit
streamlit run app.py
Use the sidebar to configure your API key, model selection, and analysis options.

📁 Project Structure
pgsql
Copy
Edit
Spyware_tool/
├── app.py                # Streamlit app
├── requirements.txt
├── demo.gif              # Demo GIF
├── chat_history.json     # (Optional) Chat logs
├── api_key.enc           # (Optional) Encrypted key
└── .streamlit/
    └── secrets.toml      # API & encryption keys
🧠 Models Available
llama3-8b-8192

mixtral-8x7b-32768

gemma-7b-it

🛡️ Disclaimer
This tool is built for educational, ethical hacking, and security analysis purposes. Use responsibly and legally.

📜 License
This project is licensed under the MIT Licence
