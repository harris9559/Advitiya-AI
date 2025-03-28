import streamlit as st
import os
import json
from datetime import datetime
from typing import Tuple
from dotenv import load_dotenv
from groq import Groq
from cryptography.fernet import Fernet

# Load environment variables
load_dotenv()

# Constants
SUPPORTED_LANGUAGES = ["Python", "JavaScript", "Java", "C++", "PHP", "Ruby", "Go", "Rust", "Other"]
SCAN_TYPES = ["Nmap", "Nikto", "OWASP ZAP", "Burp Suite", "Custom Log", "Network Scan", 
              "Web Application Scan", "Container Scan", "Cloud Security Scan"]
MODELS = ["llama3-8b-8192", "mixtral-8x7b-32768", "gemma-7b-it"]

# Initialize session state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'api_key' not in st.session_state:
    st.session_state.api_key = None

# Encryption setup (generate key once with Fernet.generate_key())
# Store this in your secrets.toml as ENCRYPTION_KEY
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
cipher_suite = Fernet(ENCRYPTION_KEY.encode()) if ENCRYPTION_KEY else None

def load_api_key() -> str:
    """Try multiple methods to load API key"""
    # 1. Check session state (user recently entered)
    if st.session_state.api_key:
        return st.session_state.api_key
        
    # 2. Check encrypted local storage
    if cipher_suite:
        try:
            with open('api_key.enc', 'rb') as f:
                return cipher_suite.decrypt(f.read()).decode()
        except:
            pass
            
    # 3. Check environment variables
    if os.getenv("GROQ_API_KEY"):
        return os.getenv("GROQ_API_KEY")
        
    # 4. Check Streamlit secrets
    try:
        if 'GROQ_API_KEY' in st.secrets:
            return st.secrets.GROQ_API_KEY
    except:
        pass
        
    return None

def save_api_key(key: str):
    """Save API key to session state and encrypted storage"""
    st.session_state.api_key = key
    if cipher_suite:
        with open('api_key.enc', 'wb') as f:
            f.write(cipher_suite.encrypt(key.encode()))

def clear_api_key():
    """Remove stored API key"""
    st.session_state.api_key = None
    if os.path.exists('api_key.enc'):
        os.remove('api_key.enc')

def fetch_groq_response(prompt: str, api_key: str, model: str = "llama3-8b-8192") -> Tuple[str, bool]:
    """Fetch response from Groq API with enhanced error handling"""
    try:
        client = Groq(api_key=api_key)
        
        completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system", 
                    "content": "You are Advitiya, an advanced AI security assistant powered by Llama 3."
                },
                {"role": "user", "content": prompt}
            ],
            model=model,
            temperature=0.7,
            max_tokens=4096,
            top_p=1,
            stream=False
        )
        
        if not completion.choices:
            return "Error: No response from model", False
            
        return completion.choices[0].message.content, True
        
    except Exception as e:
        error_msg = f"""
        ## Error in Analysis
        
        **Details**: {str(e)}
        
        Please check:
        - Your API key is valid
        - You have sufficient credits
        - The input data is properly formatted
        """
        return error_msg, False

def save_chat_history():
    """Save chat history to JSON file"""
    with open('chat_history.json', 'w') as f:
        json.dump(st.session_state.chat_history, f)
    st.success("Chat history saved successfully!")

def perform_static_analysis(language_used: str, file_data: str, api_key: str, model: str) -> Tuple[str, bool]:
    """Perform static code analysis"""
    instructions = """
    As a code security expert, analyze the given programming file to identify:
    1. Security vulnerabilities
    2. Code quality issues
    3. Potential bugs
    4. Exposed sensitive information
    5. Security best practices violations
    
    Provide a detailed analysis with:
    - Severity levels for each issue
    - Code snippets highlighting problems
    - Recommended fixes
    - Security best practices
    
    Format the response in Markdown.
    """
    
    analysis_prompt = f"""
    {instructions}
    
    Language: {language_used}
    
    Code to analyze:
    ```{language_used}
    {file_data}
    ```    
    """
    
    return fetch_groq_response(analysis_prompt, api_key, model)

def perform_vuln_analysis(scan_type: str, scan_data: str, api_key: str, model: str) -> Tuple[str, bool]:
    """Perform vulnerability analysis"""
    instructions = """
    As a security vulnerability analyzer, examine the provided scan data to:
    1. Identify all security vulnerabilities
    2. Assess the risk level of each finding
    3. Detect misconfigurations
    4. Identify exposed sensitive information
    5. Evaluate security controls
    
    Provide a comprehensive report including:
    - Executive summary
    - Detailed findings
    - Risk ratings
    - Remediation steps
    - Technical recommendations
    
    Format the response in Markdown.
    """
    
    analysis_prompt = f"""
    {instructions}
    
    Scan Type: {scan_type}
    
    Scan Data:
    ```    
    {scan_data}
    ```    
    """
    
    return fetch_groq_response(analysis_prompt, api_key, model)

def main():
    # Page configuration
    st.set_page_config(
        page_title="Advitiya AI", 
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Custom CSS
    st.markdown("""<style>
        .main {
            background-color: #f5f5f5;
        }
        .stTitle {
            color: #1E3D59;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 24px;
        }
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            padding-top: 10px;
            padding-bottom: 10px;
        }
        .stButton > button {
            background-color: #1E3D59;
            color: white;
        }
        .success {
            background-color: #D4EDDA;
            color: #155724;
            padding: 10px;
            border-radius: 5px;
        }
        </style>""", unsafe_allow_html=True)
    
    # Load API key automatically
    api_key = load_api_key()
    
    # Sidebar configuration
    st.sidebar.title("⚙️ Configuration")
    st.sidebar.markdown("---")
    
    # API Configuration
    st.sidebar.header("API Configuration")
    
    if api_key:
        st.sidebar.success("✅ API key loaded")
        if st.sidebar.button("🔄 Change API Key"):
            clear_api_key()
            st.rerun()
    else:
        api_key = st.sidebar.text_input("Enter Groq API Key", type="password")
        if api_key:
            save_api_key(api_key)
            st.rerun()
    
    # Model Selection
    st.sidebar.header("Model Selection")
    model = st.sidebar.selectbox("Select Model", MODELS, help="Choose the AI model for analysis")
    
    if st.sidebar.button("💾 Save Chat History"):
        save_chat_history()
    
    # Main interface
    st.title("🔐 Advitiya AI")
    st.markdown("Welcome to Advitiya AI - Your Advanced Security Analysis Assistant powered by Llama 3")
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["💬 Interactive Chat", "🔍 Static Analysis", "🛡️ Vulnerability Analysis"])
    
    # Chat Tab
    with tab1:
        st.header("💬 Chat with Advitiya")
        user_input = st.text_area("What would you like to know about security?")
        
        if st.button("Send 📤", key="chat_send"):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key")
            elif user_input:
                with st.spinner("🤔 Processing your query..."):
                    response, success = fetch_groq_response(user_input, api_key, model)
                    if success:
                        st.session_state.chat_history.append({
                            "query": user_input,
                            "response": response,
                            "timestamp": datetime.now().isoformat()
                        })
                    st.markdown(response)
    
    # Static Analysis Tab
    with tab2:
        st.header("🔍 Static Code Analysis")
        language = st.selectbox("Select Programming Language", SUPPORTED_LANGUAGES)
        code = st.text_area("Code for Analysis:", height=200)
        
        if st.button("🔎 Analyze Code"):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key")
            elif code:
                with st.spinner("🔍 Analyzing code..."):
                    result, success = perform_static_analysis(language, code, api_key, model)
                    st.markdown(result)
    
    # Vulnerability Analysis Tab
    with tab3:
        st.header("🛡️ Vulnerability Analysis")
        scan_type = st.selectbox("Select Scan Type", SCAN_TYPES)
        scan_data = st.text_area("Scan Data:", height=200)
        
        if st.button("🔍 Analyze Vulnerabilities"):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key")
            elif scan_data:
                with st.spinner("🔍 Analyzing vulnerabilities..."):
                    result, success = perform_vuln_analysis(scan_type, scan_data, api_key, model)
                    st.markdown(result)
    
    # Chat history
    if st.session_state.chat_history:
        st.sidebar.markdown("---")
        st.sidebar.header("📚 Chat History")
        for idx, chat in enumerate(reversed(st.session_state.chat_history)):
            with st.sidebar.expander(f"Chat {len(st.session_state.chat_history) - idx}"):
                st.markdown(f"**🗣️ {chat['query']}**")
                st.markdown(f"*{chat['timestamp']}*")
                st.markdown(chat['response'])

if __name__ == "__main__":
    main()