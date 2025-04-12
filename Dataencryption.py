import streamlit as st
import hashlib 
import json
import os 
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode  # Fixed: Added urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Configuration
DATA_FILE = "Secure_data.json"
SALT = b"secure_salt_value"  # Salt key for hashing the password
LOCKOUT_TIME = 60  # Time in seconds for locking the user out after 3 failed attempts

# Initialize session state
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
    
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Helper functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def generate_key(passkey):
    key = pbkdf2_hmac(
        'sha256',
        passkey.encode(),
        SALT,
        100000,
    )
    return urlsafe_b64encode(key[:32])  # Fernet key must be 32 url-safe base64-encoded bytes

def hash_password(password):
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        SALT,
        100000,
    ).hex()
    
def encrypt_text(text, passkey):
    cipher = Fernet(generate_key(passkey))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        return None

# Load existing data
stored_data = load_data()

# UI Setup
st.sidebar.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to 🔐 Secure Data Encryption System")
    st.write("This system allows you to securely store and retrieve sensitive data.")
    st.write("Please register or log in to get started.")

elif choice == "Register":
    st.subheader("User Registration")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.error("Username already exists!")
            else:
                # Store user data as a dictionary
                stored_data[username] = {
                    "password": hash_password(password),
                    "encrypted_data": []
                }
                save_data(stored_data)
                st.success("Registration successful! You can now log in.")
        else:
            st.error("All fields are required.")

elif choice == "Login":
    st.subheader("User Login")
    
    # Check if user is locked out
    if time.time() < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Please try again in {remaining_time} seconds.")
        st.stop()
        
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username in stored_data:
            # Access the password from the user's dictionary
            if stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"Welcome, {username}!")
            else:
                st.session_state.failed_attempts += 1
                st.error("Invalid password.")
                
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_TIME
                    st.error("Too many failed attempts. You've been locked out for 60 seconds.")
        else:
            st.error("Username not found.")

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.error("Please log in to store data.")
    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter encryption password", type="password")
        
        if st.button("Encrypt and Store"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["encrypted_data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and stored successfully!")
            else:
                st.error("Both data and password are required.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.error("Please log in to retrieve data.")
    else:
        st.subheader("Retrieve Decrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("encrypted_data", [])
        
        if not user_data:
            st.warning("No encrypted data found for this user.")
        else:
            st.write("Your encrypted data entries:")
            for idx, item in enumerate(user_data):
                st.write(f"{idx+1}. {item[:50]}...")  # Show first 50 chars of encrypted data
            
            selected = st.selectbox("Select data to decrypt", range(len(user_data)), 
                                format_func=lambda x: f"Entry {x+1}")
            passkey = st.text_input("Enter decryption password", type="password")
            
            if st.button("Decrypt"):
                encrypted_data = user_data[selected]
                decrypted = decrypt_text(encrypted_data, passkey)
                if decrypted:
                    st.success("Decrypted Data:")
                    st.text_area("", decrypted, height=200)
                else:
                    st.error("Decryption failed. Wrong password or corrupted data.")