import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

Users_file = "users.json"

def load_users():
    if os.path.exists(Users_file):
        with open(Users_file, "r") as file_data:
            content = file_data.read().strip()   # strip is used to remove space
            if content:
                return json.loads(content)
    return {}
    
def save_users(data):
    with open(Users_file,"w") as file_data:
        return json.dump(data, file_data, indent=4)
    
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key():
    return Fernet.generate_key().decode()

def encrypt(user_key,text):
    cipher= Fernet(user_key.encode())
    return cipher.encrypt(text.encode()).decode()
def decrypt(user_key, encrypted_text):
    cipher =Fernet(user_key.encode())
    return cipher.decrypt(encrypted_text.encode()).decode()

if "users" not in st.session_state:
    st.session_state.users = load_users()
if "current_user" not in st.session_state:
    st.session_state.current_user = None

st.title("🔐 Multi-User Secure Data Storage")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.markdown(" 🏠 Welcome to the secure multi-user data app.")
    
elif choice == "Register":
    st.subheader("📝 Register")
    new_user = st.text_input("Username:")
    new_password = st.text_input("Password:", type= "password")
    
    if st.button("Register"):
        if not new_user or not new_password:
            st.error("Username and Password cannot be empty.")
        elif new_user in st.session_state.users:
            st.error("Username already exists.")
        else:
            key = generate_key()
            st.session_state.users[new_user] = {
                "password": hash_passkey(new_password),
                "key": key,
                "data": {}
            }
            save_users(st.session_state.users)
            st.success("User has been registered! Login Now.")

elif choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        users = st.session_state.users
        if not username or not password:
            st.error("Username and Password cannot be empty.")
        elif username in st.session_state.users and st.session_state.users[username]["password"] == hash_passkey(password):
            st.session_state.current_user = username
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid credentials")
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("Login Required!")
    else:
        st.subheader("📦 Store Data")
        data = st.text_area("Enter the data to encrpyt:")
        if st.button("Ecncrpyt and Save"):
            user = st.session_state.users[st.session_state.current_user]
            encrypted = encrypt(user["key"], data)
            user["data"][encrypted] = ""  # Store empty string as a placeholder
            save_users(st.session_state.users)
            st.success("Data stored!")
            st.code(encrypted)
            
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("Login required")
    else:
        st.subheader("🔍 Retrieve Data")
        encrypted = st.text_area("Paste encrypted text")
        if st.button("Decrypt"):
            user = st.session_state.users[st.session_state.current_user]
            decrypted = decrypt(user["key"], encrypted)
            st.success(f"Decrypted: {decrypted}")


            
            


    
