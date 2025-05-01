import streamlit as st
import sqlite3
import bcrypt
import os

from cryptography.fernet import Fernet

KEY_FILE = "encryption.key"

# Load or generate encryption key
def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return key

cipher_suite = Fernet(load_key())

# Initialize the database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT)''')
    # Create secrets table
    c.execute('''CREATE TABLE IF NOT EXISTS secrets
                 (username TEXT PRIMARY KEY, secret TEXT)''')
    conn.commit()
    conn.close()

init_db()

# Password hashing with bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

# Encrypt secret data
def encrypt(text):
    return cipher_suite.encrypt(text.encode()).decode()

# Decrypt secret data
def decrypt(encrypted_text):
    return cipher_suite.decrypt(encrypted_text.encode()).decode()

# ---------------- Streamlit UI ----------------
st.title("🔐 Secure Data Encryption App")
menu = ["Store secret", "Retrieve secret"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Store secret":
    st.subheader("📥 Store Your Secret")

    username = st.text_input("Username", value="", key="username_store")
    password = st.text_input("Password", type="password", value="", key="password_store")
    secret_data = st.text_area("Secret Message", value="", key="secret_store")

    if st.button("Store Secret"):
        if not username or not password or not secret_data:
            st.warning("⚠️ Please fill all fields")
        else:
            hashed_pwd = hash_password(password)
            encrypted_secret = encrypt(secret_data)

            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            try:
                # Store user credentials
                c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                         (username, hashed_pwd))
                # Store encrypted secret
                c.execute("INSERT INTO secrets (username, secret) VALUES (?, ?)",
                         (username, encrypted_secret))
                conn.commit()
                st.success("✅ Secret stored securely!")
            except sqlite3.IntegrityError:
                st.error("❌ Username already exists. Try another one.")
            finally:
                conn.close()

elif choice == "Retrieve secret":
    st.subheader("📤 Retrieve Your Secret")

    username = st.text_input("Username", value="", key="username_retrieve")
    password = st.text_input("Password", type="password", value="", key="password_retrieve")

    if st.button("Retrieve Secret"):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()

        # Retrieve user credentials
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        user_result = c.fetchone()

        if not user_result:
            st.error("❌ Username not found")
        else:
            stored_hash = user_result[0].encode()
            if bcrypt.checkpw(password.encode(), stored_hash):
                # Retrieve secret data
                c.execute("SELECT secret FROM secrets WHERE username=?", (username,))
                secret_result = c.fetchone()
                if secret_result:
                    decrypted_secret = decrypt(secret_result[0])
                    st.success("✅ Access granted!")
                    st.subheader("🔓 Your Secret:")
                    st.code(decrypted_secret)
                else:
                    st.error("❌ No secret found for this user")
            else:
                st.error("❌ Incorrect password")
        conn.close()