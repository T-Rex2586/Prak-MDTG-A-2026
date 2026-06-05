import streamlit as st  # Library untuk membuat web app sederhana
import base64           # Untuk encoding/decoding base64
import secrets          # Untuk generate random bytes (lebih aman dari random biasa)

# Import komponen cryptography
from cryptography.hazmat.primitives import hashes                     # Untuk hashing (SHA256)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC      # Untuk derivasi key dari password
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # AES cipher
from cryptography.hazmat.backends import default_backend              # Backend cryptography


# --- Core Encryption Engine ---
class AdvancedEncryption:
    def __init__(self):
        # Set backend cryptography
        self.backend = default_backend()
    
    def derive_key_from_password(self, password, salt=None):
        # Jika salt belum ada, generate random 16 byte
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # PBKDF2 untuk mengubah password jadi key AES
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),   # Hash SHA256
            length=32,                   # Panjang key 32 byte (256-bit AES)
            salt=salt,                  # Salt untuk keamanan
            iterations=100000,          # Iterasi tinggi biar susah di brute-force
            backend=self.backend
        )
        
        # Derive key dari password
        key = kdf.derive(password.encode('utf-8'))
        
        return key, salt  # Return key + salt
    
    def encrypt_aes_gcm(self, plaintext, password):
        # Generate salt
        salt = secrets.token_bytes(16)
        
        # Generate key dari password + salt
        key, _ = self.derive_key_from_password(password, salt)
        
        # Generate IV (nonce) 12 byte (standar GCM)
        iv = secrets.token_bytes(12)
        
        # Buat AES GCM cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Kalau input string, ubah ke bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Proses enkripsi
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Return gabungan: salt + iv + tag + ciphertext
        return salt + iv + encryptor.tag + ciphertext
    
    def decrypt_aes_gcm(self, ciphertext, password):
        try:
            # Ambil bagian-bagian dari ciphertext
            salt = ciphertext[:16]              # 16 byte pertama = salt
            iv = ciphertext[16:28]             # 12 byte berikutnya = IV
            tag = ciphertext[28:44]            # 16 byte berikutnya = authentication tag
            actual_ciphertext = ciphertext[44:]  # sisanya = data terenkripsi
            
            # Generate key lagi dari password + salt
            key, _ = self.derive_key_from_password(password, salt)
            
            # Buat cipher untuk decrypt
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Proses dekripsi
            return decryptor.update(actual_ciphertext) + decryptor.finalize()
        
        except Exception:
            # Kalau gagal (password salah / data rusak)
            return None


# Setup halaman Streamlit
st.set_page_config(page_title="Encryption Tool", page_icon="🔐")
st.title("🔐 Text & File Encryptor")

# Inisialisasi class encryption
encryption = AdvancedEncryption()

# Buat tab UI
tab1, tab2 = st.tabs(["💬 Text Encryption", "📁 File Encryption"])


# ========================
# TAB 1: TEXT ENCRYPTION
# ========================
with tab1:
    col1, col2 = st.columns(2)  # Bagi layout jadi 2 kolom
    
    # ----- ENCRYPT -----
    with col1:
        st.subheader("Encrypt")
        
        # Input text
        t_input = st.text_area("Plain Text", placeholder="Input text here...", key="t_enc_in")
        
        # Input password
        t_pass = st.text_input("Password", type="password", key="t_enc_pass")
        
        # Tombol encrypt
        if st.button("Encrypt Text", type="primary"):
            if t_input and t_pass:
                # Enkripsi
                res = encryption.encrypt_aes_gcm(t_input, t_pass)
                
                # Encode ke base64 biar bisa ditampilkan
                st.code(base64.b64encode(res).decode(), language=None)
                
                st.success("Copy the code above.")
            else:
                st.error("Fill text and password!")

    # ----- DECRYPT -----
    with col2:
        st.subheader("Decrypt")
        
        # Input base64
        d_input = st.text_area("Encrypted Base64", placeholder="Paste base64 here...", key="t_dec_in")
        
        # Input password
        d_pass = st.text_input("Password", type="password", key="t_dec_pass")
        
        # Tombol decrypt
        if st.button("Decrypt Text", type="primary"):
            if d_input and d_pass:
                try:
                    # Decode base64 ke bytes
                    raw_data = base64.b64decode(d_input)
                    
                    # Decrypt
                    dec = encryption.decrypt_aes_gcm(raw_data, d_pass)
                    
                    if dec:
                        # Tampilkan hasil
                        st.text_area("Result", dec.decode('utf-8'), disabled=True)
                    else:
                        st.error("Wrong password or data corrupted.")
                
                except:
                    st.error("Invalid Base64 format.")


# ========================
# TAB 2: FILE ENCRYPTION
# ========================
with tab2:
    # Pilih mode
    mode = st.radio("Operation", ["Encrypt File", "Decrypt File"], horizontal=True)
    
    # Upload file
    f_input = st.file_uploader("Upload File")
    
    # Password file
    f_pass = st.text_input("File Password", type="password", key="f_pass")

    # Kalau file dan password ada
    if f_input and f_pass:
        if st.button("Process File"):
            
            # Ambil isi file sebagai bytes
            file_bytes = f_input.getvalue()
            
            if mode == "Encrypt File":
                # Encrypt file
                processed = encryption.encrypt_aes_gcm(file_bytes, f_pass)
                
                # Tambah ekstensi
                new_name = f"{f_input.name}.encrypted"
                
                st.success(f"File '{f_input.name}' Encrypted!")
            
            else:
                # Decrypt file
                processed = encryption.decrypt_aes_gcm(file_bytes, f_pass)
                
                # Hapus ekstensi
                new_name = f_input.name.replace(".encrypted", "")
                
                if processed:
                    st.success("File Decrypted!")
                else:
                    st.error("Failed to decrypt. Check password.")
                    processed = None

            # Tombol download hasil
            if processed:
                st.download_button(
                    label="Download Result",
                    data=processed,
                    file_name=new_name
                )