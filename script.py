import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SALT = b"this_is_a_static_salt"  # For demo only

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    with open(filepath + '.locked', 'wb') as f:
        f.write(iv + encrypted_data)
    
    os.remove(filepath)

def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    original_path = filepath.replace('.locked', '')
    with open(original_path, 'wb') as f:
        f.write(decrypted_data)

    os.remove(filepath)

def process_folder(folder_path, password, encrypt=True):
    key = derive_key(password)
    for root, _, files in os.walk(folder_path):
        for name in files:
            path = os.path.join(root, name)
            try:
                if encrypt and not name.endswith('.locked'):
                    encrypt_file(path, key)
                elif not encrypt and name.endswith('.locked'):
                    decrypt_file(path, key)
            except Exception as e:
                print(f"Failed on {path}: {e}")

# ------------------------ GUI ------------------------

class EncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulated File Locker")
        self.folder_path = tk.StringVar()

        tk.Label(root, text="Folder Path:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        tk.Entry(root, textvariable=self.folder_path, width=40).grid(row=0, column=1, padx=5)
        tk.Button(root, text="Browse", command=self.browse_folder).grid(row=0, column=2, padx=5)

        tk.Label(root, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.password_entry = tk.Entry(root, show="*", width=40)
        self.password_entry.grid(row=1, column=1, padx=5)

        self.mode = tk.StringVar(value="encrypt")
        tk.Radiobutton(root, text="Encrypt", variable=self.mode, value="encrypt").grid(row=2, column=1, sticky='w')
        tk.Radiobutton(root, text="Decrypt", variable=self.mode, value="decrypt").grid(row=2, column=1, sticky='e')

        tk.Button(root, text="Run", command=self.run).grid(row=3, column=1, pady=10)

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.folder_path.set(path)

    def run(self):
        folder = self.folder_path.get()
        password = self.password_entry.get()
        if not folder or not password:
            messagebox.showerror("Error", "Please select a folder and enter a password.")
            return

        encrypt_mode = self.mode.get() == "encrypt"
        process_folder(folder, password, encrypt=encrypt_mode)

        msg = "Encryption complete!" if encrypt_mode else "Decryption complete!"
        messagebox.showinfo("Done", msg)

# ------------------------ MAIN ------------------------

if __name__ == '__main__':
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()
