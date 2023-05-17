import hashlib
import hmac
import math
import time
import struct
import pyotp
import qrcode
from cryptography.fernet import Fernet
import os
import base64
import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import ImageTk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class OTPApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("One-Time Password Generator")
        self.geometry("490x490")

        self.create_widgets()

    def create_widgets(self):

        self.lbl_file = tk.Label(self, text="Key File:")
        self.lbl_file.grid(row=0, column=0, padx=5, pady=5, columnspan=2)

        self.btn_generate = tk.Button(self, text="Generate Key File", command=self.generate_key_file)
        self.btn_generate.grid(row=0, column=1, padx=5, pady=5, columnspan=2)

        self.btn_encrypt = tk.Button(self, text="Encrypt Key File", command=self.encrypt_key_file)
        self.btn_encrypt.grid(row=1, column=2, padx=5, pady=5)

        self.lbl_password = tk.Label(self, text="Encryption Password:")
        self.lbl_password.grid(row=1, column=0, pady=5)

        self.entry_password = tk.Entry(self, show="*")
        self.entry_password.grid(row=1, column=1, pady=5)

        self.btn_load_key = tk.Button(self, text="Load Master Key", command=self.load_key_file)
        self.btn_load_key.grid(row=3, column=2, pady=5)


        self.lbl_totp = tk.Label(self, text="OTP: ")
        self.lbl_totp.grid(row=3, column=0, pady=5)
        
        self.entry_temp_password = tk.Entry(self, state="readonly")
        self.entry_temp_password.grid(row=3, column=1, pady=5)

        self.btn_qr = tk.Button(self, text="Generate QR Code", command=self.generate_qr_code)
        self.btn_qr.grid(row=4, column=0, columnspan=1, pady=5)

        self.qr_label = tk.Label(self)
        self.qr_label.grid(row=4, column=1, pady=5, columnspan=2)

    def generate_key_file(self):
        hex_read = os.urandom(32).hex()
        with open('key.hex', 'w') as f:
            f.write(hex_read)
        messagebox.showinfo("Success", "Key file generated as key.hex.")


    def encrypt_key_file(self):
        password = self.entry_password.get()
        if not password:
            messagebox.showerror("Error", "Please enter an encryption password.")
        else:
            with open('key.hex', 'r') as f:
                hex_read = f.read()
            encrypt_key(hex_read, password)
            messagebox.showinfo("Success", "Key file encrypted as ft_otp.key.")

        

    def load_key_file(self):
        password = self.entry_password.get()
        if not password:
            messagebox.showerror("Error", "Please enter the encryption password.")
        else:
            keyfile = filedialog.askopenfilename(title="Select Master Key File")
            if keyfile:
                try:
                    key, salt = load_key(keyfile, password)
                    temp_password = generate_totp(key)
                    self.entry_temp_password.configure(state="normal")
                    self.entry_temp_password.delete(0, tk.END)
                    self.entry_temp_password.insert(0, temp_password)
                    self.entry_temp_password.configure(state="readonly")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to generate temporary password: {str(e)}")
                    print(e)

    def generate_qr_code(self):
        totp = self.entry_temp_password.get()

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp)
        qr.make(fit=True)

        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_photo = ImageTk.PhotoImage(qr_image)

        self.qr_label.configure(image=qr_photo)
        self.qr_label.image = qr_photo

def generate_qr_code(temp_password):
    totp = generate_totp(temp_password)
    img = qrcode.make(totp.provisioning_uri("ft_otp"))
    return img

def generate_totp(key):
    actual_sec = math.floor(time.time())
    time_between = 30
    key_time = math.floor(actual_sec / time_between)
    time_bytes = struct.pack(">Q", key_time)
    hash_code = hmac.digest(key, time_bytes, hashlib.sha1)
    offset = hash_code[len(hash_code) - 1] & 0xf
    binary = ((hash_code[offset] & 0x7f) << 24) | ((hash_code[offset + 1] & 0xff) << 16) | ((hash_code[offset + 2] & 0xff) << 8) | (hash_code[offset + 3] & 0xff);
    code_key = binary % 1000000
    totp = "{:06d}".format(code_key)
    print(key)
    print("OTP: {}".format(totp))
    print(f"PYOTP= {pyotp.TOTP(base64.b32encode(key), interval=30).now()}")
    return totp

def encrypt_key(hex_read, password):
    original = hex_read.encode('utf-8')
    salt = os.urandom(16)
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    f = Fernet(key)
    encrypted = f.encrypt(original)
    with open('ft_otp.key', 'wb') as encrypted_file:
        encrypted_file.write(salt + encrypted)
    
def load_key(keyfile, password):
    with open(keyfile, 'rb') as f:
        data = f.read()
    salt = data[:16]
    encrypted = data[16:]
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted, salt


if __name__ == "__main__":
    app = OTPApp()
    app.mainloop()