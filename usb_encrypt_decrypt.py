import os
import base64
import hashlib
from tkinter import Tk, filedialog, messagebox, Button, Label, simpledialog, Listbox, SINGLE
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend

def get_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)
    key = get_key(password, salt)
    iv = os.urandom(16)
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    
    os.remove(file_path)
    print(f"Encrypted {file_path} to {encrypted_file_path}")

def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()
    
    key = get_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    decrypted_file_path = file_path.replace('.enc', '')
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)
    
    os.remove(file_path)
    print(f"Decrypted {file_path} to {decrypted_file_path}")

def list_drives():
    if os.name == 'nt':  # Windows
        import string
        from ctypes import windll
        
        bitmask = windll.kernel32.GetLogicalDrives()
        drives = []
        
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(f"{letter}:\\")
            bitmask >>= 1
        
        return drives
    else:
        return [f"/media/{user}/{d}" for user in os.listdir("/media") for d in os.listdir(f"/media/{user}")]

def process_drive(drive_path: str, action: str):
    print(f"Processing drive: {drive_path} for {action}")  # Debug print
    password = simpledialog.askstring("Password", f"Enter {action} password:", show='*')
    if not password:
        print("No password entered, aborting")  # Debug print
        return
    
    for root, _, files in os.walk(drive_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Processing file: {file_path}")  # Debug print
            if action == "encrypt":
                encrypt_file(file_path, password)
            elif action == "decrypt":
                decrypt_file(file_path, password)
    
    messagebox.showinfo("Success", f"Drive {action}ed successfully!")

def select_drive(action: str):
    drives = list_drives()
    print(f"Drives found: {drives}")  # Debug print
    
    if not drives:
        messagebox.showerror("Error", "No USB drives detected")
        return
    
    drive_selection = Tk()
    drive_selection.title("Select USB Drive")
    drive_selection.geometry("300x200")
    
    Label(drive_selection, text="Select a USB drive:").pack(pady=10)
    drive_listbox = Listbox(drive_selection, selectmode=SINGLE)
    drive_listbox.pack(expand=True, fill='both')
    
    for drive in drives:
        drive_listbox.insert('end', drive)
    
    def on_drive_select(event=None):
        selected_index = drive_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No drive selected")
        else:
            selected_drive = drive_listbox.get(selected_index)
            print(f"Selected drive: {selected_drive}")  # Debug print
            drive_selection.destroy()
            process_drive(selected_drive, action)
    
    drive_listbox.bind("<Double-1>", on_drive_select)  # Bind double-click to selection
    select_button = Button(drive_selection, text="Select", command=on_drive_select)
    select_button.pack(pady=5)
    
    drive_selection.mainloop()

def encrypt_drive():
    print("Encrypt button clicked")  # Debug print
    select_drive("encrypt")

def decrypt_drive():
    print("Decrypt button clicked")  # Debug print
    select_drive("decrypt")

if __name__ == "__main__":
    root = Tk()
    root.title("USB Drive Encrypter/Decrypter")
    root.geometry("300x150")
    
    Label(root, text="Select an action:").pack(pady=10)
    
    Button(root, text="Encrypt USB Drive", command=encrypt_drive).pack(pady=5)
    Button(root, text="Decrypt USB Drive", command=decrypt_drive).pack(pady=5)
    
    root.mainloop()
