from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox
import os

# ---- AES Decryption from LSB ----
def extract_lsb_data(image_path, num_bytes):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for pixel in pixels:
        for channel in pixel:
            bits.append(channel & 1)
            if len(bits) >= num_bytes * 8:
                break
        if len(bits) >= num_bytes * 8:
            break

    message_bytes = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        value = int("".join(map(str, byte)), 2)
        message_bytes.append(value)

    return bytes(message_bytes)

def decrypt_message_from_image(image_path, password):
    embedded_data = extract_lsb_data(image_path, num_bytes=256)
    salt = embedded_data[:16]
    iv = embedded_data[16:32]
    ciphertext = embedded_data[32:]

    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    pad_len = padded_plaintext[-1]
    return padded_plaintext[:-pad_len].decode(errors="replace")

# ---- GUI Setup ----
root = tk.Tk()
root.title("StegoVault Viewer")
root.geometry("500x400")
root.resizable(False, False)

# ---- Decrypt Function ----
def reveal_secret():
    image_path = filedialog.askopenfilename(
        title="🖼️ Select Image with Secret",
        filetypes=[("PNG Images", "*.png")]
    )
    if not image_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showwarning("⚠️ Missing Password", "Please enter the password to decrypt the message.")
        return

    try:
        secret = decrypt_message_from_image(image_path, password)

        if save_to_file.get():
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
            if save_path:
                with open(save_path, "w") as f:
                    f.write(secret)
                messagebox.showinfo("✅ Saved", f"Secret saved to: {save_path}")
        else:
            messagebox.showinfo("🔍 Secret Revealed", f"Hidden Message:\n{secret}")

    except Exception as e:
        messagebox.showerror("❌ Error", f"Failed to reveal secret: {e}")

# ---- GUI Layout ----
welcome_label = tk.Label(root, text="🔐 StegoVault Viewer", font=("Arial", 16))
welcome_label.pack(pady=20)

password_label = tk.Label(root, text="🔑 Password:", font=("Arial", 12))
password_label.pack(pady=(10, 5))

password_entry = tk.Entry(root, width=40, show="*")
password_entry.pack(pady=5)

save_to_file = tk.BooleanVar()
save_checkbox = tk.Checkbutton(root, text="Save output to text file", variable=save_to_file)
save_checkbox.pack(pady=10)

reveal_button = tk.Button(root, text="Reveal Secret 🔍", font=("Arial", 12), command=reveal_secret)
reveal_button.pack(pady=20)

# ---- Run the App ----
root.mainloop()
