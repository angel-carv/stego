from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

# ---- AES Encryption Function ----
def encrypt_message(message, password):
    # convert secret message to bytes
    data = message.encode()
    # generate salt and use PBKDF2 to derive key from password
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    # generate a random initialization vector
    iv = get_random_bytes(16)

    # adds \x0- ( - being the number of padding added) \x03 for example.
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)

    # encrypt with AES in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    # return all data needed to decrypt
    return salt + iv + ciphertext

# ---- AES Decryption Function ----
def decrypt_message(data, password):
    # extract components
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    # derive key again
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)

    # remove padding and decode
    pad_len = padded[-1]
    return padded[:-pad_len].decode(errors="replace")

# ---- LSB Embedding Function ----
def embed_data_in_image(image_path, data, output_path):
    # prepend length of data as 2 bytes
    data_length = len(data)
    if data_length > 65535:
        raise ValueError("Data too large to embed.")
    data_with_length = data_length.to_bytes(2, 'big') + data

    # open image and convert to RGB
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    # convert our secret into bits
    bits = ''.join(f'{byte:08b}' for byte in data_with_length)
    required_pixels = (len(bits) + 2) // 3  # Each pixel can store 3 bits

    # make sure the image has enough space
    if required_pixels > len(pixels):
        raise ValueError("Image too small for this data.")

    new_pixels = []
    bit_index = 0

    # loops through each r g & b
    for pixel in pixels:
        r, g, b = pixel
        if bit_index < len(bits):
            r = (r & ~1) | int(bits[bit_index])
            bit_index += 1
        if bit_index < len(bits):
            g = (g & ~1) | int(bits[bit_index])
            bit_index += 1
        if bit_index < len(bits):
            b = (b & ~1) | int(bits[bit_index])
            bit_index += 1
        new_pixels.append((r, g, b))

    # create new image and write pixels back
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    new_img.save(output_path)

# ---- LSB Extraction Function ----
def extract_lsb_data(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for pixel in pixels:
        for channel in pixel:
            bits.append(channel & 1)

    # extract first 16 bits to get length
    length_bits = bits[:16]
    length = int("".join(map(str, length_bits)), 2)

    # now extract the rest based on length
    data_bits = bits[16:16 + (length * 8)]
    message_bytes = [int("".join(map(str, data_bits[i:i+8])), 2) for i in range(0, len(data_bits), 8)]
    return bytes(message_bytes)

# ---- App GUI Setup ----
root = tk.Tk()
root.title("StegoVault")
root.geometry("600x500")
root.resizable(False, False)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

# ---- Tab 1: Hide Secret ----
hide_tab = ttk.Frame(notebook)
notebook.add(hide_tab, text="🔐 Hide Secret")

selected_file = None

# ---- File Picker ----
def select_image():
    global selected_file
    file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
    if file_path:
        selected_file = file_path
        file_label.config(text=f"📄 {os.path.basename(file_path)}")

# ---- Hide Secret ----
def run_hide():
    if not selected_file:
        messagebox.showwarning("⚠️", "No image selected.")
        return

    secret = message_entry.get()
    password = password_entry.get()

    if not secret or not password:
        messagebox.showwarning("⚠️", "Secret and password required.")
        return

    try:
        encrypted = encrypt_message(secret, password)
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if output_path:
            embed_data_in_image(selected_file, encrypted, output_path)
            messagebox.showinfo("✅ Success", f"Secret hidden in {output_path}")
    except Exception as e:
        messagebox.showerror("❌ Error", str(e))

# ---- Hide Secret GUI ----
tk.Label(hide_tab, text="Select Image:", font=("Arial", 12)).pack(pady=(20, 5))
tk.Button(hide_tab, text="Browse Image", command=select_image).pack()
file_label = tk.Label(hide_tab, text="", font=("Arial", 10), fg="gray")
file_label.pack()

tk.Label(hide_tab, text="📝 Secret Message:", font=("Arial", 12)).pack(pady=(20, 5))
message_entry = tk.Entry(hide_tab, width=50)
message_entry.pack(pady=5)

tk.Label(hide_tab, text="🔑 Password:", font=("Arial", 12)).pack(pady=(20, 5))
password_entry = tk.Entry(hide_tab, show="*", width=50)
password_entry.pack(pady=5)

tk.Button(hide_tab, text="Hide Secret 🔐", font=("Arial", 12), command=run_hide).pack(pady=20)

# ---- Tab 2: Reveal Secret ----
reveal_tab = ttk.Frame(notebook)
notebook.add(reveal_tab, text="🔎 Reveal Secret")

# ---- Reveal Secret ----
def run_reveal():
    image_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
    if not image_path:
        return

    password = reveal_password_entry.get()
    if not password:
        messagebox.showwarning("⚠️", "Password is required.")
        return

    try:
        encrypted_data = extract_lsb_data(image_path)
        secret = decrypt_message(encrypted_data, password)

        # clean up fluff / non-ASCII
        safe_secret = ''.join(c for c in secret if c.isprintable() or c in '\n\r\t')

        if reveal_save_var.get():
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(safe_secret)
                messagebox.showinfo("✅ Saved", f"Secret saved to: {save_path}")
        else:
            messagebox.showinfo("🔍 Message", safe_secret)

    except Exception as e:
        messagebox.showerror("❌ Error", str(e))

# ---- Reveal Secret GUI ----
tk.Label(reveal_tab, text="🔑 Password:", font=("Arial", 12)).pack(pady=(30, 5))
reveal_password_entry = tk.Entry(reveal_tab, width=50, show="*")
reveal_password_entry.pack(pady=5)

reveal_save_var = tk.BooleanVar()
tk.Checkbutton(reveal_tab, text="Save to text file", variable=reveal_save_var).pack(pady=10)

tk.Button(reveal_tab, text="Reveal Secret 🔍", font=("Arial", 12), command=run_reveal).pack(pady=20)

# ---- Run App ----
root.mainloop()

#poopy butt 69

# this is something 