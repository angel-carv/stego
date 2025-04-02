from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox
import os

# ---- App Setup ----
root = tk.Tk()
root.title("StegoVault Maker")
root.geometry("600x600")
root.resizable(False, False)

# ---- Global Variables ----
selected_file = None

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

# ---- LSB Embedding Function ----
def embed_data_in_image(image_path, data, output_path):
    # open image and convert to RGB
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    # convert our secret into bits
    bits = ''.join(f'{byte:08b}' for byte in data)
    required_pixels = (len(bits) + 2) // 3  # Each pixel can store 3 bits

    # make sure the image has enough space
    if required_pixels > len(pixels):
        raise ValueError("Image too small for this data.")

    new_pixels = []
    bit_index = 0

    # loops through each r g & b
    # if r g or b data = 0 its overwritten by an encrypted bit from our bitstream.
    # spread throughout entire picture
    for pixel in pixels:
        if bit_index < len(bits):
            r, g, b = pixel
            r = (r & ~1) | int(bits[bit_index]) if bit_index < len(bits) else r
            g = (g & ~1) | int(bits[bit_index+1]) if bit_index+1 < len(bits) else g
            b = (b & ~1) | int(bits[bit_index+2]) if bit_index+2 < len(bits) else b
            new_pixels.append((r, g, b))
            bit_index += 3
        else:
            new_pixels.append(pixel)

    # create new image and write pixels back
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    new_img.save(output_path)

# ---- File Picker ----
def pick_image():
    global selected_file
    file_path = filedialog.askopenfilename(
        title="🖼️ Choose your image",
        filetypes=[("PNG Images", "*.png")]
    )
    if not file_path:
        messagebox.showwarning("⚠️ No File", "You didn't select anything.")
        return
    if not file_path.lower().endswith(".png"):
        messagebox.showerror("❌ Invalid File", "Please select a valid PNG image.")
        return

    selected_file = file_path
    filename = os.path.basename(file_path)
    filename_label.config(text=f"📄 Selected: {filename}")

# ---- Hide Secret ----
def hide_secret():
    if not selected_file:
        messagebox.showwarning("⚠️ No Image", "Please select an image first.")
        return

    secret = message_entry.get()
    password = password_entry.get()

    if not secret or not password:
        messagebox.showwarning("⚠️ Missing Info", "Please enter both a secret and a password.")
        return

    try:
        encrypted_data = encrypt_message(secret, password)
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if not output_path:
            return
        embed_data_in_image(selected_file, encrypted_data, output_path)
        messagebox.showinfo("✅ Success", f"Secret hidden successfully!\nSaved to: {output_path}")
    except Exception as e:
        messagebox.showerror("❌ Error", f"Failed to hide secret: {e}")

# ---- GUI Layout ----
welcome_label = tk.Label(root, text="🔐 Welcome to StegoVault Maker", font=("Arial", 16))
welcome_label.pack(pady=20)

select_button = tk.Button(root, text="🖼️ Select Image", font=("Arial", 12), command=pick_image)
select_button.pack(pady=10)

filename_label = tk.Label(root, text="", font=("Arial", 10), fg="gray")
filename_label.pack(pady=(0, 10))

message_label = tk.Label(root, text="📝 Secret Message:", font=("Arial", 12))
message_label.pack(pady=(5, 5))

message_entry = tk.Entry(root, width=40)
message_entry.pack(pady=5)

password_label = tk.Label(root, text="🔑 Password:", font=("Arial", 12))
password_label.pack(pady=(15, 5))

password_entry = tk.Entry(root, width=40, show="*")
password_entry.pack(pady=5)

hide_button = tk.Button(root, text="Hide Secret 🔐", font=("Arial", 12), command=hide_secret)
hide_button.pack(pady=20)

# ---- Run the App ----
root.mainloop()
