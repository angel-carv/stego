from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import string
import secrets

#final build look at encrypt or viewer to see comments


# ---- AES Encryption Function ----
def encrypt_message(message, password):
    data = message.encode()
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    iv = get_random_bytes(16)
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    return salt + iv + ciphertext

# ---- Fixed LSB Extraction Function ----
def extract_lsb_data(image_path):
    """Extract data embedded using LSB steganography"""
    if not os.path.exists(image_path):
        raise FileNotFoundError("Image file not found")
    
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    
    # Extract all LSBs from the image
    bits = []
    for pixel in pixels:
        for channel in pixel:
            bits.append(str(channel & 1))  # Convert to string for joining
    
    # First 16 bits represent the length (2 bytes = 16 bits)
    if len(bits) < 16:
        raise ValueError("Image too small to contain embedded data")
    
    length_bits = bits[:16]
    length = int("".join(length_bits), 2)
    
    if length == 0:
        raise ValueError("No data found in image")
    
    if length > 65535:  # 2^16 - 1
        raise ValueError("Invalid data length detected")
    
    # Calculate total bits needed: length bits + data bits
    total_bits_needed = 16 + (length * 8)
    
    if len(bits) < total_bits_needed:
        raise ValueError("Image doesn't contain enough data")
    
    # Extract the actual data bits
    data_bits = bits[16:16 + (length * 8)]
    
    # Convert bits back to bytes
    message_bytes = []
    for i in range(0, len(data_bits), 8):
        byte_bits = data_bits[i:i+8]
        if len(byte_bits) == 8:  # Ensure we have a complete byte
            byte_value = int("".join(byte_bits), 2)
            message_bytes.append(byte_value)
    
    return bytes(message_bytes)

# ---- Improved Decryption with Better Error Handling ----
def decrypt_message(data, password):
    """Decrypt AES encrypted data with better error detection"""
    if len(data) < 32:  # Need at least salt + iv
        raise ValueError("Data too short to be valid encrypted message")
    
    try:
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]
        
        if len(ciphertext) % 16 != 0:
            raise ValueError("Invalid ciphertext length")
        
        key = PBKDF2(password, salt, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        
        if len(padded) == 0:
            raise ValueError("Decryption failed")
        
        # Validate padding
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding or wrong password")
        
        # Check if all padding bytes are correct
        for i in range(pad_len):
            if padded[-(i+1)] != pad_len:
                raise ValueError("Invalid padding or wrong password")
        
        # Remove padding and decode
        message = padded[:-pad_len].decode('utf-8')
        return message
        
    except UnicodeDecodeError:
        raise ValueError("Decryption failed - wrong password or corrupted data")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# ---- Input Validation for Embedding ----
def embed_data_in_image(image_path, data, output_path):
    """Embed data in image with better validation"""
    # Input validation
    if not os.path.exists(image_path):
        raise FileNotFoundError("Source image not found")
    
    if len(data) == 0:
        raise ValueError("No data to embed")
    
    data_length = len(data)
    MAX_DATA_SIZE = 65535  # 2^16 - 1
    
    if data_length > MAX_DATA_SIZE:
        raise ValueError(f"Data too large. Maximum size: {MAX_DATA_SIZE} bytes")
    
    # Prepare data with length prefix
    data_with_length = data_length.to_bytes(2, 'big') + data
    
    try:
        img = Image.open(image_path).convert("RGB")
    except Exception as e:
        raise ValueError(f"Cannot open image: {str(e)}")
    
    pixels = list(img.getdata())
    
    # Convert data to bits
    bits = ''.join(f'{byte:08b}' for byte in data_with_length)
    
    # Check if image is large enough
    required_pixels = (len(bits) + 2) // 3  # 3 bits per pixel (RGB)
    if required_pixels > len(pixels):
        raise ValueError(f"Image too small. Need {required_pixels} pixels, have {len(pixels)}")
    
    # Embed bits in LSBs
    new_pixels = []
    bit_index = 0
    
    for pixel in pixels:
        r, g, b = pixel
        
        # Modify LSBs if we still have bits to embed
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
    
    # Create and save new image
    try:
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_pixels)
        new_img.save(output_path, "PNG")  # Force PNG format
        print(f"Successfully embedded {data_length} bytes in {output_path}")
    except Exception as e:
        raise ValueError(f"Cannot save image: {str(e)}")

# ---- App GUI Setup ----
root = tk.Tk()
root.title("StegoPix")
root.geometry("800x800")
root.resizable(False, False)

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

# ---- Tab 1: Hide Secret ----
hide_tab = ttk.Frame(notebook)
notebook.add(hide_tab, text="🔐 Hide Secret O_o")

selected_file = None

def select_image():
    global selected_file
    file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
    if file_path:
        selected_file = file_path
        file_label.config(text=f"📄 {os.path.basename(file_path)}")

def run_hide():
    if not selected_file:
        messagebox.showwarning("⚠️", "No image selected.")
        return

    secret = message_text.get("1.0", "end-1c").strip()
    password = password_entry.get()

    if not secret or not password:
        messagebox.showwarning("⚠️", "Secret and password requirepd.")
        return

    try:
        encrypted = encrypt_message(secret, password)
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if output_path:
            embed_data_in_image(selected_file, encrypted, output_path)
            messagebox.showinfo("✅ Success", f"Secret hidden in {output_path}")
    except Exception as e:
        messagebox.showerror("❌ Error", str(e))

#hide gui-------------------------------------------------------------------------------

tk.Label(hide_tab, text="What photo you wan hide it in (PNG ONLY) ", font=("Arial", 12)).pack(pady=(20, 5))
tk.Button(hide_tab, text="Browse my Images", command=select_image).pack()
file_label = tk.Label(hide_tab, text="", font=("Arial", 10), fg="gray")
file_label.pack()

tk.Label(hide_tab, text="📝 Secret Message...", font=("Arial", 12)).pack(pady=(20, 5))
message_text = tk.Text(hide_tab, width=60, height=10, wrap="word")
message_text.pack(pady=5)

tk.Label(hide_tab, text="Password to retrieve data later", font=("Arial", 12)).pack(pady=(20, 5))
password_entry = tk.Entry(hide_tab, show="*", width=50)
password_entry.pack(pady=5)

tk.Button(hide_tab, text="Hide Secret", font=("Arial", 12), command=run_hide).pack(pady=20)

tk.Label(hide_tab, text="This will create a new photo with data hidden in it",fg="blue",  font=("Arial", 10)).pack(pady=1)

# ---- Tab 2: Reveal Secret ----
reveal_tab = ttk.Frame(notebook)
notebook.add(reveal_tab, text="🔎 Reveal Secret O:")

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


#reveal gui-----------------------------------------------------------------


tk.Label(reveal_tab, text="Enter your password :b", font=("Arial", 12)).pack(pady=(30, 5))
reveal_password_entry = tk.Entry(reveal_tab, width=50, show="*")
reveal_password_entry.pack(pady=5)

tk.Button(reveal_tab, text="Reveal Secret (:", font=("Arial", 12), command=run_reveal).pack(pady=10)

reveal_save_var = tk.BooleanVar()
tk.Checkbutton(reveal_tab, text="💾 Save message to a text file?", variable=reveal_save_var).pack(pady=10)

# ---- Tab 3: Password Generator ----
password_tab = ttk.Frame(notebook)
notebook.add(password_tab, text="Generate a password :D ")

pLength = 15
lowercase = string.ascii_lowercase
uppercase = string.ascii_uppercase
specials = "!@#$%^&*"
numbers = list(str(i) for i in range(10))
validChars = list(lowercase + uppercase + specials) + numbers

def genPassword():
    return ''.join(secrets.choice(validChars) for _ in range(pLength))

def showPassword():
    password = genPassword()
    passwordLabel.config(text=password)
    copiedLabel.config(text="")

def copyToClipboard():
    password = passwordLabel.cget("text")
    if password:
        password_tab.clipboard_clear()
        password_tab.clipboard_append(password)
        copiedLabel.config(text="Copied to clipboard!")
    else:
        copiedLabel.config(text="No password to copy.")

welcome = tk.Label(password_tab, text="Generate a password")
welcome.pack(pady=10)

goButton = ttk.Button(password_tab, text="Generate :D", command=showPassword)
goButton.pack(pady=15)

passwordLabel = tk.Label(password_tab, text="", font=("Courier", 16), fg="green")
passwordLabel.pack(pady=10)

copyButton = ttk.Button(password_tab, text="Copy Password", command=copyToClipboard)
copyButton.pack(pady=5)

copiedLabel = tk.Label(password_tab, text="", font=("Helvetica", 10), fg="blue")
copiedLabel.pack(pady=5)

# ---- Run App ----
root.mainloop()
