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
    """
    Encrypts a text message using AES-256 encryption in CBC mode.
    
    Process:
    1. Convert message to bytes
    2. Generate random salt for key derivation
    3. Derive encryption key from password using PBKDF2
    4. Generate random IV (initialization vector)
    5. Add PKCS7 padding to make data multiple of 16 bytes
    6. Encrypt using AES-CBC
    7. Return salt + IV + ciphertext (all needed for decryption)
    """
    # Convert secret message to bytes for encryption
    data = message.encode('utf-8')
    
    # Generate random 16-byte salt and use PBKDF2 to derive key from password
    # Salt prevents rainbow table attacks, PBKDF2 makes brute force slower
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)  # 32 bytes = AES-256
    
    # Generate a random initialization vector (IV) for CBC mode
    # IV ensures same plaintext produces different ciphertext each time
    iv = get_random_bytes(16)

    # Add PKCS7 padding: AES requires data to be multiple of 16 bytes
    # If data is 13 bytes, add 3 bytes each with value \x03
    # If data is exactly 16 bytes, add 16 bytes each with value \x10
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)

    # Encrypt with AES in CBC mode (Cipher Block Chaining)
    # CBC chains blocks together like a linked list for security
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_data)
    
    # Return all data needed to decrypt: salt + iv + encrypted_message
    # Decryption needs salt to recreate key, IV to decrypt, and ciphertext
    return salt + iv + ciphertext

# ---- AES Decryption Function -----
def decrypt_message(data, password):
    """
    Decrypts AES-encrypted data that was extracted from an image.
    
    The encrypted data format is: [16 bytes salt][16 bytes IV][encrypted message]
    This matches exactly what the encrypt_message function produces.
    """
    
    # Validate minimum data length (need salt + IV at minimum)
    if len(data) < 32:
        raise ValueError("Data too short to be valid encrypted message")
    
    try:
        # Extract the components (same format as encryption function)
        salt = data[:16]        # First 16 bytes: salt for key derivation
        iv = data[16:32]        # Next 16 bytes: initialization vector
        ciphertext = data[32:]  # Remaining bytes: actual encrypted message
        
        # Validate ciphertext length (must be multiple of 16 for AES blocks)
        if len(ciphertext) % 16 != 0:
            raise ValueError("Invalid ciphertext length")
        
        # Recreate the same key using password and extracted salt
        # Must use same parameters as encryption: 32 bytes, 100k iterations
        key = PBKDF2(password, salt, dkLen=32, count=100_000)
        
        # Decrypt using AES-CBC mode with the extracted IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        
        if len(padded) == 0:
            raise ValueError("Decryption failed")
        
        # Remove PKCS7 padding to get original message
        # Last byte tells us how many padding bytes were added
        pad_len = padded[-1]
        
        # Validate padding length
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding or wrong password")
        
        # Verify padding is correct (all padding bytes should have same value)
        for i in range(pad_len):
            if padded[-(i+1)] != pad_len:
                raise ValueError("Invalid padding or wrong password")
        
        # Remove padding and convert to string
        message = padded[:-pad_len].decode('utf-8')
        return message
        
    except UnicodeDecodeError:
        raise ValueError("Decryption failed - wrong password or corrupted data")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# ---- LSB Embedding Function ----
def embed_data_in_image(image_path, data, output_path):
    """
    Hides encrypted data inside an image using LSB (Least Significant Bit) steganography.
    
    How LSB works:
    - Each pixel has RGB values (0-255)
    - We modify the last bit of each color channel
    - Human eye can't detect these tiny changes
    - Example: 255 (11111111) becomes 254 (11111110) - visually identical
    """
    
    # Input validation
    if not os.path.exists(image_path):
        raise FileNotFoundError("Source image not found")
    
    if len(data) == 0:
        raise ValueError("No data to embed")
    
    data_length = len(data)
    MAX_DATA_SIZE = 65535  # 2^16 - 1
    
    if data_length > MAX_DATA_SIZE:
        raise ValueError(f"Data too large. Maximum size: {MAX_DATA_SIZE} bytes")
    
    # Prepare data with length header
    # We need to tell the extraction function how much data to read
    # Convert length to 2 bytes (big-endian format)
    # This gives us max capacity of 65,535 bytes (2^16 - 1)
    data_with_length = data_length.to_bytes(2, 'big') + data
    
    try:
        # Open image and convert to RGB format
        # PIL Image.open() returns a PIL Image object containing all pixel data
        # Convert to RGB to ensure consistent 3-channel format (some PNGs have alpha)
        img = Image.open(image_path).convert("RGB")
    except Exception as e:
        raise ValueError(f"Cannot open image: {str(e)}")
    
    pixels = list(img.getdata())
    
    # Convert each byte to 8 bits of binary
    # data_with_length might be [0, 192, 10, 65, 66, 67...]
    # This becomes "0000000011000000000010100100000101000010..."
    bits = ''.join(f'{byte:08b}' for byte in data_with_length)
    
    # Check if image is large enough
    # Calculate pixels needed: each pixel stores 3 bits (R, G, B channels)
    required_pixels = (len(bits) + 2) // 3  # +2 accounts for integer division
    if required_pixels > len(pixels):
        raise ValueError(f"Image too small. Need {required_pixels} pixels, have {len(pixels)}")

    # Process each pixel and embed our secret bits
    new_pixels = []  # Will store our modified pixels
    bit_index = 0    # Tracks which bit we're currently embedding

    # Loop through each pixel in the original image
    for pixel in pixels:
        r, g, b = pixel  # Extract RGB values
        
        # Embed bits using bitwise operations:
        # (r & ~1) clears the LSB of r (sets last bit to 0)
        # | int(bits[bit_index]) sets the LSB to our secret bit
        # Example: if r=255 (11111111) and secret_bit=0
        #          r & ~1 = 254 (11111110), then | 0 = 254
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
        new_img = Image.new(img.mode, img.size)  # Create empty image same size as original
        new_img.putdata(new_pixels)              # Fill with our modified pixels
        new_img.save(output_path, "PNG")         # Force PNG format to preserve data
        print(f"Successfully embedded {data_length} bytes in {output_path}")
    except Exception as e:
        raise ValueError(f"Cannot save image: {str(e)}")

# ---- LSB Extraction Function ----
def extract_lsb_data(image_path):
    """
    Extracts hidden data from an image using LSB (Least Significant Bit) steganography.
    
    This function reverses the embedding process:
    1. Reads the first 16 bits to get the length of hidden data
    2. Extracts that many bytes of data from the image's LSBs
    3. Returns the raw encrypted data
    
    The data format in the image is: [2 bytes length][encrypted data]
    """
    
    # Validate input file exists
    if not os.path.exists(image_path):
        raise FileNotFoundError("Image file not found")
    
    # Open image and convert to RGB (same as embedding process)
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    
    # Extract LSBs from all pixels to get our hidden bits
    # Each pixel contributes 3 bits (from R, G, B channels)
    bits = []
    for pixel in pixels:
        for channel in pixel:  # R, G, B values
            # Extract the least significant bit (last bit) from each channel
            # Example: 255 & 1 = 1, 254 & 1 = 0
            bits.append(str(channel & 1))  # Convert to string for easier joining
    
    # First 16 bits represent the data length (2 bytes in big-endian)
    if len(bits) < 16:
        raise ValueError("Image too small to contain embedded data")
    
    # Convert first 16 bits back to a number to get data length
    length_bits = bits[:16]
    length = int("".join(length_bits), 2)  # Convert binary string to integer
    
    if length == 0:
        raise ValueError("No data found in image")
    
    if length > 65535:  # Sanity check (2^16 - 1 max)
        raise ValueError("Invalid data length detected")
    
    # Calculate total bits needed and validate
    total_bits_needed = 16 + (length * 8)  # Length header + actual data
    if len(bits) < total_bits_needed:
        raise ValueError("Image doesn't contain enough data")
    
    # Extract the actual encrypted data bits (skip the 16-bit length header)
    data_bits = bits[16:16 + (length * 8)]
    
    # Convert bits back to bytes
    # Take groups of 8 bits and convert each group to a byte value
    message_bytes = []
    for i in range(0, len(data_bits), 8):
        byte_bits = data_bits[i:i+8]  # Get next 8 bits
        if len(byte_bits) == 8:  # Ensure we have a complete byte
            # Convert 8-bit binary string to integer (0-255)
            byte_value = int("".join(byte_bits), 2)
            message_bytes.append(byte_value)

    return bytes(message_bytes)

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
    """
    Opens file dialog for user to select a PNG image.
    Updates global variable and GUI label with selected file.
    """
    global selected_file
    file_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
    if file_path:
        selected_file = file_path
        file_label.config(text=f"📄 {os.path.basename(file_path)}")

def run_hide():
    """
    Main function that orchestrates the hiding process:
    1. Validates user input
    2. Encrypts the secret message
    3. Embeds encrypted data in image
    4. Saves result to user-chosen location
    """
    if not selected_file:
        messagebox.showwarning("⚠️", "No image selected.")
        return

    secret = message_text.get("1.0", "end-1c").strip()
    password = password_entry.get()

    if not secret or not password:
        messagebox.showwarning("⚠️", "Secret and password required.")
        return

    try:
        # Step 1: Encrypt the secret message
        encrypted = encrypt_message(secret, password)
        
        # Step 2: Ask user where to save the result
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if output_path:
            # Step 3: Hide encrypted data in the image
            embed_data_in_image(selected_file, encrypted, output_path)
            messagebox.showinfo("✅ Success", f"Secret hidden in {output_path}")
    except Exception as e:
        messagebox.showerror("❌ Error", str(e))

# Hide GUI Layout
tk.Label(hide_tab, text="What photo you want to hide it in (PNG ONLY)", font=("Arial", 12)).pack(pady=(20, 5))
tk.Button(hide_tab, text="Browse my Images", command=select_image).pack()
file_label = tk.Label(hide_tab, text="", font=("Arial", 10), fg="gray")
file_label.pack()

tk.Label(hide_tab, text="📝 Secret Message...", font=("Arial", 12)).pack(pady=(20, 5))
message_text = tk.Text(hide_tab, width=60, height=10, wrap="word")
message_text.pack(pady=5)

tk.Label(hide_tab, text="Password to retrieve data later", font=("Arial", 12)).pack(pady=(20, 5))

# Password entry frame to hold entry and button together
password_frame = tk.Frame(hide_tab)
password_frame.pack(pady=5)

password_entry = tk.Entry(password_frame, show="*", width=50)
password_entry.pack(side="left", padx=(0, 5))

def toggle_hide_password():
    if password_entry.cget("show") == "*":
        password_entry.config(show="")
        toggle_hide_btn.config(text="Hide")
    else:
        password_entry.config(show="*")
        toggle_hide_btn.config(text="Show")

toggle_hide_btn = tk.Button(password_frame, text="Show", command=toggle_hide_password, width=5)
toggle_hide_btn.pack(side="left")

tk.Button(hide_tab, text="Hide Secret", font=("Arial", 12), command=run_hide).pack(pady=20)

tk.Label(hide_tab, text="This will create a new photo with data hidden in it", fg="blue", font=("Arial", 10)).pack(pady=1)

# ---- Tab 2: Reveal Secret ----
reveal_tab = ttk.Frame(notebook)
notebook.add(reveal_tab, text="🔎 Reveal Secret O:")

def run_reveal():
    """
    Main GUI function that handles the secret revealing process.
    
    Process:
    1. Let user select an image file
    2. Get password from GUI input
    3. Extract and decrypt the hidden message
    4. Either display in popup or save to file
    """
    image_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
    if not image_path:
        return

    password = reveal_password_entry.get()
    if not password:
        messagebox.showwarning("⚠️", "Password is required.")
        return

    try:
        # Extract and decrypt the hidden message
        encrypted_data = extract_lsb_data(image_path)
        secret = decrypt_message(encrypted_data, password)
        
        # Filter to only printable characters for safety
        safe_secret = ''.join(c for c in secret if c.isprintable() or c in '\n\r\t')

        if reveal_save_var.get():
            # Save to file option
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(safe_secret)
                messagebox.showinfo("✅ Saved", f"Secret saved to: {save_path}")
        else:
            # Display in popup
            messagebox.showinfo("🔍 Message", safe_secret)

    except Exception as e:
        messagebox.showerror("❌ Error", str(e))

# Reveal GUI Layout
tk.Label(reveal_tab, text="Enter your password :b", font=("Arial", 12)).pack(pady=(30, 5))

# Password entry frame for reveal tab
reveal_password_frame = tk.Frame(reveal_tab)
reveal_password_frame.pack(pady=5)

reveal_password_entry = tk.Entry(reveal_password_frame, width=50, show="*")
reveal_password_entry.pack(side="left", padx=(0, 5))

def toggle_reveal_password():
    if reveal_password_entry.cget("show") == "*":
        reveal_password_entry.config(show="")
        toggle_reveal_btn.config(text="Hide")
    else:
        reveal_password_entry.config(show="*")
        toggle_reveal_btn.config(text="Show")

toggle_reveal_btn = tk.Button(reveal_password_frame, text="Show", command=toggle_reveal_password, width=5)
toggle_reveal_btn.pack(side="left")

tk.Button(reveal_tab, text="Reveal Secret (:", font=("Arial", 12), command=run_reveal).pack(pady=10)

reveal_save_var = tk.BooleanVar()
tk.Checkbutton(reveal_tab, text="💾 Save message to a text file?", variable=reveal_save_var).pack(pady=10)

# ---- Tab 3: Password Generator ----
password_tab = ttk.Frame(notebook)
notebook.add(password_tab, text="Generate a password :D")

# Password generator settings
pLength = 15
lowercase = string.ascii_lowercase
uppercase = string.ascii_uppercase
specials = "!@#$%^&*"
numbers = list(str(i) for i in range(10))
validChars = list(lowercase + uppercase + specials) + numbers

def genPassword():
    """Generate a secure random password using cryptographically secure random"""
    return ''.join(secrets.choice(validChars) for _ in range(pLength))

def showPassword():
    """Generate and display a new password"""
    password = genPassword()
    passwordLabel.config(text=password)
    copiedLabel.config(text="")

def copyToClipboard():
    """Copy the displayed password to clipboard"""
    password = passwordLabel.cget("text")
    if password:
        password_tab.clipboard_clear()
        password_tab.clipboard_append(password)
        copiedLabel.config(text="Copied to clipboard!")
    else:
        copiedLabel.config(text="No password to copy.")

# Password Generator GUI Layout
welcome = tk.Label(password_tab, text="Generate a secure password")
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