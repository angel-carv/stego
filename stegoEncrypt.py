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
selected_file = None  # Stores the path to the image file user selects


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
    
    # Open image and convert to RGB format
    # PIL Image.open() returns a PIL Image object containing all pixel data
    # Convert to RGB to ensure consistent 3-channel format (some PNGs have alpha)
    # getdata() returns list of tuples: [(255,255,255), (120,10,4), ...]
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    # Prepare data for embedding with length header
    # We need to tell the extraction function how much data to read
    data_length = len(data)  # Number of bytes in our encrypted data
    
    # Convert length to 2 bytes (big-endian format)
    # This gives us max capacity of 65,535 bytes (2^16 - 1)
    # Big-endian means most significant byte first
    data_with_length = data_length.to_bytes(2, 'big') + data
    
    # Convert each byte to 8 bits of binary
    # data_with_length might be [0, 192, 10, 65, 66, 67...]
    # This becomes "0000000011000000000010100100000101000010..."
    bits = ''.join(f'{byte:08b}' for byte in data_with_length)  # FIXED: was using 'data' instead of 'data_with_length'
    
    # Calculate pixels needed: each pixel stores 3 bits (R, G, B channels)
    # +2 accounts for integer division rounding
    required_pixels = (len(bits) + 2) // 3

    # Make sure the image has enough space
    if required_pixels > len(pixels):
        raise ValueError("Image too small for this data.")

    # Process each pixel and embed our secret bits
    new_pixels = []  # Will store our modified pixels
    bit_index = 0    # Tracks which bit we're currently embedding

    # Loop through each pixel in the original image
    for pixel in pixels:
        if bit_index < len(bits):
            r, g, b = pixel  # Extract RGB values
            
            # Embed bits using bitwise operations:
            # (r & ~1) clears the LSB of r (sets last bit to 0)
            # | int(bits[bit_index]) sets the LSB to our secret bit
            # Example: if r=255 (11111111) and secret_bit=0
            #          r & ~1 = 254 (11111110), then | 0 = 254
            r = (r & ~1) | int(bits[bit_index]) if bit_index < len(bits) else r
            g = (g & ~1) | int(bits[bit_index+1]) if bit_index+1 < len(bits) else g
            b = (b & ~1) | int(bits[bit_index+2]) if bit_index+2 < len(bits) else b
            
            new_pixels.append((r, g, b))
            bit_index += 3  # Move to next 3 bits
        else:
            # No more data to embed, keep original pixel unchanged
            new_pixels.append(pixel)

    # Create new image with our modified pixels and save it
    new_img = Image.new(img.mode, img.size)  # Create empty image same size as original
    new_img.putdata(new_pixels)              # Fill with modified pixels
    new_img.save(output_path)                # Save as PNG to preserve data


# ---- File Picker Function ----
def pick_image():
    """
    Opens file dialog for user to select a PNG image.
    Updates global variable and GUI label with selected file.
    """
    global selected_file
    
    # Open file picker dialog, only show PNG files
    file_path = filedialog.askopenfilename(
        title="Choose your image",
        filetypes=[("PNG Images", "*.png")]
    )
    
    # Handle case where user cancels dialog
    if not file_path:
        messagebox.showwarning("No File", "You didn't select anything.")
        return
    
    # Double-check file extension (defense in depth)
    if not file_path.lower().endswith(".png"):
        messagebox.showerror("Invalid File", "Please select a valid PNG image.")
        return

    # Store selected file path and update GUI
    selected_file = file_path
    filename = os.path.basename(file_path)  # Get just the filename, not full path
    filename_label.config(text=f"📄 Selected: {filename}")


# ---- Hide Secret Function ----
def hide_secret():
    """
    Main function that orchestrates the hiding process:
    1. Validates user input
    2. Encrypts the secret message
    3. Embeds encrypted data in image
    4. Saves result to user-chosen location
    """
    
    # Validate that user has selected an image
    if not selected_file:
        messagebox.showwarning("No Image", "Please select an image first.")
        return

    # Get user input from GUI
    secret = message_entry.get()    # The message to hide
    password = password_entry.get() # Password for encryption

    # Validate that both fields have content
    if not secret or not password:
        messagebox.showwarning("Missing Info", "Please enter both a secret and a password.")
        return

    try:
        # Step 1: Encrypt the secret message
        encrypted_data = encrypt_message(secret, password)
        
        # Step 2: Ask user where to save the result
        output_path = filedialog.asksaveasfilename(
            defaultextension=".png", 
            filetypes=[("PNG Image", "*.png")]
        )
        if not output_path:  # User canceled save dialog
            return
        
        # Step 3: Hide encrypted data in the image
        embed_data_in_image(selected_file, encrypted_data, output_path)
        
        # Step 4: Show success message
        messagebox.showinfo("Success", f"Secret hidden successfully!\nSaved to: {output_path}")
        
    except Exception as e:
        # Show any errors that occurred during the process
        messagebox.showerror("Error", f"Failed to hide secret: {e}")


# ---- GUI Layout Section ----
# Create and position all the visual elements of our app

# App title at the top
welcome_label = tk.Label(root, text="Welcome to StegoVault Maker", font=("Arial", 16))
welcome_label.pack(pady=20)

# Button to select image file
select_button = tk.Button(root, text="Select Image", font=("Arial", 12), command=pick_image)
select_button.pack(pady=10)

# Label to show selected filename (initially empty)
filename_label = tk.Label(root, text="", font=("Arial", 10), fg="gray")
filename_label.pack(pady=(0, 10))

# Secret message input section
message_label = tk.Label(root, text="📝 Secret Message:", font=("Arial", 12))
message_label.pack(pady=(5, 5))

message_entry = tk.Entry(root, width=40)  # Single-line text input
message_entry.pack(pady=5)

# Password input section
password_label = tk.Label(root, text="🔑 Password:", font=("Arial", 12))
password_label.pack(pady=(15, 5))

password_entry = tk.Entry(root, width=40, show="*")  # show="*" hides password
password_entry.pack(pady=5)

# Button to start the hiding process
hide_button = tk.Button(root, text="Hide Secret 🔐", font=("Arial", 12), command=hide_secret)
hide_button.pack(pady=20)

# ---- Run the App ----
# Start the GUI event loop - this keeps the window open and responsive
root.mainloop()