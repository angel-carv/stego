from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from PIL import Image
import tkinter as tk
from tkinter import filedialog, messagebox
import os


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
    img = Image.open(image_path)
    img = img.convert("RGB")
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
    data_length = int("".join(length_bits), 2)  # Convert binary string to integer
    
    if data_length == 0:
        raise ValueError("No data found in image")
    
    if data_length > 65535:  # Sanity check (2^16 - 1 max)
        raise ValueError("Invalid data length detected")

    # Calculate total bits needed and validate
    total_bits_needed = 16 + (data_length * 8)  # Length header + actual data
    if len(bits) < total_bits_needed:
        raise ValueError("Image doesn't contain enough data")

    # Extract the actual encrypted data bits (skip the 16-bit length header)
    data_bits = bits[16:16 + (data_length * 8)]

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


def decrypt_message(data, password):
    """
    Decrypts AES-encrypted data that was extracted from an image.
    
    The encrypted data format is: [16 bytes salt][16 bytes IV][encrypted message]
    This matches exactly what the encrypt_message function in the maker produces.
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
        padded_plaintext = cipher.decrypt(ciphertext)
        
        if len(padded_plaintext) == 0:
            raise ValueError("Decryption failed")
        
        # Remove PKCS7 padding to get original message
        # Last byte tells us how many padding bytes were added
        pad_len = padded_plaintext[-1]
        
        # Validate padding length
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding or wrong password")
        
        # Verify padding is correct (all padding bytes should have same value)
        for i in range(pad_len):
            if padded_plaintext[-(i+1)] != pad_len:
                raise ValueError("Invalid padding or wrong password")
        
        # Remove padding and convert to string
        message = padded_plaintext[:-pad_len].decode('utf-8')
        return message
        
    except UnicodeDecodeError:
        raise ValueError("Decryption failed - wrong password or corrupted data")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


def decrypt_message_from_image(image_path, password):
    """
    High-level function that combines extraction and decryption.
    
    This is the main function that:
    1. Extracts encrypted data from the image
    2. Decrypts it using the provided password
    3. Returns the original secret message
    """
    
    # Step 1: Extract the raw encrypted data from image LSBs
    embedded_data = extract_lsb_data(image_path)
    
    # Step 2: Decrypt the extracted data using the password
    secret_message = decrypt_message(embedded_data, password)
    
    return secret_message


# ---- GUI Setup ----
root = tk.Tk()
root.title("StegoVault Viewer")
root.geometry("500x400")
root.resizable(False, False)


def reveal_secret():
    """
    Main GUI function that handles the secret revealing process.
    
    Process:
    1. Let user select an image file
    2. Get password from GUI input
    3. Extract and decrypt the hidden message
    4. Either display in popup or save to file
    """
    
    # Step 1: Let user select image containing hidden data
    image_path = filedialog.askopenfilename(
        title="🖼️ Select Image with Secret",
        filetypes=[("PNG Images", "*.png")]
    )
    
    # Handle case where user cancels file dialog
    if not image_path:
        return

    # Step 2: Get password from GUI input field
    password = password_entry.get()
    if not password:
        messagebox.showwarning("⚠️ Missing Password", "Please enter the password to decrypt the message.")
        return

    try:
        # Step 3: Extract and decrypt the hidden message
        secret = decrypt_message_from_image(image_path, password)

        # Step 4: Output the result based on user preference
        if save_to_file.get():  # User checked the "save to file" checkbox
            # Let user choose where to save the revealed message
            save_path = filedialog.asksaveasfilename(
                defaultextension=".txt", 
                filetypes=[("Text Files", "*.txt")]
            )
            if save_path:
                # Write the secret message to the chosen file
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(secret)
                messagebox.showinfo("✅ Saved", f"Secret saved to: {save_path}")
        else:
            # Display the message in a popup dialog
            messagebox.showinfo("🔍 Secret Revealed", f"Hidden Message:\n\n{secret}")

    except Exception as e:
        # Show error if extraction/decryption fails
        # Common causes: wrong password, corrupted image, no hidden data
        messagebox.showerror("❌ Error", f"Failed to reveal secret: {e}")


# ---- GUI Layout Section ----
# Create and arrange all the visual elements

# App title
welcome_label = tk.Label(root, text="🔐 StegoVault Viewer", font=("Arial", 16))
welcome_label.pack(pady=20)

# Password input section
password_label = tk.Label(root, text="🔑 Password:", font=("Arial", 12))
password_label.pack(pady=(10, 5))

# Password entry field (show="*" hides the actual password)
password_entry = tk.Entry(root, width=40, show="*")
password_entry.pack(pady=5)

# Checkbox to let user choose between popup display or file save
save_to_file = tk.BooleanVar()  # Boolean variable for checkbox state
save_checkbox = tk.Checkbutton(
    root, 
    text="💾 Save output to text file", 
    variable=save_to_file
)
save_checkbox.pack(pady=10)

# Main button to start the reveal process
reveal_button = tk.Button(
    root, 
    text="🔍 Reveal Secret", 
    font=("Arial", 12), 
    command=reveal_secret
)
reveal_button.pack(pady=20)

# Instructions for user
instructions = tk.Label(
    root, 
    text="Select an image created with StegoVault Maker\nand enter the password used to hide the secret.", 
    font=("Arial", 10), 
    fg="gray"
)
instructions.pack(pady=10)

# ---- Run the Application ----
# Start the GUI event loop to keep window open and responsive
root.mainloop()