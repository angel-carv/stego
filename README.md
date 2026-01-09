# StegoPix

A Python-based steganography application that allows you to hide encrypted messages inside PNG images using LSB (Least Significant Bit) steganography with AES-256 encryption.

## Features

- **Hide Secret Messages**: Encrypt and embed text inside PNG images
- **Reveal Hidden Messages**: Extract and decrypt messages from images
- **Secure Password Generator**: Generate cryptographically secure passwords
- **AES-256 Encryption**: Military-grade encryption using PBKDF2 key derivation
- **LSB Steganography**: Invisible embedding technique that minimally affects image appearance

## How It Works

StegoPix combines two security layers:

1. **Encryption (AES-256)**: Your message is encrypted using AES-256 in CBC mode with PBKDF2 key derivation (100,000 iterations)
2. **Steganography (LSB)**: The encrypted data is hidden in the least significant bits of the image's RGB pixels

The multiple layers of security means that if a malicious actor knew your image contained personal information, they would still need a password to decrypt the text. 

## Installation

### Requirements

- Python 3.x
- Required packages:

```bash
pip install pycryptodome Pillow
```

### Dependencies

- `pycryptodome`: For AES encryption
- `Pillow`: For image processing
- `tkinter`: For GUI (usually included with Python)

## Usage

### Running the Main Application

```bash
python stego.py
```

This launches the main GUI with three tabs:

#### 1. Hide Secret Tab
- Select a PNG image
- Enter your secret message
- Set a password
- Save the output image with hidden data

#### 2. Reveal Secret Tab
- Enter the password
- Select an image with hidden data
- View or save the revealed message

#### 3. Password Generator Tab
- Generate secure 15-character passwords
- Copy to clipboard for easy use

### Alternative Standalone Tools

```bash
# Hide messages only
python stegoEncrypt.py

# Reveal messages only
python stegoViewer.py

# Generate passwords only
python pgen.py
```

## Security Notes

- **Password Protection**: Your messages are encrypted with AES-256 before embedding
- **Salt & IV**: Each encryption uses unique random salt and initialization vector
- **PBKDF2**: 100,000 iterations slow down brute force attacks
- **PNG Only**: Use PNG format to preserve the hidden data (JPEG compression destroys it)

## Limitations

- **File Format**: Only PNG images are supported (JPEG compression corrupts hidden data)
- **Capacity**: Maximum 65,535 bytes per image (limited by 2-byte length header)
- **Image Size**: Larger images can hide more data (3 bits per pixel)

## Technical Details

### Encryption Process
1. Message converted to UTF-8 bytes
2. Random 16-byte salt generated
3. Password + salt → PBKDF2 → 256-bit key (100k iterations)
4. Random 16-byte IV generated
5. PKCS7 padding added
6. AES-CBC encryption applied
7. Output: [salt][IV][ciphertext]

### LSB Embedding Process
1. Encrypted data prefixed with 2-byte length header
2. Data converted to binary bits
3. Each bit replaces the LSB of RGB channels
4. Modified pixels saved as PNG

### Extraction & Decryption
1. LSBs extracted from image pixels
2. First 16 bits decoded to get data length
3. Specified number of bits extracted and converted to bytes
4. Salt and IV extracted from data
5. Password + salt → PBKDF2 → key
6. AES-CBC decryption with IV
7. PKCS7 padding removed
8. Original message recovered

## Files

- `stego.py`: Main application with all features in tabbed interface
- `stegoEncrypt.py`: Standalone tool for hiding messages
- `stegoViewer.py`: Standalone tool for revealing messages
- `pgen.py`: Standalone password generator

## Lessons Learned
### 1. Separation of Concerns
* Split functionality into separate files (`stegoEncrypt.py`, `stegoViewer.py`, `pgen.py`) before combining into one unified app (`stego.py`)
* This modular approach makes testing easier and lets users choose their preferred interface

### 2. User Experience Decisions
* The Show/Hide password toggle - small UX improvements matter
* Giving users choices (popup vs. save to file, tabs for different functions)
* Input validation before operations (checking file types, password presence)

### 3. Data Flow
* Clear pipeline: Input → Process → Output
* Hide: Message → Encrypt → Embed → Save
* Reveal: Load → Extract → Decrypt → Display
* Each step can fail independently and be debugged separately

### 4. Working with Binary Data
* Converting between different formats (strings, bytes, bits)
* Understanding data size constraints (2-byte length header = 65KB max)
* Bitwise operations for LSB manipulation
## Fun Facts!
Steganography dates back to 440 B.C. in Greece! Documented by the historian Herodotus, Histiaeus was an ancient Greek tyrant who was being held as a political prisoner under house arrest by King Darius I of Persia.

Histiaeus wanted to return home so he devised a plan that would make him famous in cryptography millennia later.

Histiaeus selected his most trusted slave, tattooed a message on his scalp, and let his hair grow back before sending him to his son-in-law Aristagoras in Miletus. This message contained a plan to incite rebellion in his home city, Miletus, so that he could be sent to stop it.

Essentially Histiaeus created a problem to position himself as the solution, as he was respected and had influence in Miletus that the Persians didn't have.

### Historical Examples
- **WWII Invisible Ink** - Spies wrote messages with lemon juice or milk between the lines of innocent letters. The hidden text only appeared when heated.
- **Microdots** - During the Cold War, agents reduced entire photographs to the size of a period (.) and hid them in regular documents. You'd need a microscope to spot them!
- **Null Ciphers** - Hidden messages created by taking specific letters from innocent-looking text. Example: "Can one decipher elegantly?" - first letters spell "CODE"
- **Prison Communication** - Inmates have used pinpricks above certain letters in books, or written with bodily fluids visible only under UV light

### Modern Examples
- **LSB (Least Significant Bit) encoding** - Hiding data in image pixels by slightly altering color values imperceptible to the human eye (what this app uses!)
- **Audio steganography** - Embedding messages in sound files by modifying frequencies we can't consciously hear
- **Network steganography** - Hiding data in network packets or protocol headers during transmission
- **Video steganography** - Concealing information across video frames in movies or streams
- **Digital watermarking** - Companies embed invisible ownership information in photos, music, and videos

## What is Steganography?
Steganography is the practice of hiding secret messages in plain sight. Unlike encryption which scrambles a message, steganography conceals that a message even exists at all.
## License

This project is provided as-is for educational and personal use.

## Disclaimer

This tool is intended for legitimate privacy purposes. Users are responsible for complying with applicable laws and regulations regarding encryption and data hiding.
