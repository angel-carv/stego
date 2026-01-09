import secrets
import string
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

pLength = 15
lowercase = string.ascii_lowercase
uppercase = string.ascii_uppercase
specials = "!@#$%^&*"
numbers = list(str(i) for i in range(10))

validChars = list(lowercase + uppercase + specials) + numbers


root = tk.Tk()
root.geometry("600x600")
root.title("Secure Password Generator")


    
def genPassword():
    return ''.join(secrets.choice(validChars) for _ in range(pLength))


def showPassword():
    password = genPassword()
    passwordLabel.config(text=password)
    copiedLabel.config(text="")  # clear old "Copied!" message  

def copyToClipboard():
    password = passwordLabel.cget("text")  # get current label text
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        copiedLabel.config(text="Copied to clipboard!")
    else:
        copiedLabel.config(text="No password to copy.")



welcome = tk.Label(root, text="Generate a password" )
welcome.pack(pady=10)

goButton = ttk.Button(root, text="Generate :D", command=showPassword)
goButton.pack(pady= 15)

passwordLabel = tk.Label(root, text="", font=("Courier", 16), fg="green")
passwordLabel.pack(pady=10)


copyButton = ttk.Button(root, text="Copy Password", command=copyToClipboard)
copyButton.pack(pady=5)

copiedLabel = tk.Label(root, text="", font=("Helvetica", 10), fg="blue")
copiedLabel.pack(pady=5)

root.mainloop()

