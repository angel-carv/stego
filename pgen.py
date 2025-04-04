import secrets
import string
import tkinter as tk
from tkinter import ttk

root = tk.Tk()
root.geometry("600x600")
root.title("HELLO")

lowercase = string.ascii_lowercase
uppercase = string.ascii_uppercase
specials = "!@#$%^&*"
numbers = list(str(i) for i in range(10))

validChars = list(lowercase + uppercase + specials + numbers)
print(validChars)
    




#def generatePass():

    

    







#welcome = tk.Label(root, text="Generate a password" )
#welcome.pack(pady=10)
#testEntry = ttk.Entry(root , width= 50)
#testEntry.pack(pady=20)

#goButton = ttk.Button(root, text="Generate 0:")
#goButton.pack(pady= 15)

#root.mainloop()

