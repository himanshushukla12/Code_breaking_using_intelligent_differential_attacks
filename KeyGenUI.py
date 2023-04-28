#clean UI of key Gen
import pyperclip
from tkinter import *
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import secrets
import os

os.chdir(os.getcwd())
root = Tk()
root.title("Key Generator")
root.geometry("500x300")

# Vigenere key generation function
def generate_vigenere_key():
    key = ''
    for i in range(16):
        key += secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    key_output.delete('1.0', END)
    key_output.insert(END, key)

# DES key generation function
def generate_des_key():
    key = get_random_bytes(8)
    key_hex = key.hex()
    key_output.delete('1.0', END)
    key_output.insert(END, key_hex)

# RSA key generation function
def generate_rsa_key():
    key = RSA.generate(1024)
    key_hex = key.export_key().hex()
    key_output.delete('1.0', END)
    key_output.insert(END, key_hex)

# Save key to file function
def save_key():
    key_type = key_type_var.get()
    key_hex = key_output.get("1.0", END).strip()
    with open("keys.txt", "a") as f:
        f.write(key_type + ": " + key_hex + "\n")
    key_output.delete('1.0', END)

def copy_key():
    key_hex = key_output.get("1.0", END).strip()
    pyperclip.copy(key_hex)

# Key type selection menu
key_type_var = StringVar()
key_type_var.set("Vigenere")

key_type_menu = OptionMenu(root, key_type_var, "Vigenere", "DES", "RSA")
key_type_menu.pack(pady=20)

# Generate key button
generate_button = Button(root, text="Generate Key", command=lambda:
                         generate_vigenere_key() if key_type_var.get() == "Vigenere" else
                         generate_des_key() if key_type_var.get() == "DES" else
                         generate_rsa_key())
generate_button.pack(pady=10)

# Key output field
key_output = Text(root, height=5)
key_output.pack(pady=10)

# Copy button
copy_button = Button(root, text="Copy Key", command=copy_key)
copy_button.pack(pady=10)

# Save button
save_button = Button(root, text="Save Key to File", command=save_key)
save_button.pack(pady=10)

root.mainloop()