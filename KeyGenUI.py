import pyperclip
from tkinter import *
from PIL import Image, ImageTk
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import secrets

root = Tk()
root.title("Key Generator")
root.geometry("500x300")

# Load the animated GIF background
background_image = Image.open("E:\\bg3.gif")  # Replace 'flowers.gif' with the path to your animated GIF
background_frames = []

# Extract the frames of the animated GIF
for i in range(background_image.n_frames):
    background_image.seek(i)
    background_frames.append(ImageTk.PhotoImage(background_image.copy()))

# Function to animate the background
def animate_background(index=0):
    background_label.config(image=background_frames[index])
    index += 1
    if index >= len(background_frames):
        index = 0
    root.after(50, animate_background, index)

# Set the background label
background_label = Label(root)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

# Vigenere key generation function
def generate_vigenere_key():
    key = ''
    for i in range(16):
        key += secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    key_output.delete('1.0', END)
    key_output.insert(END, key)

# DES key generation function
def generate_des_key():
    key = get_random_bytes(16)
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
key_type_menu.config(bg="#808080", activebackground="#808080")
key_type_menu.pack(pady=20)

# Generate key button
generate_button = Button(root, text="Generate Key", command=lambda:
                         generate_vigenere_key() if key_type_var.get() == "Vigenere" else
                         generate_des_key() if key_type_var.get() == "DES" else
                         generate_rsa_key())
generate_button.config(bg="#808080", activebackground="#808080")
generate_button.pack(pady=10)

# Key output field
key_output = Text(root, height=5, bg="#808080", fg="#FFFFFF")
key_output.pack(pady=10)

# Copy button
copy_button = Button(root, text="Copy Key", command=copy_key)
copy_button.config(bg="#808080", activebackground="#808080")
copy_button.pack(pady=10)

# Save button
save_button = Button(root, text="Save Key to File", command=save_key)
save_button.config(bg="#808080", activebackground="#808080")
save_button.pack(pady=10)

# Function to raise the widgets above the background
def raise_widgets(widgets):
    for widget in widgets:
        widget.lift()

# Raise the widgets above the background
widgets = [key_type_menu, generate_button, key_output, copy_button, save_button]
raise_widgets(widgets)

# Start the background animation
animate_background()

root.mainloop()
