import tkinter as tk
from tkinter import messagebox
import random
import string

def save_credentials():
    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    if website and email and password:
        with open("passwords.txt", "a") as file:
            file.write(f"{website} | {email} | {password}\n")

        messagebox.showinfo("Success", "Credentials saved successfully!")
        clear_entries()
    else:
        messagebox.showwarning("Error", "Please fill in all the fields.")

def clear_entries():
    website_entry.delete(0, tk.END)
    email_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

def search_credentials():
    search_text = search_entry.get()
    if search_text:
        with open("passwords.txt", "r") as file:
            for line in file:
                if search_text in line:
                    _, _, password = line.strip().split(" | ")
                    print(f"Debug: Found line: {line}")
                    password_display.set("*" * len(password))
                    return
    password_display.set("")
    messagebox.showinfo("Result", "No credentials found for the given website.")

def copy_password():
    search_text = search_entry.get()
    if search_text:
        with open("passwords.txt", "r") as file:
            for line in file:
                if search_text in line:
                    _, _, password = line.strip().split(" | ")
                    print(f"Debug: Copying password from file: {password}")

                    root.clipboard_clear()
                    root.clipboard_append(password)
                    root.update()
                    messagebox.showinfo("Copy Password", "Password copied to clipboard.")
                    return

    messagebox.showinfo("Result", "No credentials found for the given website.")

def generate_password():
    password_length = 12  # You can adjust the length as needed
    characters = string.ascii_letters + string.digits + string.punctuation
    generated_password = ''.join(random.choice(characters) for _ in range(password_length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated_password)

# GUI setup
root = tk.Tk()
root.title("Shubham's Password Manager")

website_label = tk.Label(root, text="Website:")
website_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")
website_entry = tk.Entry(root)
website_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=5)

email_label = tk.Label(root, text="Email:")
email_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
email_entry = tk.Entry(root)
email_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5)

password_label = tk.Label(root, text="Password:")
password_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=2, column=1, columnspan=2, padx=10, pady=5)

save_button = tk.Button(root, text="Save", command=save_credentials)
save_button.grid(row=3, column=0, columnspan=3, pady=10)

search_label = tk.Label(root, text="Search:")
search_label.grid(row=4, column=0, padx=10, pady=5, sticky="e")
search_entry = tk.Entry(root)
search_entry.grid(row=4, column=1, padx=10, pady=5)
search_button = tk.Button(root, text="Search", command=search_credentials)
search_button.grid(row=4, column=2, pady=5)

password_display = tk.StringVar()
password_result_label = tk.Label(root, textvariable=password_display)
password_result_label.grid(row=5, column=0, columnspan=2, padx=10, pady=5)

copy_button = tk.Button(root, text="Copy Password", command=copy_password)
copy_button.grid(row=5, column=2, pady=5)

generate_button = tk.Button(root, text="Generate Password", command=generate_password)
generate_button.grid(row=6, column=0, columnspan=3, pady=10)

root.mainloop()
