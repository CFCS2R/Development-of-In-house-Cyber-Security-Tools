import tkinter as tk
from tkinter import messagebox
import hashlib

class PasswordManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Encryption Manager")
        self.configure(bg="#6495ED")  

        self.label_username = tk.Label(self, text="Username:", bg="#F0F0F0", fg="#333333", font=("Arial", 12))  # Set background and foreground color for labels
        self.label_username.pack(pady=5)
        self.entry_username = tk.Entry(self, bg="white", fg="#333333", font=("Arial", 12))  # Set background and foreground color for entry fields
        self.entry_username.pack(pady=5)

        self.label_password = tk.Label(self, text="Password:", bg="#F0F0F0", fg="#333333", font=("Arial", 12))  # Set background and foreground color for labels
        self.label_password.pack(pady=5)
        self.entry_password = tk.Entry(self, show="*", bg="white", fg="#333333", font=("Arial", 12))  # Set background and foreground color for entry fields
        self.entry_password.pack(pady=5)

        self.button_encrypt = tk.Button(self, text="Encrypt", command=self.encrypt_password, bg="#4CAF50", fg="white", font=("Arial", 12))  # Set background and foreground color for the button
        self.button_encrypt.pack(pady=10)

    def encrypt_password(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty!")
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        messagebox.showinfo("Encrypted Password", f"Username: {username}\nEncrypted Password: {hashed_password}")

if __name__ == "__main__":
    app = PasswordManager()
    app.mainloop()
