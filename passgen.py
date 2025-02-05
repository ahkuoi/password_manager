import os
import sqlite3
import time
import random
import string
import hashlib
from getpass import getpass
from cryptography.fernet import Fernet

DB_FILE = "passwords.db"

# Updated ASCII Art Banner
def display_banner():
    banner = """
    ██████╗  █████╗ ███████╗███████╗ ██████╗  ██████╗ ███████╗
    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ██████╔╝███████║███████╗███████╗██║   ██║██████╔╝███████╗
    ██╔═══╝ ██╔══██║╚════██║╚════██║██║   ██║██╔═══╝ ╚════██║
    ██║     ██║  ██║███████║███████║╚██████╔╝██║     ███████║
    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚══════╝
                      Secure CLI Password Manager
    """
    print("\033[92m" + banner + "\033[0m")  # Green color text

# Loading Effect for Smooth Experience
def loading_animation():
    print("\n[🔒] Setting up...", end="")
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print(" ✅\n")

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to create the database and master password table
def create_database(master_password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create the users table (only stores one master password)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS master (
        id INTEGER PRIMARY KEY,
        password TEXT NOT NULL
    )
    """)

    # Store the hashed master password
    hashed_password = hash_password(master_password)
    cursor.execute("INSERT INTO master (password) VALUES (?)", (hashed_password,))
    
    conn.commit()
    conn.close()
    print("[✅] Master password set and database created!")

# Function to check if it's the first time
def check_first_time():
    if not os.path.exists(DB_FILE):
        print("[🔒] First time using PassGen!")
        master_password = getpass("Create a master password: ")

        # Create the database and store the password
        create_database(master_password)
        loading_animation()
    else:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Get the stored master password
        cursor.execute("SELECT password FROM master")
        stored_password = cursor.fetchone()

        conn.close()

        if stored_password:
            # Ask the user for the master password
            input_password = getpass("[🔑] Enter your master password: ")

            # Verify if the entered password matches
            if hash_password(input_password) == stored_password[0]:
                print("[✅] Access granted!")
            else:
                print("[❌] Incorrect password! Exiting...")
                exit()

# Function to create the passwords table
def create_passwords_table():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create table for storing passwords
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

# Function to add a new password
def add_password():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    website = input("Enter website name: ")
    username = input("Enter username/email: ")
    password = getpass("Enter password: ")

    # Encrypt the password
    encrypted_password = encrypt_password(password)

    # Store in database
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)", (website, username, encrypted_password))
    
    conn.commit()
    conn.close()
    print(f"[✅] Password for {website} saved securely!")


# Function to view stored passwords
def view_passwords():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT website, username, password FROM passwords")
    passwords = cursor.fetchall()

    conn.close()

    if not passwords:
        print("[❌] No stored passwords found.")
    else:
        print("\n[🔐] Saved Passwords:")
        for website, username, encrypted_password in passwords:
            try:
                decrypted_password = decrypt_password(encrypted_password)
                print(f"🌐 {website} | 👤 {username} | 🔑 {decrypted_password}")
            except  cryptography.fernet.InvalidToken:
                print(f"[❌] Failed to decrypt password for {website}. The data may have been tampered with.")


# Menu to interact with the user
def menu():
    while True:
        print("\n[🔹] Choose an option:")
        print("1️⃣ Add a new password")
        print("2️⃣ View saved passwords")
        print("3️⃣ Auto-generate and store a password")
        print("4️⃣ Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            add_password()
        elif choice == "2":
            view_passwords()
        elif choice == "3":
            auto_generate_password()  # Call the auto-generate function
        elif choice == "4":
            print("[👋] Exiting... Stay Secure!")
            break
        else:
            print("[❌] Invalid choice! Please select again.")


# Generate and store this key safely. You only need to generate it once.
def generate_key():
    return Fernet.generate_key()

# Save the generated key to a file (we'll need this key to decrypt passwords later)
def save_key(key):
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the key from file
def load_key():
    return open("secret.key", "rb").read()

# Encrypt password
def encrypt_password(password):
    key = load_key()  # Load the key
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

# Decrypt password
def decrypt_password(encrypted_password):
    key = load_key()  # Load the key
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

def setup_encryption():
    # Only generate key if secret.key doesn't exist
    if not os.path.exists("secret.key"):
        key = generate_key()
        save_key(key)
        print("[✅] Encryption key generated and saved!")
    else:
        print("[🔑] Encryption key already exists.")


# Function to generate a random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    random_password = ''.join(random.choice(characters) for _ in range(length))
    return random_password

# Function to automatically generate and store the password
def auto_generate_password():
    website = input("Enter website name: ")
    username = input("Enter username/email: ")

    # Generate a random password
    password = generate_random_password()

    # Encrypt the password
    encrypted_password = encrypt_password(password)

    # Store in database
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)", (website, username, encrypted_password))
    conn.commit()
    conn.close()

    print(f"[✅] Password for {website} saved securely!")
    print(f"Generated password: {password}")


# Run startup sequence
display_banner()
check_first_time()
setup_encryption()
create_passwords_table()
menu()
