# password_manager
Overview
--------

PassGen is a simple, secure, and user-friendly command-line interface (CLI) password manager that allows you to store, view, edit, and delete passwords for various websites. The application uses encryption to securely store passwords in a database and provides options for generating strong passwords.
Features
--------
    Secure Password Storage: Your passwords are securely stored in an encrypted database, making them inaccessible to unauthorized users.
    Password Generation: Auto-generate strong, random passwords for secure usage.
    View Saved Passwords: List all saved passwords with the option to view them after decryption.
    Edit Passwords: Modify passwords associated with a website or service.
    Delete Passwords: Remove saved passwords when no longer needed.
    Encryption: Passwords are encrypted using the Fernet encryption standard to ensure high-level security.
    Master Password Protection: Access is secured by a master password, which must be entered each time the program is started.
Installation
-------------

To install and run PassGen, ensure you have Python 3.x installed and follow these steps:
    Clone or download the repository to your local machine.
    Install required dependencies:

    $pip install cryptography

Run the program using Python:

    $python3 passgen.py    

Security
---------

  Password Hashing
  Password Encryption
