from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
import os

# Function to decrypt the encrypted file using a wordlist
def decrypt_with_wordlist(encrypted_file_path, wordlist_path):
    # Read the encrypted data
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()

    # Open the wordlist file and iterate through each password
    with open(wordlist_path, 'r') as wordlist:
        for line in wordlist:
            password = line.strip()  # Remove newline or extra spaces
            try:
                # Ensure the password length is valid
                if len(password) not in [16, 24, 32]:
                    continue

                # Convert password to bytes
                password_bytes = password.encode()

                # Initialize the AES cipher in ECB mode
                cipher = AES.new(password_bytes, AES.MODE_ECB)

                # Attempt to decrypt and unpad
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

                # If decryption succeeds, print and return the result
                print(f"Password found: {password}")
                print(f"Decrypted message: {decrypted_data.decode('utf-8')}")
                return password, decrypted_data

            except (ValueError, UnicodeDecodeError):
                # Ignore decryption errors and try the next password
                continue

    print("No valid password found in the wordlist.")
    return None, None

# Example usage
# Provide paths to the encrypted file and the wordlist
encrypted_file = 'encrypted_message.aes'  # Replace with actual path
wordlist_file = 'wordlist.txt'  # Replace with actual path to the wordlist

# Run the decryption
decrypt_with_wordlist(encrypted_file, wordlist_file)