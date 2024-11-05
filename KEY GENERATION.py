from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key()

# Print the key to use it in your code
print("Generated Key:", key.decode())
