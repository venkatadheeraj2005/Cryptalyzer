from ntru_new import generate_keys, encrypt, decrypt

# Get user input for mode and message
mode = input("Enter mode (moderate, high, highest): ").strip().lower()
message = input("Enter message to encrypt: ").strip()

# Validate mode input
if mode not in ["moderate", "high", "highest"]:
    print("Invalid mode. Please enter one of the following: moderate, high, highest")
    exit(1)

# Generate keys
generate_keys("key", mode=mode, skip_check=False, debug=True, check_time=True)

# Encrypt the message
enc = encrypt("key", message, check_time=True)
#print("Encrypted message:", enc)

# Decrypt the message
dec = decrypt("key", enc, check_time=True)
#print("Decrypted message:", dec)