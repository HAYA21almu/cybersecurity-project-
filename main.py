
# Import the RSA algorithm and padding methods from the Cryptography library.
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Import hash algorithms such as SHA-256.
from cryptography.hazmat.primitives import hashes

# Import InvalidSignature to handle incorrect digital signatures.
from cryptography.exceptions import InvalidSignature


# ==========================================
# 1. RSA KEY GENERATION
# ==========================================

# Generate a new RSA private key.
private_key = rsa.generate_private_key(
    public_exponent=65537,  # Set the public exponent to 65537.
    key_size=2048           # Set the RSA key size to 2048 bits.
)

# Create the public key from the private key.
public_key = private_key.public_key()

# Display a message to confirm that the keys were generated.
print("RSA Keys Generated Successfully!")


# ==========================================
# 2. USER MESSAGE INPUT
# ==========================================

# Ask the user to enter a message.
message = input("\nEnter your message: ")


# ==========================================
# 3. MESSAGE ENCRYPTION
# ==========================================

# Encrypt the original message using the public key.
encrypted_message = public_key.encrypt(
    message.encode(),  # Convert the message from text to bytes.

    # Use OAEP padding to make RSA encryption more secure.
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),  # Use SHA-256 with MGF1.
        algorithm=hashes.SHA256(),          # Use SHA-256 as the hash algorithm.
        label=None                          # No additional label is used.
    )
)

# Display the encrypted message.
print("\nEncrypted Message:")

# Convert the encrypted bytes into hexadecimal format for display.
print(encrypted_message.hex())


# ==========================================
# 4. MESSAGE DECRYPTION
# ==========================================

# Decrypt the encrypted message using the private key.
decrypted_message = private_key.decrypt(
    encrypted_message,  # The encrypted message to decrypt.

    # Use the same OAEP settings used during encryption.
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),  # Use SHA-256 with MGF1.
        algorithm=hashes.SHA256(),          # Use the same hash algorithm.
        label=None                          # Keep the label as None.
    )
)

# Display the decrypted message.
print("\nDecrypted Message:")

# Convert the decrypted bytes back into readable text.
print(decrypted_message.decode())

# Display a message confirming that encryption and decryption are completed.
print("\nEncryption and Decryption Completed!")


# ==========================================
# 5. DIGITAL SIGNATURE GENERATION
# ==========================================

# Create a digital signature using the private key.
signature = private_key.sign(
    message.encode(),  # Sign the original message in bytes.

    # Use PSS padding for digital signature generation.
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),  # Use SHA-256 with MGF1.
        salt_length=padding.PSS.MAX_LENGTH  # Use the maximum salt length.
    ),

    # Use SHA-256 to calculate the message hash.
    hashes.SHA256()
)

# Display a message confirming that the signature was created.
print("\nDigital Signature Created Successfully!")


# ==========================================
# 6. TEST 1: VERIFY THE ORIGINAL MESSAGE
# ==========================================

# Display the title of the first test.
print("\n======================================")
print("TEST 1: ORIGINAL MESSAGE (NO CHANGES)")
print("======================================")

# Display the original message before verification.
print("Message:", message)

# Use try to check whether the digital signature is valid.
try:
    # Verify the original message using the public key.
    public_key.verify(
        signature,          # The digital signature created earlier.
        message.encode(),   # The original message in bytes.

        # Use the same PSS settings used during signature generation.
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # Use SHA-256 with MGF1.
            salt_length=padding.PSS.MAX_LENGTH  # Use the maximum salt length.
        ),

        # Use SHA-256 to verify the message hash.
        hashes.SHA256()
    )

    # Display the result if verification is successful.
    print("Result: SIGNATURE IS VALID!")

    # Confirm that the original message was not changed.
    print("The original message has not been modified.")

# Run this block if the signature verification fails.
except InvalidSignature:

    # Display an error message if the signature is invalid.
    print("Result: SIGNATURE IS INVALID!")


# ==========================================
# 7. TEST 2: VERIFY THE MODIFIED MESSAGE
# ==========================================

# Display the title of the second test.
print("\n======================================")
print("TEST 2: MODIFIED MESSAGE")
print("======================================")

# Modify the original message by adding the characters "123".
modified_message = message + "123"

# Display both the original and modified messages.
print("Original Message:", message)
print("Modified Message:", modified_message)

# Try to verify the modified message using the original signature.
try:
    # Verify the modified message with the public key.
    public_key.verify(
        signature,                  # Use the original digital signature.
        modified_message.encode(),  # Use the modified message in bytes.

        # Use the same PSS settings as before.
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),  # Use SHA-256 with MGF1.
            salt_length=padding.PSS.MAX_LENGTH  # Use the maximum salt length.
        ),

        # Use SHA-256 for signature verification.
        hashes.SHA256()
    )

    # This message appears only if verification succeeds.
    print("Result: SIGNATURE IS VALID!")

# The expected result is InvalidSignature because the message was changed.
except InvalidSignature:

    # Display that the signature does not match the modified message.
    print("Result: SIGNATURE IS INVALID!")

    # Warn the user that the message has been modified.
    print("WARNING: Message has been modified!")

    # Confirm that signature verification failed.
    print("Signature verification FAILED!")


# ==========================================
# 8. FINISH THE TESTS
# ==========================================

# Display a final message after completing both tests.
print("\nAll Tests Completed!")
