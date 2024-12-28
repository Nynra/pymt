from pymt import RsaKeyPair

# Step 1: Generate an RSA key pair.
rsa_key_pair = RsaKeyPair(nickname="TestKeyPair")
rsa_key_pair.generate_keypair()

# Step 2: Sign a piece of data.
data = b"Test data for signing"
signature = rsa_key_pair.sign(data)

# Step 3: Verify the signature.
is_valid_signature = rsa_key_pair.signature_valid(data, signature)

# Step 4: Encrypt the data using the public key.
receiver_public_key = rsa_key_pair.public_key
encrypted_data = rsa_key_pair.encrypt(data, receiver_public_key)

# Step 5: Decrypt the data using the private key.
decrypted_data = rsa_key_pair.decrypt(encrypted_data, rsa_key_pair.public_key)

# Verify the steps
is_valid_signature, decrypted_data.decode() == data.decode()
