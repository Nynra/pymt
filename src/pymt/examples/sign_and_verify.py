import sys, os
from pymt import RsaKeyPair

# Create a new keyring
keyring = RsaKeyPair()

# Sign and verify a message
message = b"Hello World"
signature = keyring.sign(message)
print("RSA Signature: {}".format(signature))
print(
    "RSA Signature valid: {}".format(
        keyring.signature_valid(message, signature, keyring.public_key)
    )
)

# Verify with new user
new_keyring = RsaKeyPair()
print(
    "RSA Signature valid by second: {}".format(
        new_keyring.signature_valid(message, signature, keyring.public_key)
    )
)
