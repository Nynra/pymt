import sys, os
from pypsst import RsaKeyPair

# Create a new keyring
sender_keyring = RsaKeyPair()
receiver_keyring = RsaKeyPair()

print("Sender Public Key: {}\n".format(sender_keyring.public_key))
print("Receiver Public Key: {}\n".format(receiver_keyring.public_key))

# Encrypt the message for the receiver
message = b"Hello World"
encrypted_message = sender_keyring.encrypt(message, receiver_keyring.public_key)
print("Message: {}".format(message))
print("Encrypted Message: {}\n".format(encrypted_message))

# Decrypt the message
decrypted_message = receiver_keyring.decrypt(encrypted_message)
print("Decrypted Message: {}".format(decrypted_message))
