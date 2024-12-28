import unittest
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import PKCS1_v1_5, eddsa
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from pymt import RsaKeyPair, Utils
import os
import json
import uuid


class TestRsaKeyPair(unittest.TestCase):
    # MAKE SURE THE KEY EXISTS, OTHERWISE THE TESTS WILL FAIL WITHOUT ERROR
    dir_path = os.path.dirname(os.path.realpath(__file__))
    private_key_file = dir_path + "/test_keys/test_rsa_private_key.pem"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Load the genesis private key
        with open(cls.private_key_file, "rb") as f:
            cls.genesis_key = RSA.importKey(f.read())

        cls.public_key = cls.genesis_key.publickey().exportKey("PEM")
        cls.public_key_id = uuid.uuid4().hex

    def setUp(self):
        super().setUp()
        self.wallet = RsaKeyPair(_generate_keys=False)
        self.wallet._key_pair = self.genesis_key
        self.wallet._nickname = self.public_key_id

        # Create the tmp_keys dir
        if not os.path.exists(self.dir_path + "/tmp_keys"):
            os.mkdir(self.dir_path + "/tmp_keys")

    def tearDown(self):
        super().tearDown()

        # Check if the the tmp_key dir exists and delete it
        if os.path.exists(self.dir_path + "/tmp_keys"):
            for file in os.listdir(self.dir_path + "/tmp_keys"):
                os.remove(self.dir_path + "/tmp_keys/" + file)
            os.rmdir(self.dir_path + "/tmp_keys")

    def test_sign(self):
        message = b"Hello World"
        signature = self.wallet.sign(message)

        # Verify the signature
        data_hash = Utils.hash_data(message, finalize=False)
        signature_scheme_obj = PKCS1_v1_5.new(self.genesis_key)
        expected = signature_scheme_obj.sign(data_hash)

        self.assertEqual(signature, expected)

    def test_verify_signature(self):
        # Sign the message
        message = b"Hello World"
        data_hash = Utils.hash_data(message, finalize=False)
        signature_scheme_obj = PKCS1_v1_5.new(self.genesis_key)
        signature = signature_scheme_obj.sign(data_hash)

        self.assertTrue(
            self.wallet.signature_valid(message, signature, self.public_key)
        )

    def test_get_public_key_string(self):
        # Load the genesis_public_key.pem file
        pk = self.wallet.public_key_string
        self.assertEqual(pk, self.public_key.decode())
        self.assertIsInstance(pk, str)

    def test_get_public_key_bytes(self):
        # Load the genesis_public_key.pem file
        pk = self.wallet.public_key
        self.assertEqual(pk, self.public_key)
        self.assertIsInstance(pk, bytes)

    def test_encrypt_decrypt_to_self(self):
        # Encrypt the message
        message = b"Hello World"
        encrypted_message = self.wallet.encrypt(message, self.public_key)

        # Decrypt the message
        decrypted_message = self.wallet.decrypt(encrypted_message, self.public_key)

        self.assertEqual(message, decrypted_message)

    def test_encrypt_decrypt_to_other(self):
        # Create a keypair for the recipient
        recipient = RsaKeyPair()

        # Encrypt the message
        message = b"Hello World"
        encrypted_message = self.wallet.encrypt(
            data=message, receiver_public_key=recipient.public_key
        )

        # Decrypt the message
        decrypted_message = recipient.decrypt(
            data=encrypted_message, sender_public_key=self.wallet.public_key
        )

        self.assertEqual(message, decrypted_message)

        # Try to decrypt with the wrong key
        with self.assertRaises(ValueError):
            self.wallet.decrypt(encrypted_message, RsaKeyPair().public_key)

    def test_generate_keypair(self):
        old_key_pair = self.wallet._key_pair
        self.wallet.generate_keypair()
        new_key_pair = self.wallet._key_pair

        self.assertNotEqual(old_key_pair, new_key_pair)

    def test_to_and_from_key_file(self):
        # Save the key to a file
        key_file = self.dir_path + "/tmp_keys/test_key.json"
        test_password = "test_password"
        self.wallet.to_key_file(key_file, test_password)

        # Load the key from the file
        new_wallet = RsaKeyPair.from_key_file(key_file, test_password)

        self.assertEqual(self.wallet.public_key, new_wallet.public_key)
        self.assertEqual(self.wallet.nickname, new_wallet.nickname)
        self.assertEqual(self.wallet._key_pair, new_wallet._key_pair)

    def test_to_and_from_key_string(self):
        # Save the key to a string
        test_password = "test_password"
        key_string = self.wallet.to_key_string(test_password)

        # Load the key from the string
        new_wallet = RsaKeyPair.from_key_string(key_string, test_password)

        self.assertEqual(self.wallet.public_key, new_wallet.public_key)
        self.assertEqual(self.wallet.nickname, new_wallet.nickname)
        self.assertEqual(self.wallet._key_pair, new_wallet._key_pair)


# class TestEccKeyring(unittest.TestCase):
#     # MAKE SURE THE KEY EXISTS, OTHERWISE THE TESTS WILL FAIL WITHOUT ERROR
#     dir_path = os.path.dirname(os.path.realpath(__file__))
#     private_key_file = dir_path + "/test_keys/test_ecc_private_key.pem"

#     @classmethod
#     def setUpClass(cls):
#         # Load the genesis private key
#         with open(cls.private_key_file, "rt") as f:
#             cls.genesis_key = ECC.import_key(f.read())

#         cls.public_key = cls.genesis_key.public_key().export_key(format="PEM").encode()

#     def setUp(self):
#         self.wallet = EccKeyring(key_file=self.private_key_file)

#     def test_load_from_key(self):
#         pk = self.wallet.public_key
#         self.assertIsInstance(pk, bytes)
#         self.assertEqual(pk, self.public_key)

#     def test_sign(self):
#         message = b"Hello World"
#         signature = self.wallet.sign(message)

#         # Verify the signature
#         data_hash = Utils.hash_data(message, finalize=False, type="sha512")
#         signature_scheme_obj = eddsa.new(self.genesis_key, mode="rfc8032")
#         expected = signature_scheme_obj.sign(data_hash)

#         self.assertEqual(signature, expected)

#     def test_verify_signature(self):
#         # Sign the message
#         message = b"Hello World"
#         data_hash = Utils.hash_data(message, finalize=False, type="sha512")
#         signature_scheme_obj = eddsa.new(self.genesis_key, mode="rfc8032")
#         signature = signature_scheme_obj.sign(data_hash)

#         self.assertTrue(
#             self.wallet.signature_valid(message, signature, self.public_key)
#         )

#     def test_get_public_key_string(self):
#         pk = self.wallet.public_key_string
#         self.assertEqual(pk, self.public_key.decode())
#         self.assertIsInstance(pk, str)

#     def test_get_public_key_bytes(self):
#         pk = self.wallet.public_key
#         self.assertEqual(pk, self.public_key)
#         self.assertIsInstance(pk, bytes)
