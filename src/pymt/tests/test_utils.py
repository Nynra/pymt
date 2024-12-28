import sys, os
from pymt.utils.node import Node, Leaf, Extension, Branch
from pymt.utils.nibble_path import NibblePath
from pymt.proof import Proof
from pymt.utils.hash import keccak_hash
from pymt.utils import Utils
import unittest
import rlp
import json
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256, SHA512
from Crypto.Cipher import AES
import os


class TestProof(unittest.TestCase):
    def setUp(self):
        self.proof = Proof(
            b"target_key",
            b"root_hash",
            (b"proof", b"proof2", b"proof3"),
            proof_type=b"MT-POI",
        )
        self.dict_content = {
            "proof_type": self.proof._type,
            "timestamp": self.proof._timestamp,
            "target_key": self.proof._target_key,
            "root_hash": self.proof._root_hash,
            "proof": self.proof._proof,
        }

    def _get_str_dict(self) -> dict:
        dict_content = self.dict_content.copy()
        for k, v in dict_content.items():
            if isinstance(v, (list, tuple)):
                dict_content[k] = [i.decode() for i in v]
            else:
                dict_content[k] = dict_content[k].decode()
        return dict_content

    def assertDict(self, dict1, dict2):
        for key in dict1:
            self.assertEqual(dict1[key], dict2[key])

    def test_dict(self):
        self.assertDict(self.dict_content, self.proof.__dict__())

    def test_hash(self):
        expected = int(keccak_hash(str(self.dict_content).encode(), hexdigest=True), 16)
        self.assertEqual(expected, self.proof.__hash__())

    def test_eq(self):
        proof1 = Proof(
            b"target_key",
            b"root_hash",
            (b"proof", b"proof2", b"proof3"),
            proof_type=b"MPT-POE",
        )
        proof2 = Proof(
            b"target_key",
            b"root_hash",
            (b"proof", b"proof2", b"proof3"),
            proof_type=b"MPT-POE",
        )
        proof3 = Proof(
            b"target_key",
            b"root_hash",
            (b"proof", b"proof2", b"proof3"),
            proof_type=b"MPT-POI",
        )
        proof2._timestamp = proof1._timestamp
        self.assertTrue(proof1 == proof2)
        self.assertFalse(proof1 == proof3)

    def test_encode_decode_json(self):
        expected = json.dumps(self._get_str_dict())
        res = self.proof.encode_json()
        self.assertEqual(expected, res)

        proof = Proof.decode_json(expected)
        self.assertEqual(self.proof, proof)

    def test_encode_decode_rlp(self):
        expected = rlp.encode(
            [
                self.proof._type,
                self.proof._timestamp,
                self.proof._target_key,
                self.proof._root_hash,
                self.proof._proof,
            ]
        )
        self.assertEqual(expected, self.proof.encode_rlp())

        proof = Proof.decode_rlp(expected)
        self.assertEqual(self.proof, proof)


class TestNibblePath(unittest.TestCase):
    def test_at(self):
        nibbles = NibblePath([0x12, 0x34])
        self.assertEqual(nibbles.at(0), 0x1)
        self.assertEqual(nibbles.at(1), 0x2)
        self.assertEqual(nibbles.at(2), 0x3)
        self.assertEqual(nibbles.at(3), 0x4)

    def test_at_with_offset(self):
        nibbles = NibblePath([0x12, 0x34], offset=1)
        self.assertEqual(nibbles.at(0), 0x2)
        self.assertEqual(nibbles.at(1), 0x3)
        self.assertEqual(nibbles.at(2), 0x4)
        with self.assertRaises(IndexError):
            nibbles.at(3)

    def test_encode(self):
        nibbles = NibblePath([0x12, 0x34])
        self.assertEqual(nibbles.encode(False), b"\x00\x12\x34")
        self.assertEqual(nibbles.encode(True), b"\x20\x12\x34")

        nibbles = NibblePath([0x12, 0x34], offset=1)
        self.assertEqual(nibbles.encode(False), b"\x12\x34")
        self.assertEqual(nibbles.encode(True), b"\x32\x34")

    def test_common_prefix(self):
        nibbles_a = NibblePath([0x12, 0x34])
        nibbles_b = NibblePath([0x12, 0x56])
        common = nibbles_a.common_prefix(nibbles_b)
        self.assertEqual(common, NibblePath([0x12]))

        nibbles_a = NibblePath([0x12, 0x34])
        nibbles_b = NibblePath([0x12, 0x36])
        common = nibbles_a.common_prefix(nibbles_b)
        self.assertEqual(common, NibblePath([0x01, 0x23], offset=1))

        nibbles_a = NibblePath([0x12, 0x34], offset=1)
        nibbles_b = NibblePath([0x12, 0x56], offset=1)
        common = nibbles_a.common_prefix(nibbles_b)
        self.assertEqual(common, NibblePath([0x12], offset=1))

        nibbles_a = NibblePath([0x52, 0x34])
        nibbles_b = NibblePath([0x02, 0x56])
        common = nibbles_a.common_prefix(nibbles_b)
        self.assertEqual(common, NibblePath([]))

    def test_combine(self):
        nibbles_a = NibblePath([0x12, 0x34])
        nibbles_b = NibblePath([0x56, 0x78])
        common = nibbles_a.combine(nibbles_b)
        self.assertEqual(common, NibblePath([0x12, 0x34, 0x56, 0x78]))

        nibbles_a = NibblePath([0x12, 0x34], offset=1)
        nibbles_b = NibblePath([0x56, 0x78], offset=3)
        common = nibbles_a.combine(nibbles_b)
        self.assertEqual(common, NibblePath([0x23, 0x48]))


class TestNode(unittest.TestCase):
    """This class tests the general CODEC functions of the different node types."""

    def assertRoundtrip(self, raw_node: Node, expected_type: type) -> ...:
        """Test the general Node.decode function."""
        decoded = Node.decode(raw_node)
        encoded = decoded.encode()

        self.assertEqual(type(decoded), expected_type)
        self.assertEqual(raw_node, encoded)

    def assertNodeContent(self, node: Node, raw_node: bytes) -> ...:
        """Test the data and path persistence of a node after encoding and decoding."""
        decoded_node = Node.decode(raw_node)
        self.assertEqual(decoded_node.data, node.data)

    def test_leaf(self) -> ...:
        """Test the Leaf node type."""
        # Path 0xABC. 0x3_ at the beginning: 0x20 (for leaf type) + 0x10 (for odd len)
        nibbles_path = NibblePath(bytearray([0x3A, 0xBC]))
        data = bytearray([0xDE, 0xAD, 0xBE, 0xEF])
        leaf = Leaf(nibbles_path, data)
        raw_node = leaf.encode()
        self.assertRoundtrip(raw_node, Leaf)
        self.assertNodeContent(leaf, raw_node)

        # Path 0xABC. 0x2_ at the beginning: 0x20 (for leaf type) + 0x00 (for even len)
        nibbles_path = NibblePath(bytearray([0x2A, 0xBC]))
        data = bytearray([0xDE, 0xAD, 0xBE, 0xEF])
        leaf = Leaf(nibbles_path, data)
        raw_node = leaf.encode()
        self.assertRoundtrip(raw_node, Leaf)
        self.assertNodeContent(leaf, raw_node)

    def test_extension(self) -> ...:
        """Test the Extension node type."""
        # Path 0xABC. 0x1_ at the beginning: 0x10 (for extension type) + 0x10 (for odd len)
        nibbles_path = NibblePath(bytearray([0x1A, 0xBC]))
        child = Node.into_reference(
            Leaf(NibblePath([0x12, 0x34]), bytearray([0xDE, 0xAD, 0xBE, 0xEF]))
        )
        extension = Extension(nibbles_path, child)
        raw_node = extension.encode()
        self.assertRoundtrip(raw_node, Extension)

        # Path 0xABC. 0x0_ at the beginning: 0x10 (for extension type) + 0x00 (for even len)
        nibbles_path = NibblePath(bytearray([0x0A, 0xBC]))
        child = Node.into_reference(
            Leaf(NibblePath([0x12, 0x34]), bytearray([0xDE, 0xAD, 0xBE, 0xEF]))
        )
        extension = Extension(nibbles_path, child)
        raw_node = extension.encode()
        self.assertRoundtrip(raw_node, Extension)

    def test_branch(self) -> ...:
        """Test the Branch node type."""
        # Path 0xABC. 0x1_ at the beginning: 0x00 (for branch type) + 0x10 (for odd len)
        # without data
        nibbles_path = NibblePath(bytearray([0x1A, 0xBC]))
        branches = [b""] * 16
        branch = Branch(branches=branches)
        raw_node = branch.encode()
        self.assertRoundtrip(raw_node, Branch)
        self.assertNodeContent(branch, raw_node)

        # Path 0xABC. 0x0_ at the beginning: 0x00 (for branch type) + 0x00 (for even len)
        # without data
        nibbles_path = NibblePath(bytearray([0x0A, 0xBC]))
        branches = [b""] * 16
        branch = Branch(branches=branches)
        raw_node = branch.encode()
        self.assertRoundtrip(raw_node, Branch)
        self.assertNodeContent(branch, raw_node)

        # Path 0xABC. 0x1_ at the beginning: 0x00 (for branch type) + 0x10 (for odd len)
        # with data
        nibbles_path = NibblePath(bytearray([0x1A, 0xBC]))
        branches = [b""] * 16
        branch = Branch(branches=branches, data=b"some data")
        raw_node = branch.encode()
        self.assertRoundtrip(raw_node, Branch)
        self.assertNodeContent(branch, raw_node)

        # Path 0xABC. 0x0_ at the beginning: 0x00 (for branch type) + 0x00 (for even len)
        # with data
        nibbles_path = NibblePath(bytearray([0x0A, 0xBC]))
        branches = [b""] * 16
        branch = Branch(branches=branches, data=b"some data")
        raw_node = branch.encode()
        self.assertRoundtrip(raw_node, Branch)
        self.assertNodeContent(branch, raw_node)


class TestUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> ...:
        # Generate an RSA keypair
        cls.rsa_keypair = RSA.generate(2048)

    def test_get_timestamp_string(self) -> ...:
        # Get the timestamp as a string
        timestamp = Utils.get_timestamp_string()
        self.assertIsInstance(timestamp, str)

    def test_get_timestamp(self) -> ...:
        # Get the timestamp
        timestamp = Utils.get_timestamp()
        self.assertIsInstance(timestamp, bytes)

    def test_get_id_string(self) -> ...:
        # Get the id as a string
        id = Utils.get_id_string()
        self.assertIsInstance(id, str)
        self.assertEqual(len(id), 32)

    def test_get_id(self) -> ...:
        # Get the id
        id = Utils.get_id()
        self.assertIsInstance(id, bytes)
        self.assertEqual(len(id), 32)

    def test_generate_rsa_keypair(self) -> ...:
        # Generate a RSA keypair
        keypair = Utils.generate_rsa_keypair()
        self.assertIsInstance(keypair, bytes)

        # Try loading the keypair
        new_keypair = RSA.import_key(keypair)

        # Check if the keys match
        self.assertEqual(keypair, new_keypair.export_key(format="PEM"))

    def test_generate_ecc_key(self) -> ...:
        # Generate a ECC key
        key = Utils.generate_ecc_key()
        self.assertIsInstance(key, bytes)

        # Try loading the key
        new_key = ECC.import_key(key)

        # Check if the keys match
        self.assertEqual(key, new_key.export_key(format="PEM").encode())

    def test_sha256(self) -> ...:
        # Hash some data with finalize
        data = b"Hello World"
        expected = SHA256.new(data=data)
        expected = expected.hexdigest().encode()

        result = Utils.hash_data(data, finalize=True, type="sha256")
        self.assertEqual(result, expected)

        # Hash some data without finalize
        expected = SHA256.new(data=data)

        result = Utils.hash_data(data, finalize=False, type="sha256")
        self.assertIsInstance(result, SHA256.SHA256Hash)
        self.assertEqual(result.digest(), expected.digest())

    def test_sha512(self) -> ...:
        # Hash some data with finalize
        data = b"Hello World"
        expected = SHA512.new(data=data)
        expected = expected.hexdigest().encode()

        result = Utils.hash_data(data, finalize=True, type="sha512")
        self.assertEqual(result, expected)

        # Hash some data without finalize
        expected = SHA512.new(data=data)

        result = Utils.hash_data(data, finalize=False, type="sha512")
        self.assertIsInstance(result, SHA512.SHA512Hash)
        self.assertEqual(result.digest(), expected.digest())

    def test_file_exists(self) -> ...:
        # Test if the file exists
        self.assertTrue(Utils.file_exists(__file__))

        # Test if the file does not exist
        self.assertFalse(Utils.file_exists("test.txt"))

        # Create a file in the current directory
        with open("test.txt", "w") as f:
            f.write("Hello World")

        # Test if the file exists
        self.assertTrue(Utils.file_exists("test.txt"))
        os.remove("test.txt")

    def test_dir_exists(self) -> ...:
        # Test if the directory exists
        dir_path = os.path.dirname(__file__)
        self.assertTrue(Utils.dir_exists(dir_path))

        # Test if the directory does not exist
        self.assertFalse(Utils.dir_exists("test"))

    def test_encrypt_and_decrypt(self) -> ...:
        # Decrypt some data
        data = b"Hello World"
        password = "password"

        pass_hash = Utils.hash_data(password.encode(), finalize=False).digest()
        cypher = AES.new(pass_hash, AES.MODE_EAX)
        ctekst, tag = cypher.encrypt_and_digest(data)
        expected = b"".join([cypher.nonce, tag, ctekst])

        result = Utils.decrypt(expected, password)
        self.assertEqual(result, data)

        encrypted = Utils.encrypt(data, password)
        result = Utils.decrypt(encrypted, password)
        self.assertEqual(result, data)

    def test_rsa_public_key_valid(self):
        # Test if the public key is valid
        public_key = self.rsa_keypair.publickey().export_key(format="PEM")
        self.assertTrue(Utils.rsa_key_valid(public_key, key_type="public"))

        # Test if the public key is not valid
        self.assertFalse(Utils.rsa_key_valid(b"Hello World", key_type="public"))

    def test_rsa_private_key_valid(self):
        # Test if the private key is valid
        private_key = self.rsa_keypair.export_key(format="PEM")
        self.assertTrue(Utils.rsa_key_valid(private_key, key_type="private"))

        # Test if the private key is not valid
        self.assertFalse(Utils.rsa_key_valid(b"Hello World", key_type="private"))
