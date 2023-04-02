import sys, os

# Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)
from trie.node import Node, Leaf, Extension, Branch
from trie.nibble_path import NibblePath
from trie.proof import Proof
from trie.hash import keccak_hash
import unittest
import rlp
import json


class TestProof(unittest.TestCase):

    def setUp(self):
        self.proof = Proof(b"target_key", b"root_hash", [b"proof", b"proof2", b"proof3"],
                           type=b'MPT-POE')
        self.dict_content = {
            "type": self.proof._type,
            "timestamp": self.proof._timestamp,
            "target_key": self.proof._target_key,
            "root_hash": self.proof._root_hash,
            "proof": str(self.proof._proof),
        }

    def assertDict(self, dict1, dict2):
        for key in dict1:
            self.assertEqual(dict1[key], dict2[key])

    def test_dict(self):
        self.assertDict(self.dict_content, self.proof.__dict__())

    def test_hash(self):

        expected = int(keccak_hash(str(self.dict_content).encode(), hexdigest=True), 16)
        self.assertEqual(expected, self.proof.__hash__())

    def test_eq(self):
        proof1 = Proof(b"target_key", b"root_hash", [b"proof", b"proof2", b"proof3"],
                       type=b'MPT-POE')
        proof2 = Proof(b"target_key", b"root_hash", [b"proof", b"proof2", b"proof3"],
                       type=b'MPT-POE')
        proof3 = Proof(b"target_key", b"root_hash", [b"proof", b"proof2", b"proof3"],
                       type=b'MPT-POI')
        proof2._timestamp = proof1._timestamp
        self.assertTrue(proof1 == proof2)
        self.assertFalse(proof1 == proof3)

    def test_encode_decode_json(self):
        expected = json.dumps(self.dict_content)
        self.assertEqual(expected, self.proof.encode_json())

        proof = Proof.decode_json(expected)
        self.assertEqual(self.proof, proof)
        
    def test_encode_decode_rlp(self):
        expected = rlp.encode([
            self.proof._type,
            self.proof._timestamp,
            self.proof._target_key,
            self.proof._root_hash,
            self.proof._proof,
        ])
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
        self.assertEqual(nibbles.encode(False), b'\x00\x12\x34')
        self.assertEqual(nibbles.encode(True), b'\x20\x12\x34')

        nibbles = NibblePath([0x12, 0x34], offset=1)
        self.assertEqual(nibbles.encode(False), b'\x12\x34')
        self.assertEqual(nibbles.encode(True), b'\x32\x34')

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

    def assertRoundtrip(self, raw_node : Node, expected_type : type) -> ...:
        """Test the general Node.decode function."""
        decoded = Node.decode(raw_node)
        encoded = decoded.encode()

        self.assertEqual(type(decoded), expected_type)
        self.assertEqual(raw_node, encoded)

    def assertNodeContent(self, node : Node, raw_node : bytes) -> ...:
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
        child = Node.into_reference(Leaf(NibblePath([0x12, 0x34]), bytearray([0xDE, 0xAD, 0xBE, 0xEF])))
        extension = Extension(nibbles_path, child)
        raw_node = extension.encode()
        self.assertRoundtrip(raw_node, Extension)

        # Path 0xABC. 0x0_ at the beginning: 0x10 (for extension type) + 0x00 (for even len)
        nibbles_path = NibblePath(bytearray([0x0A, 0xBC]))
        child = Node.into_reference(Leaf(NibblePath([0x12, 0x34]), bytearray([0xDE, 0xAD, 0xBE, 0xEF])))
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

