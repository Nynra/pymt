import sys, os
#Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)
from src.merkletools.mt import MerkleTree
import hashlib
import unittest


class TestMerkleTools(unittest.TestCase):
    """Test the main merkletools functions."""

    def test_add_one_leaf(self):
        mt = MerkleTree()
        mt.put(b"tierion")
        mt.put(b"tie")
        mt.put(b"tieon")
        self.assertEqual(mt.get_leaf_count(), 3)
        self.assertFalse(mt.is_ready)

    # TODO: #5 add more tests for the other functions
    # Test addind and getting one leaf, then building the tree.
    def test_adding_and_getting_one_leaf(self):
        mt = MerkleTree()

        data = [b"tierion"]
        for d in data:
            mt.put(d)

        for i, d in enumerate(data):
            self.assertEqual(mt.get(i), mt.hash_function(d).hexdigest())

    def test_build_tree_with_one_leaf(self):
        mt = MerkleTree()

        data = [b"tierion"]
        for d in data:
            mt.put(d)
       
        mt.make_tree()
        self.assertTrue(mt.is_ready)

        # TODO: #6 Generate the right merkle roots for the MT tests
        self.assertEqual(mt.get_merkle_root(), 'd5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882')

    # Test addding and getting many leaves, then building the tree.
    def test_adding_and_getting_many_leaves(self):
        mt = MerkleTree()

        data = [b"tierion", b"bitcoin", b"blockchain", b"trie", b"triangle"]
        for d in data:
            mt.put(d)

        for i, d in enumerate(data):
            self.assertEqual(mt.get(i), mt.hash_function(d).hexdigest())

    def test_build_tree_with_many_leaves(self):
        mt = MerkleTree()

        data = [b"tierion", b"bitcoin", b"blockchain", b"trie", b"triangle"]
        for d in data:
            mt.put(d)
       
        mt.make_tree()
        self.assertTrue(mt.is_ready)
        self.assertEqual(mt.get_merkle_root(), '765f15d171871b00034ee55e48ffdf76afbc44ed0bcff5c82f31351d333c2ed1')

    # Test adding and getting lots of leaves, then building the tree.

    

class Test_proof(unittest.TestCase):
    """Test proof functionality."""

    def test_proof_nodes(self):
        bLeft = b'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb'
        bRight = b'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c'
        
        mt = MerkleTree()
        mt.put(bLeft)
        mt.put(bRight)
        mt.make_tree()
        proof = mt.get_proof_of_inclusion(0)
        self.assertEqual(proof.proof[0][b'right'], 'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c')
        proof = mt.get_proof_of_inclusion(1)
        self.assertEqual(proof.proof[0][b'left'], 'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb')

    def test_proof_empty_tree(self):
        mt = MerkleTree()
        mt.make_tree()
        with self.assertRaises(IndexError):
            _ = mt.get_proof_of_inclusion(0)

    def test_proof_info(self):
        mt = MerkleTree()
        data = [b'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
                b'3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
                b'2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
                b'18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
                b'3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea']
        
        for d in data:
            mt.put(d)
        mt.make_tree()
        proof = mt.get_proof_of_inclusion(2)

        # Check it the merkle root hash is correct
        self.assertEqual(proof.trie_root, mt.get_merkle_root())

        # Check if the proof type is correct
        self.assertEqual(proof.type, 'MT POI')

        # Check if the target is correct
        self.assertEqual(proof.target, mt.hash_function(data[2]).hexdigest())



if __name__ == '__main__':
    unittest.main()