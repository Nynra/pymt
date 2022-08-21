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

    def test_add_leaf(self):
        mt = MerkleTree()
        mt.put(b"tierion")
        mt.put(b"tie")
        mt.put(b"tieon")
        self.assertEqual(mt.get_leaf_count(), 3)
        self.assertFalse(mt.is_ready)

    def test_build_tree(self):
        mt = MerkleTree()
        mt.put(b"tierion")
        mt.put(b"bitcoin") 
        mt.put(b"blockchain")
        mt.make_tree()
        self.assertTrue(mt.is_ready)
        self.assertEqual(mt.get_merkle_root(), '765f15d171871b00034ee55e48ffdf76afbc44ed0bcff5c82f31351d333c2ed1')

    def test_get_proof(self):
        mt = MerkleTree()
        mt.put(b"tierion")
        mt.put(b"bitcoin") 
        mt.put(b"blockchain")
        mt.make_tree()
        proof_1 = mt.get_proof_of_inclusion(b"bitcoin", 1, do_hash=True)
        for p in proof_1.proof:
            try:
                self.assertEqual(p['left'], '2da7240f6c88536be72abe9f04e454c6478ee29709fc3729ddfb942f804fbf08')
            except:
                self.assertEqual(p['right'], 'ef7797e13d3a75526946a3bcf00daec9fc9c9c4d51ddc7cc5df888f74dd434d1')

    # Standard tests
    def test_basics(self):
        bLeft = 'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb'
        bRight = 'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c'
        mRoot = hashlib.sha256(bytearray.fromhex(bLeft) + bytearray.fromhex(bRight)).hexdigest()

        # tree with no leaves
        mt = MerkleTree()
        mt.make_tree()
        self.assertEqual(mt.get_merkle_root(), None)

        # tree with hex add_leaf
        mt.put(bLeft.encode()) 
        mt.put(bRight.encode())
        mt.make_tree()
        self.assertEqual(mt.get_merkle_root(), mRoot)

    def test_bad_hex(self):
        # try to add bad hex
        mt = MerkleTree()
        with self.assertRaises(ValueError):
            mt.put(b'nothexandnothashed')

    def test_one_leaf(self):
        # make tree with one leaf
        mt = MerkleTree()
        mt.put(b'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb')
        mt.make_tree()
        self.assertEqual(mt.get_merkle_root(), 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb')

    def test_5_leaves(self):
        mt = MerkleTree()
        mt.put(b'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb')
        mt.put(b'3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d')
        mt.put(b'2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6')
        mt.put(b'18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4')
        mt.put(b'3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea')
        mt.make_tree()
        self.assertEqual(mt.get_merkle_root(), 'd71f8983ad4ee170f8129f1ebcdd7440be7798d8e1c80420bf11f1eced610dba')


class Test_proof(unittest.TestCase):
    """Test proof functionality."""

    def test_proof_nodes(self):
        bLeft = b'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb'
        bRight = b'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c'
        
        mt = MerkleTree()
        mt.put(bLeft)
        mt.put(bRight)
        mt.make_tree()
        proof = mt.get_proof_of_inclusion(bLeft, 0, do_hash=True)
        self.assertEqual(proof.proof[0]['right'], 'cb4990b9a8936bbc137ddeb6dcab4620897b099a450ecdc5f3e86ef4b3a7135c')
        proof = mt.get_proof_of_inclusion(bRight, 1, do_hash=True)
        self.assertEqual(proof.proof[0]['left'], 'a292780cc748697cb499fdcc8cb89d835609f11e502281dfe3f6690b1cc23dcb')

    def test_proof_empty_tree(self):
        mt = MerkleTree()
        mt.make_tree()
        with self.assertRaises(ValueError):
            _ = mt.get_proof_of_inclusion(b'', 0)

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
        proof = mt.get_proof_of_inclusion(data[2], 2, do_hash=True)

        # Check it the merkle root hash is correct
        self.assertEqual(proof.trie_root, mt.get_merkle_root())

        # Check if the proof type is correct
        self.assertEqual(proof.type, 'MT POI')

        # Check if the target is correct
        self.assertEqual(proof.target, mt.hash_function(data[2]))



if __name__ == '__main__':
    unittest.main()