import sys, os
from pymt.mt import MerkleTree
import unittest


class ProofOfInclusion:
    """Test proof functionality."""

    def setUp(self):
        self.mt = MerkleTree()

    def test_poi_empty_tree(self):
        self.mt.make_tree()
        with self.assertRaises(ValueError):
            _ = self.mt.get_proof_of_inclusion(b"0")

    def test_poi_root_hash(self):
        self.mt.put(b"dog")
        self.mt.make_tree()
        proof = self.mt.get_proof_of_inclusion(b"dog")
        self.assertEqual(proof.trie_root, self.mt.get_merkle_root())

    def test_poi_valid(self):
        data = [b"tierion", b"bitcoin", b"blockchain", b"trie", b"triangle"]
        for d in data:
            self.mt.put(d)
        self.mt.make_tree()

        with self.assertRaises(ValueError):
            _ = self.mt.get_proof_of_inclusion(b"0")

        proof = self.mt.get_proof_of_inclusion(b"tierion")
        self.assertTrue(self.mt.verify_proof_of_inclusion(proof))

    def test_poi_verify_one_item_removed(self):
        data = [b"tierion", b"bitcoin", b"blockchain", b"trie", b"triangle"]
        for d in data:
            self.mt.put(d)
        self.mt.make_tree()
        proof = self.mt.get_proof_of_inclusion(b"bitcoin")

        mt = MerkleTree(secure=self.mt.secure)
        for d in data[2:]:
            mt.put(d)
        mt.make_tree()

        self.assertFalse(mt.verify_proof_of_inclusion(proof))

    def test_poi_verify_one_item_added(self):
        data = [b"tierion", b"bitcoin", b"blockchain", b"trie", b"triangle"]
        for d in data:
            self.mt.put(d)
        self.mt.make_tree()
        proof = self.mt.get_proof_of_inclusion(b"bitcoin")

        mt = MerkleTree(secure=self.mt.secure)
        for d in data:
            mt.put(d)
        mt.put(b"added")
        mt.make_tree()

        self.assertFalse(mt.verify_proof_of_inclusion(proof))


class TestMerkleTree(ProofOfInclusion, unittest.TestCase):
    """Test the main merkletools functions."""

    def setUp(self):
        self.mt = MerkleTree(secure=False)

    def test_add_one_leaf(self):
        self.mt.put(b"tierion")
        self.mt.put(b"tie")
        self.mt.put(b"tieon")
        self.assertEqual(self.mt.get_leaf_count(), 3)
        self.assertFalse(self.mt.is_ready)

    # TODO: add more tests for the other functions
    # Test addind and getting one leaf, then building the tree.
    def test_adding_one_leaf(self):
        data = b"tierion"
        self.mt.put(data)
        self.assertEqual(self.mt.get_leaf_count(), 1)

    def test_build_tree_with_one_leaf(self):
        data = b"tierion"
        self.mt.put(data)
        self.mt.make_tree()
        self.assertTrue(self.mt.is_ready)

        # TODO: Generate the right merkle roots for the MT tests
        self.assertEqual(self.mt.get_merkle_root(), b"74696572696f6e")

    def test_adding_many_leaves(self):
        data = [b"tierion", b"bitcoin", b"blockchain", b"trie", b"triangle"]
        for d in data:
            self.mt.put(d)

        self.assertEqual(self.mt.get_leaf_count(), 5)

    def test_build_tree_with_many_leaves(self):
        data = [b"tierion", b"bitcoin", b"blockchain", b"trie", b"triangle"]
        for d in data:
            self.mt.put(d)

        self.mt.make_tree()
        self.assertTrue(self.mt.is_ready)
        self.assertEqual(
            self.mt.get_merkle_root(),
            b"90a110224740a76b68e8c5a7980ac65e991620e1ce7e0d02cc586993599542bd",
        )


if __name__ == "__main__":
    unittest.main()
