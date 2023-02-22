import sys, os

# Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)
from trie.mpt import MPT
from trie.proof import Proof
from trie.hash import keccak_hash
from trie.node import Node
from trie.exceptions import (
    KeyNotFoundError,
    PoeError,
    PoiError,
)
import rlp
import unittest
import random


class ProofOfInclusion:
    """Test the proof functions of the MMPT."""

    def test_poi_proof_on_empty_trie(self):
        """Test getting the proof of an empty self.trie."""
        with self.assertRaises(ValueError):
            self.trie.get_proof_of_inclusion(rlp.encode(b''))

    def test_poi_root_hash(self):
        """Test if the root hash of the self.trie is correct."""
        self.trie.update(b'dog', b'dog')
        proof = self.trie.get_proof_of_inclusion(b'dog')
        self.assertEqual(proof.trie_root, self.trie.root(), 
                        'The root hash in the proof does not mathc the self.trie root.')
    
    def test_poi_valid(self):
        """Test if the validation function wokrs."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Get the proofs and validate
        for i in range(len(data)):
            proof = self.trie.get_proof_of_inclusion(data[i])
            self.assertTrue(self.trie.verify_proof_of_inclusion(proof), 
                    'Proof for {} is not valid.'.format(data[i]))

    def test_poi_verify_one_item_removed(self):
        """Test if the proof is still valid after removing one point."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Get the proofs and validate
        proof = self.trie.get_proof_of_inclusion(b'doge')
        self.trie.delete(b'do')
        self.assertFalse(self.trie.verify_proof_of_inclusion(proof))

    def test_poi_verify_one_point_added(self):
        """Test if the proof is still valid after adding one point."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Get the proofs and validate
        proof = self.trie.get_proof_of_inclusion(data[2])
        self.trie.update(b'testing', b'testing')
        self.assertFalse(self.trie.verify_proof_of_inclusion(proof) )

    def test_poi_verify_one_char_removed(self):
        """Test if the proof is still valid after removing one char from the proof."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Get the proofs and validate
        og_proof = self.trie.get_proof_of_inclusion(data[2])
        proof = og_proof.proof
        proof[1] = proof[1][:-1]
        proof = Proof(target_key=og_proof.target_key, proof=proof,
                    root_hash=og_proof.trie_root, type=og_proof.type)
        self.assertFalse(self.trie.verify_proof_of_inclusion(proof), 
                        'Proof should not be valid.')

    def test_poi_verify_one_char_added(self):
        """Test if the proof is still valid after adding one char to the proof."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Get the proofs and validate
        og_proof = self.trie.get_proof_of_inclusion(data[2])
        proof = []
        for i in range(len(og_proof.proof)):
            proof.append(og_proof.proof[i] + b'o')
        proof = Proof(target_key=og_proof.target_key, proof=proof,
                    root_hash=og_proof.trie_root, type=og_proof.type)

        self.assertFalse(self.trie.verify_proof_of_inclusion(proof))


class ProofOfExclusion:
    """Test the proof functions of the MMPT."""

    def test_poe_proof_on_empty_trie(self):
        """Test getting the proof of an empty self.trie."""
        with self.assertRaises(ValueError):
            self.trie.get_proof_of_exclusion(b'wolf')

    def test_poe_root_hash(self):
        """Test if the root hash of the self.trie is correct."""
        self.trie.update(b'dog', b'dog')
        proof = self.trie.get_proof_of_exclusion(b'wolf')
        self.assertEqual(proof.trie_root, self.trie.root_hash(), 
                        'The root hash in the proof does not mathc the self.trie root.')

    def test_poe_proof_on_existing_key(self):
        """Test getting the proof of an existing key."""
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        with self.assertRaises(PoeError):
            _ = self.trie.get_proof_of_exclusion(b'doge')

    def test_poe_valid(self):
        """Test if the validation function wokrs."""
        # Add some data
        data = [
            [rlp.encode(b"do"), b"verb"],
            [rlp.encode(b"dog"), b"puppy"],
            [rlp.encode(b"doge"), b"coin"],
            [rlp.encode(b"horse"), b"stallion"],
        ]
        for k, v in data:
            self.trie.update(k, v)

        keys = [[rlp.encode(str(i).encode()), str(i + 1).encode()] for i in range(101, 201)]
        proofs = [self.trie.get_proof_of_exclusion(k) for k, v in keys]

        for proof in proofs:
            self.assertTrue(self.trie.verify_proof_of_exclusion(proof))

    def test_poe_verify_one_item_removed(self):
        """Test if the proof is still valid after removing one point."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Generate the proof for eacht item
        keys = [b'wolf', b'giraffe', b'tiger', b'lion']
        proofs = [self.trie.get_proof_of_exclusion(keccak_hash(rlp.encode(k))) for k in keys]
        self.trie.delete(b'do')
        for proof in proofs:
            self.assertFalse(self.trie.verify_proof_of_exclusion(proof)) 

    def test_poe_verify_one_point_added(self):
        """Test if the proof is still valid after adding one point."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Generate the proof for eacht item
        keys = [b'wolf', b'giraffe', b'tiger', b'lion']
        proofs =  [self.trie.get_proof_of_exclusion(k) for k in keys]
        self.trie.update(b'bear', b'bear')
        for proof in proofs:
            self.assertFalse(self.trie.verify_proof_of_exclusion(proof)) 

    def test_poe_verify_one_char_removed(self):
        """Test if the proof is still valid after removing one char from the proof."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Get the proofs and validate
        og_proof = self.trie.get_proof_of_exclusion(keccak_hash(rlp.encode(b'wolf')))
        proof = []
        for i in range(len(og_proof.proof)):
            proof.append(og_proof.proof[i][:-1])

        proof = Proof(target_key=og_proof.target_key, proof=proof,
                    root_hash=og_proof.trie_root, type=og_proof.type)
        self.assertFalse(self.trie.verify_proof_of_exclusion(proof))

    def test_poe_verify_one_char_added(self):
        """Test if the proof is still valid after adding one char to the proof."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Get the proofs and validate
        og_proof = self.trie.get_proof_of_exclusion(keccak_hash(rlp.encode(b'wolf')))
        proof = []
        for i in range(len(og_proof.proof)):
            proof.append(og_proof.proof[i] + b'o')
        proof = Proof(target_key=og_proof.target_key, proof=proof,
                    root_hash=og_proof.trie_root, type=og_proof.type)
        self.assertFalse(self.trie.verify_proof_of_exclusion(proof))


class TestMptNonSecure(unittest.TestCase, ProofOfInclusion, ProofOfExclusion):
    ROOT_HASH = "5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84"
    ROOT_HASH_AFTER_UPDATES = "5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84"
    ROOT_HASH_AFTER_DELETES = "5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84"

    def setUp(self):
        self.storage = {}
        self.trie = MPT(storage=self.storage, secure=False)

    def test_insert_get_one_short(self):
        """Test inserting one short key-value pair and then getting it."""
        key = rlp.encode(b"key")
        value = rlp.encode(b"value")
        self.trie.update(key, value)
        gotten_value = self.trie.get(key)

        self.assertEqual(value, gotten_value)

        with self.assertRaises(KeyNotFoundError):
            self.trie.get(rlp.encode(b"no_key"))

    def test_insert_get_one_long(self):
        """Test inserting one long key-value pair and then getting it."""
        key = rlp.encode(
            b"key_0000000000000000000000000000000000000000000000000000000000000000"
        )
        value = rlp.encode(
            b"value_0000000000000000000000000000000000000000000000000000000000000000"
        )
        self.trie.update(key, value)
        gotten_value = self.trie.get(key)

        self.assertEqual(value, gotten_value)

    def test_insert_get_many(self):
        """Test inserting many key-value pairs and then getting them."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"dog", b"puppy")
        self.trie.update(b"doge", b"coin")
        self.trie.update(b"horse", b"stallion")

        self.assertEqual(self.trie.get(b"do"), b"verb")
        self.assertEqual(self.trie.get(b"dog"), b"puppy")
        self.assertEqual(self.trie.get(b"doge"), b"coin")
        self.assertEqual(self.trie.get(b"horse"), b"stallion")

    def test_insert_get_lots(self):
        """Test inserting lots of key-value pairs and then getting them."""
        random.seed(42)
        rand_numbers = [random.randint(1, 1000000) for _ in range(100)]
        keys = list(map(lambda x: bytes("{}".format(x), "utf-8"), rand_numbers))

        for kv in keys:
            self.trie.update(kv, kv * 2)

        for kv in keys:
            self.assertEqual(self.trie.get(kv), kv * 2)

    def test_delete_one(self):
        """Test deleting one key-value pair and then getting it."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"key", b"value")
        self.trie.delete(b"key")

        with self.assertRaises(KeyNotFoundError):
            self.trie.get(b"key")

    def test_delete_many(self):
        """Test deleting many key-value pairs and then getting them."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"dog", b"puppy")
        self.trie.update(b"doge", b"coin")
        self.trie.update(b"horse", b"stallion")

        root_hash = self.trie.root_hash()

        self.trie.update(b"a", b"aaa")
        self.trie.update(b"some_key", b"some_value")
        self.trie.update(b"dodog", b"do_dog")

        self.trie.delete(b"a")
        self.trie.delete(b"some_key")
        self.trie.delete(b"dodog")

        new_root_hash = self.trie.root_hash()

        self.assertEqual(root_hash, new_root_hash)

    def test_delete_lots(self):
        """Test deleting lots of key-value pairs and then getting them."""
        random.seed(42)
        rand_numbers = set(
            [random.randint(1, 1000000) for _ in range(100)]
        )  # Unique only.
        keys = list(map(lambda x: bytes("{}".format(x), "utf-8"), rand_numbers))

        for kv in keys:
            self.trie.update(kv, kv * 2)

        for kv in keys:
            self.trie.delete(kv)

        self.assertEqual(self.trie.root_hash(), Node.EMPTY_HASH)

    def test_root_hash(self):
        """Test getting the root hash of a trie."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"dog", b"puppy")
        self.trie.update(b"doge", b"coin")
        self.trie.update(b"horse", b"stallion")

        root_hash = self.trie.root_hash()
        self.assertEqual(root_hash, bytes.fromhex(self.ROOT_HASH))

    def test_root_hash_after_updates(self):
        """Test getting the root hash of a trie after updates."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"dog", b"puppy1")
        self.trie.update(b"doge", b"coin1")
        self.trie.update(b"horse", b"stallion1")

        self.trie.update(b"dog", b"puppy")
        self.trie.update(b"doge", b"coin")
        self.trie.update(b"horse", b"stallion")

        root_hash = self.trie.root_hash()
        # raise Exception(root_hash.hex())
        self.assertEqual(root_hash, bytes.fromhex(self.ROOT_HASH_AFTER_UPDATES))

    def test_root_hash_after_deletes(self):
        """Test getting the root hash of a trie after deletes."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"dog", b"puppy")
        self.trie.update(b"doge", b"coin")
        self.trie.update(b"horse", b"stallion")

        self.trie.update(b"dodo", b"pizza")
        self.trie.update(b"hover", b"board")
        self.trie.update(b"capital", b"Moscow")
        self.trie.update(b"a", b"b")

        self.trie.delete(b"dodo")
        self.trie.delete(b"hover")
        self.trie.delete(b"capital")
        self.trie.delete(b"a")

        root_hash = self.trie.root_hash()
        self.assertEqual(root_hash, bytes.fromhex(self.ROOT_HASH_AFTER_DELETES))

    def test_trie_from_old_root(self):
        """Test getting the root hash of a trie after deletes."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"dog", b"puppy")

        root = self.trie.root()

        self.trie.delete(b"dog")
        self.trie.update(b"do", b"not_a_verb")

        trie_from_old = MPT(self.storage, root, secure=self.trie._secure)

        # Old.
        self.assertEqual(trie_from_old.get(b"do"), b"verb")
        self.assertEqual(trie_from_old.get(b"dog"), b"puppy")

        # New.
        self.assertEqual(self.trie.get(b"do"), b"not_a_verb")
        with self.assertRaises(KeyNotFoundError):
            self.trie.get(b"dog")

    def test_contains(self):
        """Test checking if a key is in the trie."""
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )
        for k, v in data:
            self.trie.update(k, v)

        # Test exising keys
        for k, v in data:
            self.assertTrue(self.trie.contains(k))
            self.assertTrue(self.trie.__contains__(k))
            self.assertTrue(k in self.trie)

        # Test non-existing keys
        non_keys = [b"doe", b"doggy", b"doggye", b"horsee"]
        for k in non_keys:
            self.assertFalse(self.trie.contains(k))
            self.assertFalse(self.trie.__contains__(k))
            self.assertFalse(k in self.trie)

        # Test some numbers
        keys = [str(i).encode() for i in range(101, 201)]
        for k in keys:
            self.assertFalse(self.trie.contains(k))
            self.assertFalse(self.trie.__contains__(k))
            self.assertFalse(k in self.trie)

    def test_contains_empty(self):
        """Test checking if a key is in the trie."""
        self.assertFalse(self.trie.contains(b"do"))
        self.assertFalse(self.trie.contains(b"dog"))
        self.assertFalse(self.trie.contains(b"doge"))
        self.assertFalse(self.trie.contains(b"horse"))

    def test_save_and_load_one_value(self):
        """Test if the self.trie can be saved and loaded with one value."""
        # Add some data
        data = [b'do']
        for kv in data:
            self.trie.update(kv, kv)

        # Save the self.trie
        encoded_trie = self.trie.encode()
        new_trie = MPT.decode(encoded_trie)

        # Check if the data is still there
        for kv in data:
            self.assertEqual(new_trie.get(kv), kv, 'Data not found in self.trie.')

    def test_save_and_load_multiple_values(self):
        """Test if the self.trie can be saved and loaded with multiple values."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Save the self.trie
        encoded_trie = self.trie.encode()
        new_trie = MPT.decode(encoded_trie)

        # Check if the data is still there
        for kv in data:
            self.assertEqual(new_trie.get(kv), kv, 'Data not found in self.trie.')

    def test_save_and_load_lot_of_values(self):
        """Test if the self.trie can be saved and loaded with lot of values."""
        # Add some data
        data = [str(i).encode() for i in range(100)]
        for kv in data:
            self.trie.update(kv, kv)

        # Save the self.trie
        encoded_trie = self.trie.encode()
        new_trie = MPT.decode(encoded_trie)

        # Check if the data is still there
        for kv in data:
            self.assertEqual(new_trie.get(kv), kv, 'Data not found in self.trie.')

    def test_save_and_load_new_item_to_copy(self):
        """Test if the roots differ when an item is only added to original."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Save the self.trie
        encoded_trie = self.trie.encode()
        new_trie = MPT.decode(encoded_trie)

        # Add new item
        new_trie.update(b'new', b'new')

        self.assertNotEqual(self.trie.root_hash(), new_trie.root_hash(), 'Root hashes are equal but should not be.')
    
    def test_save_and_load_new_item(self):
        """Test if the roots differ when a new value is added to original and copy."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Save the self.trie
        encoded_trie = self.trie.encode()
        new_trie = MPT.decode(encoded_trie)

        # Add new item
        new_trie.update(b'new', b'new')
        self.trie.update(b'new', b'new')

        self.assertEqual(new_trie.root_hash(), new_trie.root_hash(), 'Root hashes are not equal but should be.')

    def test_save_and_load_remove_item(self):
        """Test if the roots differ when an item is removed from original and copy."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Save the self.trie
        encoded_trie = self.trie.encode()
        new_trie = MPT.decode(encoded_trie)

        # Remove an item
        new_trie.delete(data[0])
        self.trie.delete(data[0])

        self.assertEqual(self.trie.root_hash(), new_trie.root_hash(), 'Root hashes are not equal but should be.')

    def test_save_and_load_update_item(self):
        """Test if the roots differ when an item is updated in original and copy."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Save the self.trie
        encoded_trie = self.trie.encode()
        new_trie = MPT.decode(encoded_trie)

        # Update an item
        new_trie.update(b'new', b'dog')
        self.trie.update(b'new', b'dog')

        self.assertEqual(self.trie.root_hash(), new_trie.root_hash(), 'Root hashes are not equal but should be.')

    def test_proof_on_copy(self):
        """Test if the proof is correct when the original is modified."""
        # Add some data
        data = [b'do', b'dog', b'doge', b'horse']
        for kv in data:
            self.trie.update(kv, kv)

        # Save the self.trie
        encoded_trie = self.trie.encode()
        new_trie = MPT.decode(encoded_trie)

        proof = self.trie.get_proof_of_inclusion(data[0])
        self.trie.update(b'new', b'dog')
        self.assertFalse(self.trie.verify_proof_of_inclusion(proof))
        self.assertTrue(new_trie.verify_proof_of_inclusion(proof))



class TestMptSecure(TestMptNonSecure):
    ROOT_HASH = "29b235a58c3c25ab83010c327d5932bcf05324b7d6b1185e650798034783ca9d"
    ROOT_HASH_AFTER_UPDATES = "29b235a58c3c25ab83010c327d5932bcf05324b7d6b1185e650798034783ca9d"
    ROOT_HASH_AFTER_DELETES = "29b235a58c3c25ab83010c327d5932bcf05324b7d6b1185e650798034783ca9d"

    def setUp(self):
        self.storage = {}
        self.trie = MPT(storage=self.storage, secure=True)

