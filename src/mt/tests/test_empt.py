import sys, os

# Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)
from trie.empt import EMPT, DataReference, SparseEMPT, RootEMPT
from trie.node import Node
from trie.exceptions import KeyNotFoundError
from trie.hash import keccak_hash
import rlp
import unittest
import random
import copy

try:
    from .test_mpt import ProofOfExclusion, ProofOfInclusion
except ImportError:
    from test_mpt import ProofOfExclusion, ProofOfInclusion


class TestDataReference(unittest.TestCase):
    def test_equals(self):
        key = b"key"
        value = b"value"
        ref = DataReference(key, value)
        ref2 = DataReference(key, value)
        self.assertEqual(ref, ref2)

        ref3 = DataReference(key, b"other value")
        self.assertNotEqual(ref, ref3)

    def test_hash(self):
        key = b"key"
        value = b"value"
        ref = DataReference(key, value)

        expected = int(keccak_hash(key + value, hexdigest=True), 16)
        self.assertEqual(ref.hash, expected)
        self.assertEqual(ref.__hash__(), expected)

    def test_encode_rlp(self):
        key = b"key"
        value = b"value"
        ref = DataReference(key, value)
        expected = rlp.encode(["FF", key, value, ref.hash])
        self.assertEqual(ref.encode(), expected)

    def test_decode_rlp(self):
        key = b"key"
        value = b"value"
        ref = DataReference(key, value)
        encoded = rlp.encode(["FF", key, value, ref.hash])
        decoded = DataReference.decode(encoded)
        self.assertEqual(ref, decoded)


class TestFullEmptNonSecure(unittest.TestCase, ProofOfInclusion, ProofOfExclusion):
    """Test the full DBMMPT."""

    ROOT_HASH = b"some root hash"
    ROOT_HASH_AFTER_UPDATES = b"some other root hash"
    ROOT_HASH_AFTER_DELETES = b"some other root hash"

    def setUp(self):
        self.storage = {}
        self.trie_storage = {}
        self.trie = EMPT(trie_storage=self.trie_storage, data_storage=self.storage)

    def test_len(self):
        self.assertEqual(len(self.trie), 0)
        self.trie.update(rlp.encode(b"key"), b"value")
        self.assertEqual(len(self.trie), 1)

    def test_insert_get_one_short(self):
        """Test inserting one short key-value pair and then getting it."""
        key = rlp.encode(b"key")
        value = rlp.encode(b"value")
        self.trie.update(key, value)
        gotten_value = self.trie.get(key)

        self.assertEqual(value, gotten_value)

        with self.assertRaises(KeyError):
            self.trie.get(rlp.encode(b"no_key"))

        ref = DataReference(key, value)
        self.assertEqual(self.trie.get_reference(key), ref)

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
        ref = DataReference(key, value)
        self.assertEqual(self.trie.get_reference(key), ref)

    def test_insert_get_many(self):
        """Test inserting many key-value pairs and then getting them."""
        data = [
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        ]
        for k, v in data:
            self.trie.update(k, v)

        for k, v in data:
            self.assertEqual(self.trie.get(k), v)
            ref = DataReference(k, v)
            self.assertEqual(self.trie.get_reference(k), ref)

    def test_insert_get_lots(self):
        """Test inserting lots of key-value pairs and then getting them."""
        random.seed(42)
        rand_numbers = [random.randint(1, 1000000) for _ in range(100)]
        keys = list(map(lambda x: bytes("{}".format(x), "utf-8"), rand_numbers))

        for kv in keys:
            self.trie.update(kv, kv * 2)

        for kv in keys:
            self.assertEqual(self.trie.get(kv), kv * 2)
            ref = DataReference(kv, kv * 2)
            self.assertEqual(self.trie.get_reference(kv), ref)

    def test_delete_one(self):
        """Test deleting one key-value pair and then getting it."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"key", b"value")
        self.trie.delete(b"key")

        with self.assertRaises(KeyError):
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

        self.assertEqual(root_hash, self.ROOT_HASH)

    def test_root_hash_after_updates(self):
        """Test getting the root hash of a trie after updates."""
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
            (b"a", b"aaa"),
            (b"some_key", b"some_value"),
            (b"dodog", b"do_dog"),
        )
        for k, v in data:
            self.trie.update(k, v)

        root_hash = self.trie.root_hash()

        self.assertEqual(root_hash, self.ROOT_HASH_AFTER_UPDATES)

    def test_root_hash_after_deletes(self):
        """Test getting the root hash of a trie after deletes."""
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
            (b"dodo", b"pizza"),
            (b"hover", b"board"),
            (b"capital", b"Moscow"),
            (b"a", b"b"),
        )
        for k, v in data:
            self.trie.update(k, v)

        for k, v in data[-4:]:
            self.trie.delete(k)

        root_hash = self.trie.root_hash()
        self.assertEqual(root_hash, self.ROOT_HASH_AFTER_DELETES)

    # def test_trie_from_old_root(self):
    #     """Test getting the root hash of a trie after deletes."""
    #     self.trie.update(b"do", b"verb")
    #     self.trie.update(b"dog", b"puppy")

    #     root = self.trie.root()

    #     self.trie.delete(b"dog")
    #     self.trie.update(b"do", b"not_a_verb")

    #     trie_from_old = StorageMMPT(data_storage={}, trie_storage=self.storage,
    #                                 root=root)

    #     # Old.
    #     self.assertEqual(trie_from_old.get(b"do"), b"verb")
    #     self.assertEqual(trie_from_old.get(b"dog"), b"puppy")

    #     # New.
    #     self.assertEqual(self.trie.get(b"do"), b"not_a_verb")
    #     with self.assertRaises(KeyNotFoundError):
    #         self.trie.get(b"dog")

    def test_contains(self):
        """Test checking if a key is in the trie."""
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )
        for key, value in data:
            self.trie.update(key, value)

        # Test exising keys
        for key, value in data:
            self.assertTrue(self.trie.contains(key))
            self.assertTrue(self.trie.__contains__(key))
            self.assertTrue(key in self.trie)

        # Test non-existing keys
        non_keys = (b"doe", b"doggy", b"dogecoin", b"horsepower")
        for k in non_keys:
            self.assertFalse(self.trie.contains(k))
            self.assertFalse(self.trie.__contains__(k))
            self.assertFalse(k in self.trie)

        # Test some numbers
        keys = [str(i).encode() for i in range(101, 201)]
        for k in keys:
            self.assertFalse(self.trie.contains(k))

    def test_contains_empty(self):
        """Test checking if a key is in the trie."""
        self.assertFalse(self.trie.contains(b"do"))
        self.assertFalse(self.trie.contains(b"dog"))
        self.assertFalse(self.trie.contains(b"doge"))
        self.assertFalse(self.trie.contains(b"horse"))


class TestFullEmptSecure(TestFullEmptNonSecure):
    ROOT_HASH = b"have to set a hash here"
    ROOT_HASH_AFTER_UPDATES = b"have to set a hash here"
    ROOT_HASH_AFTER_DELETES = b"have to set a hash here"

    def setUp(self):
        """Set up the test."""
        self.storage = {}
        self.trie_storage = {}
        self.trie = EMPT(
            data_storage=self.storage, trie_storage=self.trie_storage, secure=True
        )


class TestSparseEmptNonSecure(unittest.TestCase, ProofOfInclusion, ProofOfExclusion):

    ROOT_HASH = b"have to set a hash here"
    ROOT_HASH_AFTER_UPDATES = b"have to set a hash here"
    ROOT_HASH_AFTER_DELETES = b"have to set a hash here"

    @classmethod
    def setUpClass(cls):
        cls.storage = {}
        trie = EMPT(data_storage={}, trie_storage=cls.storage)
        cls.data = (
            (b"digeridoo", b"instrument"),
            (b"bike", b"vehicle"),
            (b"car", b"vehicle"),
            (b"caterpillar", b"animal"),
            (b"sandwitch", b"food"),
            (b"icecream", b"food"),
        )
        for k, v in cls.data:
            trie.update(k, v)

        cls.source_root = trie.root()

    def setUp(self):
        storage = copy.deepcopy(self.storage)
        root = copy.deepcopy(self.source_root)
        self.trie = SparseEMPT(trie_storage=storage, root=root)

    def test_insert_get_one_short(self):
        key = b"king"
        value = b"queen"

        self.trie.update(key, value)

        ref = DataReference(key, value)
        self.assertEqual(self.trie.get_reference(key), ref)

    def test_insert_get_one_long(self):
        key = b"dogsnjwacqiob3om8whqne9icha ofaohnsuikv bschm hweoacduwac wku bacm ukwmbc na ce"
        value = b"puppy chkawucb wik jwacj h wkab wkda,n zv krac sjndbywafbjdwc aki,cbn av anck wdzmvbkab u"

        self.trie.update(key, value)

        ref = DataReference(key, value)
        self.assertEqual(self.trie.get_reference(key), ref)

    def test_insert_get_many(self):
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )

        for k, v in data:
            self.trie.update(k, v)

        for k, v in data:
            ref = DataReference(k, v)
            self.assertEqual(self.trie.get_reference(k), ref)

    def test_insert_get_lots(self):
        random.seed(42)
        rand_numbers = [random.randint(1, 1000000) for _ in range(100)]
        keys = list(map(lambda x: bytes("{}".format(x), "utf-8"), rand_numbers))

        for kv in keys:
            self.trie.update(kv, kv * 2)

        for kv in keys:
            ref = DataReference(kv, kv * 2)
            self.assertEqual(self.trie.get_reference(kv), ref)

    def test_delete_one(self):
        key = b"do"
        value = b"verb"

        self.trie.update(key, value)
        self.trie.update(b"og", b"puppy")
        self.trie.delete(key)

        ref = DataReference(key, value)
        with self.assertRaises(KeyNotFoundError):
            self.trie.get_reference(key)
        with self.assertRaises(AttributeError):
            self.trie.get(key)

    def test_delete_many(self):
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )

        for k, v in data:
            self.trie.update(k, v)

        for k, v in data[:-1]:
            self.trie.delete(k)

        for k, v in data[:-1]:
            ref = DataReference(k, v)
            with self.assertRaises(KeyNotFoundError):
                self.trie.get_reference(k)
            with self.assertRaises(AttributeError):
                self.trie.get(k)

    def test_delete_lots(self):
        random.seed(42)
        rand_numbers = [random.randint(1, 1000000) for _ in range(100)]
        keys = list(map(lambda x: bytes("{}".format(x), "utf-8"), rand_numbers))

        for kv in keys:
            self.trie.update(kv, kv * 2)

        for kv in keys[:-1]:
            self.trie.delete(kv)

        for kv in keys[:-1]:
            ref = DataReference(kv, kv * 2)
            with self.assertRaises(KeyNotFoundError):
                self.trie.get_reference(kv)
            with self.assertRaises(AttributeError):
                self.trie.get(kv)

    def test_root_hash(self):
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )

        for k, v in data:
            self.trie.update(k, v)

        self.assertEqual(self.trie.root_hash, self.ROOT_HASH)

    def test_root_hash_after_update(self):
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )

        for k, v in data:
            self.trie.update(k, v)

        self.trie.update(b"horse", b"mare")

        self.assertEqual(self.trie.root_hash, self.ROOT_HASH_AFTER_UPDATES)

    def test_root_hash_after_delete(self):
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )

        for k, v in data:
            self.trie.update(k, v)

        self.trie.delete(b"horse")
        self.trie.delete(b"doge")

        self.assertEqual(self.trie.root_hash, self.ROOT_HASH_AFTER_DELETES)

    def test_contains(self):
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )

        for k, v in data:
            self.trie.update(k, v)

        for k, v in data:
            self.assertTrue(self.trie.contains(k))

    def test_poi_proof_on_empty_trie(self):
        self.trie = SparseEMPT(trie_storage={})
        super().test_poi_proof_on_empty_trie()

    def test_poe_proof_on_empty_trie(self):
        self.trie = SparseEMPT(trie_storage={})
        return super().test_poe_proof_on_empty_trie()


class TestSparseEmptSecure(TestSparseEmptNonSecure):
    ROOT_HASH = b'\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f'
    ROOT_HASH_AFTER_UPDATE = b'\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f'
    ROOT_HASH_AFTER_DELETE = b'\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f\x9f\x1f'

    def setUp(self):
        self.trie = SparseEMPT({}, secure=True)


class TestRootEmptNonSecure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )
        cls.non_data = (
            (b"cat", b"meow"),
            (b"bird", b"tweet"),
            (b"fish", b"blub"),
        )

    def setUp(self):
        self.full_trie = EMPT({}, {}, secure=False)
        for k, v in self.data:
            self.full_trie.update(k, v)

        root = copy.deepcopy(self.full_trie.root())
        self.trie = RootEMPT(root=root, secure=False)

    def test_poi_verify(self):
        """Test the proof of inclusion verification."""
        for k, v in self.data:
            poi = self.full_trie.get_proof_of_inclusion(k)
            self.assertTrue(self.trie.verify_proof_of_inclusion(poi))

    def test_poi_verify_after_update(self):
        """Test the proof of inclusion verification after an update."""
        self.full_trie.update(self.non_data[0][0], self.non_data[0][1])

        poi = self.full_trie.get_proof_of_inclusion(self.non_data[0][0])
        self.assertFalse(self.trie.verify_proof_of_inclusion(poi))

    def test_poi_verify_after_delete(self):
        """Test the proof of inclusion verification after a delete."""
        self.full_trie.delete(self.data[0][0])
        self.full_trie.delete(self.data[3][0])

        poi = self.full_trie.get_proof_of_inclusion(self.data[2][0])
        self.assertFalse(self.trie.verify_proof_of_inclusion(poi))

    def test_poe_verify(self):
        """Test the proof of exclusion verification."""
        for k, v in self.non_data:
            poe = self.full_trie.get_proof_of_exclusion(k)
            self.assertTrue(self.trie.verify_proof_of_exclusion(poe))

    def test_poe_verify_after_update(self):
        """Test the proof of exclusion verification after an update."""
        self.full_trie.update(self.non_data[0][0], self.non_data[0][1])

        poe = self.full_trie.get_proof_of_exclusion(self.non_data[1][0])
        self.assertFalse(self.trie.verify_proof_of_exclusion(poe))

    def test_poe_verify_after_delete(self):
        """Test the proof of exclusion verification after a delete."""
        self.full_trie.delete(self.data[2][0])
        self.full_trie.delete(self.data[1][0])

        poe = self.full_trie.get_proof_of_exclusion(self.non_data[0][0])
        self.assertFalse(self.trie.verify_proof_of_exclusion(poe))


class TestRootEmptSecure(TestRootEmptNonSecure):
    def setUp(self):
        self.full_trie = EMPT({}, {}, secure=True)
        for k, v in self.data:
            self.full_trie.update(k, v)

        root = copy.deepcopy(self.full_trie.root())
        self.trie = RootEMPT(root=root, secure=True)


if __name__ == "__main__":
    unittest.main()
