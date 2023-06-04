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
from unittest.mock import MagicMock
import random
import copy

try:
    from .test_mpt import ProofOfExclusion, ProofOfInclusion
except ImportError:
    from test_mpt import ProofOfExclusion, ProofOfInclusion


class DummyDataClass:
    """
    Class that is used to test the capability to reference and save rlp encodable objects.
    """

    def __init__(self, key : bytes, data : bytes) -> ...:
        if not isinstance(key, bytes):
            raise TypeError("key must be of type bytes")
        if not isinstance(data, bytes):
            raise TypeError("data must be of type bytes")
        self.data = data
        self.key = key

    def encode_rlp(self) -> bytes:
        return rlp.encode([self.key, self.data])
    
    @staticmethod
    def decode_rlp(encoded : bytes) -> "DummyDataClass":
        if not isinstance(encoded, bytes):
            raise TypeError("encoded must be of type bytes")
        key, data = rlp.decode(encoded)
        return DummyDataClass(key, data)
    

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

    ROOT_HASH = "7598c123c0f082dbd703076fa18fd3d714ec6339fd134f1af62a6fb34dd5cba4"
    ROOT_HASH_AFTER_UPDATES = (
        "802e7fce3ed1b6e6017c354221efdd69326ada996d2070459e3867831a9af19d"
    )
    ROOT_HASH_AFTER_DELETES = (
        "7598c123c0f082dbd703076fa18fd3d714ec6339fd134f1af62a6fb34dd5cba4"
    )

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

    def test_insert_get_one_rlp_encodable(self):
        data = DummyDataClass(b"key", b"value")
        self.trie.update(data.key, data)

        gotten_value = self.trie.get(data.key)
        self.assertIsInstance(gotten_value, DummyDataClass)
        self.assertEqual(gotten_value.key, data.key)

    def test_update_one_rlp_encodable(self):
        data = DummyDataClass(b"key", b"value")
        self.trie.update(data.key, data)

        gotten_value = self.trie.get(data.key)
        self.assertIsInstance(gotten_value, DummyDataClass)
        self.assertEqual(gotten_value.key, data.key)

        data2 = DummyDataClass(b"key", b"other value")
        self.trie.update(data2.key, data2)

        gotten_value = self.trie.get(data.key)
        self.assertIsInstance(gotten_value, DummyDataClass)
        self.assertEqual(gotten_value.key, data2.key)

    def test_get_insert_one_short_non_bytes(self):
        test = MagicMock()
        test.encode_rlp.return_value = b"test"
        test.decode_rlp.return_value = test

        self.trie.update(b'key1', test)
        test.encode_rlp.assert_called_once()
        self.assertIsInstance(self.trie.get(b'key1'), MagicMock)

        with self.assertRaises(NotImplementedError):
            self.trie.update(b'key2', 2)

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

    def test_insert_get_many_rlp_encodable(self):
        data = []
        for i in range(5):
            x = DummyDataClass(b"key" + str(i).encode(), b"value" + str(i).encode())
            data.append(x)

        for i in data:
            self.trie.update(i.key, i)

        for i in data:
            gotten_value = self.trie.get(i.key)
            self.assertIsInstance(gotten_value, DummyDataClass)
            self.assertEqual(gotten_value.key, i.key)

    def test_get_insert_get_many_non_bytes(self):
        data = []
        for i in range(5):
            x = MagicMock()
            x.encode_rlp.return_value = str(i).encode()
            x.decode_rlp.return_value = x
            data.append(x)

        for cnt, i in enumerate(data):
            self.trie.update(str(cnt).encode(), i)
            i.encode_rlp.assert_called_once()
        
        for cnt, i in enumerate(data):
            self.assertIsInstance(self.trie.get(str(cnt).encode()), MagicMock)

        with self.assertRaises(NotImplementedError):
            self.trie.update(b'key2', 2)

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

    def test_insert_get_lots_rlp_encodable(self):
        random.seed(42)
        rand_numbers = [random.randint(1, 1000000) for _ in range(100)]
        keys = list(map(lambda x: bytes("{}".format(x), "utf-8"), rand_numbers))

        for kv in keys:
            self.trie.update(kv, DummyDataClass(bytes(kv), (kv * 2)))

        for kv in keys:
            gotten_value = self.trie.get(kv)
            self.assertIsInstance(gotten_value, DummyDataClass)
            self.assertEqual(gotten_value.key, kv)

    def test_get_insert_get_lots_non_bytes(self):
        data = []
        for i in range(100):
            x = MagicMock()
            x.encode_rlp.return_value = str(i).encode()
            x.decode_rlp.return_value = x
            data.append(x)

        for cnt, i in enumerate(data):
            self.trie.update(str(cnt).encode(), i)
            i.encode_rlp.assert_called_once()
        
        for cnt, i in enumerate(data):
            self.assertIsInstance(self.trie.get(str(cnt).encode()), MagicMock)

        with self.assertRaises(NotImplementedError):
            self.trie.update(b'key2', 2)

    def test_delete_one(self):
        """Test deleting one key-value pair and then getting it."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"key", b"value")
        self.trie.delete(b"key")

        with self.assertRaises(KeyError):
            self.trie.get(b"key")

        self.assertEqual(self.trie.get(b"do"), b"verb")

    def test_delete_one_rlp_encodable(self):
        entry1 = DummyDataClass(b"key1", b"value1")
        entry2 = DummyDataClass(b"key2", b"value2")
        self.trie.update(entry1.key, entry1)
        self.trie.update(entry2.key, entry2)
        self.trie.delete(entry1.key)

        with self.assertRaises(KeyError):
            self.trie.get(entry1.key)

        self.assertEqual(self.trie.get(entry2.key), entry2)

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

    def test_delete_many_rlp_encodable(self):
        entry1 = DummyDataClass(b"key1", b"value1")
        entry2 = DummyDataClass(b"key2", b"value2")
        entry3 = DummyDataClass(b"key3", b"value3")
        entry4 = DummyDataClass(b"key4", b"value4")
        self.trie.update(entry1.key, entry1)
        self.trie.update(entry2.key, entry2)
        self.trie.update(entry3.key, entry3)
        self.trie.update(entry4.key, entry4)

        root_hash = self.trie.root_hash()

        entry5 = DummyDataClass(b"key5", b"value5")
        entry6 = DummyDataClass(b"key6", b"value6")
        entry7 = DummyDataClass(b"key7", b"value7")
        self.trie.update(entry5.key, entry5)
        self.trie.update(entry6.key, entry6)
        self.trie.update(entry7.key, entry7)

        self.trie.delete(entry5.key)
        self.trie.delete(entry6.key)
        self.trie.delete(entry7.key)

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

    def test_delete_lots_rlp_encodable(self):
        random.seed(42)
        rand_numbers = set(
            [random.randint(1, 1000000) for _ in range(100)]
        )

        data = []
        for i in rand_numbers:
            x = DummyDataClass(str(i).encode(), str(i * 2).encode())
            data.append(x)

        for kv in data:
            self.trie.update(kv.key, kv)

        for kv in data:
            self.trie.delete(kv.key)

        self.assertEqual(self.trie.root_hash(), Node.EMPTY_HASH)

    def test_root_hash(self):
        """Test getting the root hash of a trie."""
        self.trie.update(b"do", b"verb")
        self.trie.update(b"dog", b"puppy")
        self.trie.update(b"doge", b"coin")
        self.trie.update(b"horse", b"stallion")

        root_hash = self.trie.root_hash()

        self.assertEqual(root_hash.hex(), self.ROOT_HASH)

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

        self.assertEqual(root_hash.hex(), self.ROOT_HASH_AFTER_UPDATES)

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
        self.assertEqual(root_hash.hex(), self.ROOT_HASH_AFTER_DELETES)

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
    ROOT_HASH = "14b986c52c285e80583ffbd8683e2218211c99f089b2534c7dc474925af13276"
    ROOT_HASH_AFTER_UPDATES = (
        "554c18b65fec9cc090469cefaefd3dbe8a8123dd9ae178c2f7d96432dbf60b8c"
    )
    ROOT_HASH_AFTER_DELETES = (
        "14b986c52c285e80583ffbd8683e2218211c99f089b2534c7dc474925af13276"
    )

    def setUp(self):
        """Set up the test."""
        self.storage = {}
        self.trie_storage = {}
        self.trie = EMPT(
            data_storage=self.storage, trie_storage=self.trie_storage, secure=True
        )


class TestSparseEmptNonSecure(unittest.TestCase, ProofOfInclusion, ProofOfExclusion):
    ROOT_HASH = "175d31ebdcc71dec9a0f869cf7e00585f861413e910170514eeb76c080a3801d"
    ROOT_HASH_AFTER_UPDATES = (
        "175d31ebdcc71dec9a0f869cf7e00585f861413e910170514eeb76c080a3801d"
    )
    ROOT_HASH_AFTER_DELETES = (
        "0c3b843aeb53187e821416668635a9ac454579486ad1b06bd16a57b06ebfb9b0"
    )

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

        self.assertEqual(self.trie.root_hash().hex(), self.ROOT_HASH)

    def test_root_hash_after_update(self):
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )

        for k, v in data:
            self.trie.update(k, v)

        root_hash = self.trie.root_hash()

        self.assertEqual(root_hash.hex(), self.ROOT_HASH_AFTER_UPDATES)

    def test_root_hash_after_delete(self):
        data = (
            (b"do", b"verb"),
            (b"dog", b"puppy"),
            (b"doge", b"coin"),
            (b"horse", b"stallion"),
        )

        for k, v in data:
            self.trie.update(k, v)

        for k, v in data[-1:]:
            self.trie.delete(k)

        root_hash = self.trie.root_hash()
        self.assertEqual(root_hash.hex(), self.ROOT_HASH_AFTER_DELETES)

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

    def test_encode_decode_rlp(self):
        data = {
            b"do": b"verb",
            b"dog": b"puppy",
            b"doge": b"coin",
        }
        for k, v in data.items():
            self.trie.update(k, v)
        encoded = self.trie.encode_rlp()
        expected = self.trie._trie.encode()
        self.assertEqual(encoded, expected)

        decoded = SparseEMPT.decode_rlp(encoded)
        self.assertEqual(decoded.root_hash(), self.trie.root_hash())


class TestSparseEmptSecure(TestSparseEmptNonSecure):
    ROOT_HASH = "14b986c52c285e80583ffbd8683e2218211c99f089b2534c7dc474925af13276"
    ROOT_HASH_AFTER_UPDATES = (
        "14b986c52c285e80583ffbd8683e2218211c99f089b2534c7dc474925af13276"
    )
    ROOT_HASH_AFTER_DELETES = (
        "800641195c56ee2e27ce01736309bf994689099b078a7ff2a4091ee493f855b5"
    )

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

    def test_encode_decode_rlp(self):
        encoded = self.trie.encode_rlp()
        expected = self.trie._trie.encode()

        self.assertEqual(encoded, expected)

        decoded = RootEMPT.decode_rlp(encoded)
        self.assertEqual(decoded.root_hash(), self.trie.root_hash())


class TestRootEmptSecure(TestRootEmptNonSecure):
    def setUp(self):
        self.full_trie = EMPT({}, {}, secure=True)
        for k, v in self.data:
            self.full_trie.update(k, v)

        root = copy.deepcopy(self.full_trie.root())
        self.trie = RootEMPT(root=root, secure=True)


if __name__ == "__main__":
    unittest.main()
