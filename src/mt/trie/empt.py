from .mpt import MPT
from .exceptions import InvalidReferenceError
from .hash import keccak_hash
import rlp
from _collections_abc import MutableMapping
from .proof import Proof
from typing import Iterable, Union


class DataReference:
    """
    Data reference class.

    The data reference class is used to reduce the data that is stored in the MMPT
    while still being able to verify the data.
    """

    def __init__(self, key: bytes, data: bytes) -> ...:
        """
        Initiate the data reference.

        Parameters
        ----------
        key : bytes
            The key of the data.
        data : bytes
            The data that is referenced.
        """
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes, not {}".format(type(key)))
        self._key = key

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes, not {}".format(type(data)))
        self._data = data
        self._hash = self.__hash__()

    @property
    def key(self) -> bytes:
        return self._key

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def hash(self) -> bytes:
        """
        Return the hash of the data reference.

        the hash is calculated as keccak(key + data)
        """
        return self._hash

    # DUNDER METHODS
    def __eq__(self, other) -> bool:
        if not isinstance(other, DataReference):
            return False
        return self.hash == other.hash

    def __hash__(self) -> int:
        return int(keccak_hash(self._key + self._data, hexdigest=True), 16)

    # CODEC
    def encode(self) -> bytes:
        """Encode the data reference to bytes."""
        return rlp.encode([b"FF", self._key, self._data, self._hash])

    @staticmethod
    def decode(data: bytes) -> "DataReference":
        """Decode the data reference from bytes."""
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes, not {}".format(type(data)))
        sedes = rlp.sedes.List(
            [
                rlp.sedes.binary,
                rlp.sedes.binary,
                rlp.sedes.binary,
                rlp.sedes.big_endian_int,
            ]
        )
        flag, key, data, hash = rlp.decode(data, sedes=sedes)
        if flag != b"FF":
            raise ValueError("Corrupted data reference or not a reference.")

        ref = DataReference(key, data)
        if ref.hash != hash:
            raise ValueError(
                "Invalid data reference, saved hash does not match calculated hash"
            )
        return ref


class EMPT(MutableMapping):
    """
    This class is a wrapper for a storage class that implements the MPT.

    The  ExtendedMPT (EMPT) is a wrapper around a storage class that implements the
    dict interface (see description of functions below). The MPT is used to
    save references to the data in the storage. This way the data can be
    validated against the MPT and the data can be retrieved from the storage
    without having to traverse the MPT.

    The MPT storage as well as the data storage can be defined by the user
    and passed to the constructor. The storage must implement the following
    methods:
    - __getitem__(key: bytes) -> bytes
    - __setitem__(key: bytes, value: bytes)
    - __delitem__(key: bytes)
    - __contains__(key: bytes) -> bool
    - __len__() -> int
    - keys() -> List[bytes]

    .. note::
        It is recommended to inherit from :class:`MutableMapping` when using a
        custom storage class (for example :class:`dict`).
    """

    def __init__(
        self,
        trie_storage={},
        data_storage={},
        root: Union[bytes, None] = None,
        secure: bool = False,
    ) -> ...:
        """
        Initiate the StorageMMPT.

        The trie can be used in three different modes:
        - FULL: The data is stored in the data storage and the reference is
                stored in the trie.
        - SPARSE: The data is not stored in the data storage but the reference
                    is still stored in the trie.

            .. note::
                This mode cannot be used to retreive data, but it can still create
                and validate proofs

        - ROOT: The data is not stored in either the data storage or the trie.

            .. note::
                This mode cannot be used to set or retreive data, it can only be
                used to validate proofs.

        Parameters
        ----------
        trie_storage : Storage, optional
            The storage that will be used to store the trie. Default is an
            empty dict.
        data_storage : Storage, optional
            The storage that will be used to store the data. Default is
            an empty dict.
        root : bytes, optional
            The encoded root node of the trie. If this is not None, the trie
            will be considered empty. Default is None.
        secure : bool, optional
            If the trie should be secure or not. If the trie is secure
            the key is hashed before it is used in the trie. Default is False.

            .. warning::
                Setting secure to True will only hash the key.
                The trie does not encrypt or hash the value, this is the
                responsibility of the user.
        """
        if data_storage is None:
            raise TypeError(
                "The data storage must be set when the trie is in FULL mode"
            )
        if len(trie_storage) != 0 and root is None:
            raise ValueError(
                "The nodes in the trie storage must be deleted or the root must be set"
            )

        self._data_storage = data_storage
        self._trie = MPT(trie_storage, secure=secure, root=root)

    # PROPERTIES
    @property
    def secure(self) -> bool:
        """Return whether the trie is secure or not."""
        return self._trie.secure

    # DUNDER METHODS
    def __len__(self) -> int:
        """Return the number of references in the trie."""
        return len(self._data_storage)

    def __iter__(self) -> Iterable[bytes]:
        """Return an iterator over the keys in the trie."""
        return iter(self._data_storage)

    def __getitem__(self, key: bytes) -> bytes:
        """Wrapper for the get method."""
        return self.get(key)

    def __setitem__(self, key: bytes, value: bytes) -> ...:
        """Wrapper for the update method."""
        self.update(key, value)

    def __delitem__(self, key: bytes) -> ...:
        """Wrapper for the delete method."""
        self.delete(key)

    def __contains__(self, key: bytes) -> bool:
        """Wrapper for the contains method."""
        return self.contains(key)

    # TRIE METHODS
    def root_hash(self) -> bytes:
        """Return the hash of the root of the trie."""
        return self._trie.root_hash()

    def root(self) -> bytes:
        """Return the root of the trie."""
        return self._trie.root()

    def build_trie(self) -> ...:
        """
        Build the trie.

        The trie is built from the data storage. If the trie is already built,
        it will be rebuilt.

        .. note::
            This method is very expensive and should be used with caution. As the
            database grows, the time it takes to build the trie will increase.
        """
        # Delete all the nodes in the trie
        for key in self._trie._storage.keys():
            del self._trie._storage[key]

        # Build the new trie
        for key in self._data_storage.keys():
            ref = DataReference(key, self._data_storage[key])
            self._trie.update(key, ref.encode())

    def get(self, key: bytes) -> bytes:
        """
        Get the value of a certain key.

        The value is retrieved from the data storage and validated against the
        trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))

        data = self._data_storage[key]
        ref = self._trie.get(key)
        ref = DataReference.decode(ref)
        expected = DataReference(key, data)
        if ref != expected:
            raise InvalidReferenceError(
                "The reference does not match the expected data"
            )
        return data

    # @typechecked
    def get_reference(self, key: bytes) -> DataReference:
        """Return the data reference corresponding with the key."""
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        return DataReference.decode(self._trie.get(key))

    # @typechecked
    def update(self, key: bytes, value: bytes) -> ...:
        """
        Set the value of a certain key.

        The value is stored in the data storage and a reference is stored in
        the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        if not isinstance(value, bytes):
            raise TypeError("The value must be type bytes, not {}".format(type(value)))
        ref = DataReference(key, value)
        self._trie.update(key, ref.encode())
        self._data_storage[key] = value

    # @typechecked
    def delete(self, key: bytes) -> ...:
        """
        Delete the value of a certain key.

        The value is deleted from the data storage and the reference is deleted
        from the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        del self._data_storage[key]
        self._trie.delete(key)

    # @typechecked
    def contains(self, key: bytes) -> bool:
        """
        Check if a certain key is in the storage.

        The key is checked in the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        return self._trie.contains(key)

    # CONVERSION METHODS
    def get_root_trie(self) -> "RootEMPT":
        """
        Get the root trie.

        The root trie is a trie that only contains the root of the trie.
        """
        return RootEMPT(mode=b"ROOT", secure=self._trie.secure, root=self._trie.root())

    def get_sparse_trie(self) -> "SparseEMPT":
        """
        Get the sparse trie.

        The sparse trie is a trie that only contains the references of the trie.
        """
        return SparseEMPT(
            trie_storage=self._trie._storage,
            secure=self._trie.secure,
            root=self._trie.root(),
        )

    # PROOF METHODS
    def get_proof_of_inclusion(self, key: bytes) -> Proof:
        """
        Get the proof of inclusion for a certain key.

        The proof of inclusion is a proof that a certain key is in the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        return self._trie.get_proof_of_inclusion(key)

    # @typechecked
    def verify_proof_of_inclusion(self, proof: Proof) -> bool:
        """
        Validate a proof of inclusion.

        The proof of inclusion is a proof that a certain key is in the trie.
        """
        if not isinstance(proof, Proof):
            raise TypeError("The proof must be type Proof, not {}".format(type(proof)))
        return self._trie.verify_proof_of_inclusion(proof)

    # @typechecked
    def get_proof_of_exclusion(self, key: bytes) -> Proof:
        """
        Get the proof of exclusion for a certain key.

        The proof of exclusion is a proof that a certain key is not in the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        return self._trie.get_proof_of_exclusion(key)

    # @typechecked
    def verify_proof_of_exclusion(self, proof: Proof) -> bool:
        """
        Validate a proof of exclusion.

        The proof of exclusion is a proof that a certain key is not in the trie.
        """
        if not isinstance(proof, Proof):
            raise TypeError("The proof must be type Proof, not {}".format(type(proof)))
        return self._trie.verify_proof_of_exclusion(proof)


class SparseEMPT:
    """
    The sparse storage EMPT.

    This class is not much more than a wrapper around the :class:`MPT` class. It
    implements the same methods as the :class:`MPT` class but it stores references
    to the data instead of the data itself. This means that the data is not
    stored in the trie and cannot be retrieved, the data reference can still
    be retrieved.

    .. note::
        Although the data is not stored in the trie, the reference is.
        Because the reference can be easily reproduced, existence of a key
        and creation and verification of proofs can still be done.
    """

    def __init__(
        self, trie_storage={}, root: Union[bytes, None] = None, secure: bool = False
    ):
        """
        Initialize the sparse storage EMPT.

        Parameters
        ----------
        trie_storage : Storage, optional
            The storage for the trie. This storage should be a dictionary-like
            object. The default is an empty dictionary.
        root : bytes, optional
            The root of the trie. The default is None.
        secure : bool, optional
            Whether the trie is secure or not. The default is False.

            .. warning::
                Setting secure to True will only hash the key.
                The trie does not encrypt or hash the value, this is the
                responsibility of the user.
        """
        self._trie = MPT(trie_storage, root, secure=secure)

    # DUNDER METHODS
    # These methods are inherited from the parent but not supported in this class.
    def __setitem__(self, key: bytes, value: bytes) -> ...:
        """Wrapper for the update method."""
        self.update(key, value)

    def __delitem__(self, key: bytes) -> ...:
        """Wrapper for the delete method."""
        self.delete(key)

    def __contains__(self, key: bytes) -> bool:
        """Wrapper for the contains method."""
        return self.contains(key)

    # TRIE METHODS
    def root_hash(self) -> bytes:
        """Return the hash of the root of the trie."""
        return self._trie.root_hash()

    def root(self) -> bytes:
        """Return the root of the trie."""
        return self._trie.root()

    # CONVERSION METHODS
    def get_root_trie(self) -> "RootEMPT":
        """
        Get the root trie.

        The root trie is a trie that only contains the root of the trie.
        """
        return RootEMPT(mode=b"ROOT", secure=self._trie.secure, root=self._trie.root())

    # TRIE METHODS
    def get_reference(self, key: bytes) -> DataReference:
        """
        Get the reference of a certain key.

        The reference is stored in the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        return DataReference.decode(self._trie.get(key))

    # @typechecked
    def update(self, key: bytes, value: bytes) -> ...:
        """
        Set the value of a certain key.

        The reference to the value is stored in the trie.

        .. note::
            Because this is a sparse trie the data will not be stored,
            only the reference to the data.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        if not isinstance(value, bytes):
            raise TypeError("The value must be type bytes, not {}".format(type(value)))
        ref = DataReference(key, value)
        self._trie.update(key, ref.encode())

    def delete(self, key: bytes) -> ...:
        """
        Delete the value of a certain key.

        The reference to the value is deleted from the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        self._trie.delete(key)

    def contains(self, key: bytes) -> bool:
        """
        Check whether a certain key is in the trie.

        The reference to the value is checked in the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        return self._trie.contains(key)

    # PROOF METHODS
    def get_proof_of_inclusion(self, key: bytes) -> Proof:
        """
        Get the proof of inclusion for a certain key.

        The proof of inclusion is a proof that a certain key is in the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        return self._trie.get_proof_of_inclusion(key)

    def verify_proof_of_inclusion(self, proof: Proof) -> bool:
        """
        Validate a proof of inclusion.

        The proof of inclusion is a proof that a certain key is in the trie.
        """
        if not isinstance(proof, Proof):
            raise TypeError("The proof must be type Proof, not {}".format(type(proof)))
        return self._trie.verify_proof_of_inclusion(proof)

    def get_proof_of_exclusion(self, key: bytes) -> Proof:
        """
        Get the proof of exclusion for a certain key.

        The proof of exclusion is a proof that a certain key is not in the trie.
        """
        if not isinstance(key, bytes):
            raise TypeError("The key must be type bytes, not {}".format(type(key)))
        return self._trie.get_proof_of_exclusion(key)

    def verify_proof_of_exclusion(self, proof: Proof) -> bool:
        """
        Validate a proof of exclusion.

        The proof of exclusion is a proof that a certain key is not in the trie.
        """
        if not isinstance(proof, Proof):
            raise TypeError("The proof must be type Proof, not {}".format(type(proof)))
        return self._trie.verify_proof_of_exclusion(proof)


class RootEMPT:
    """
    The root storage MMPT.

    This class is not much more than a wrapper around the MMPT class. It
    uses the trie root to validate proofs of inclusion and exclusion.
    """

    def __init__(self, root: bytes, secure: bool = False) -> ...:
        """
        Initialize the root storage MMPT.

        Parameters
        ----------
        root : bytes
            The root of the trie.
        secure : bool
            Whether the trie is secure or not.
        """
        self._trie = MPT({}, root, secure=secure)

    # PROOF VALIDATION METHODS
    def verify_proof_of_inclusion(self, proof: Proof) -> bool:
        """
        Validate a proof of inclusion.

        The proof of inclusion is a proof that a certain key is in the trie.
        """
        if not isinstance(proof, Proof):
            raise TypeError("The proof must be type Proof, not {}".format(type(proof)))
        return self._trie.verify_proof_of_inclusion(proof)

    def verify_proof_of_exclusion(self, proof: Proof) -> bool:
        """
        Validate a proof of exclusion.

        The proof of exclusion is a proof that a certain key is not in the trie.
        """
        if not isinstance(proof, Proof):
            raise TypeError("The proof must be type Proof, not {}".format(type(proof)))
        return self._trie.verify_proof_of_exclusion(proof)
