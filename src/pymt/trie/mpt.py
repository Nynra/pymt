from enum import Enum
from .hash import keccak_hash
from .nibble_path import NibblePath
from .proof import Proof
from .node import (
    Node,
    Leaf,
    Extension,
    Branch,
    _prepare_reference_for_encoding,
    _prepare_reference_for_usage,
)
from .exceptions import (
    KeyNotFoundError,
    ExtensionPathError,
    LeafPathError,
    BranchPathError,
    PoeError,
    PoiError,
    InvalidNodeError,
)
from typing import Tuple, List, Union, Optional
import rlp


class MPT:
    """
    This class represents a trie.

    MerklePatriciaTrie works like a wrapper over provided storage.
    Storage must implement dict-like interface. Any data structure
    that implements `__getitem__` and `__setitem__` should be OK.

    IMPORTANT: MPT's use the terms path, node_ref, node value a lot
    and it can cause some confusion.
    -   path is a sequence of nibbles. The path is used for database lookup
        and consists of the steps down the tree that are needed to reach the value.
    -   node_ref is a reference to a node in the storage. The node ref is a
        hash of the node itself.
    -   node is the object that represents a node in the trie. It can be a leaf,
        an extension or a branch. How many values are stored in a node depends on
        the node type.

    Methods
    -------
    get(encoded_key)
        This method gets a value associtated with provided key.
    update(encoded_key, encoded_value)
        This method updates a provided key-value pair into the trie.
    delete(encoded_key)
        This method removes a value associtated with provided key.
    """

    def __init__(
        self, storage: dict, root: Union[bytes, None] = None, secure: bool = False
    ) -> ...:
        """
        Create a new instance of MPT.

        Parameters
        ----------
        storage: dict-like
            Data structure to store all the data of MPT.
        root: bytes
            (Optional) Root node (not root hash!) of the trie.
            If not provided, tree will be considered empty.
        secure: bool
            (Optional) In secure mode all the keys are hashed using keccak256 internally.
        """
        self._storage = storage
        if root == ... or root is None:
            self._root = Node.EMPTY_HASH
        else:
            self._root = root
        self._secure = secure

    # PROPERTIES
    @property
    def secure(self) -> bool:
        """Return True if trie is in secure mode."""
        return self._secure

    # DUNDER METHODS
    def __len__(self) -> int:
        """Return the number of nodes in the trie."""
        return len(self._storage.keys())

    def __contains__(self, encoded_key: bytes) -> bool:
        return self.contains(encoded_key)

    def __getitem__(self, encoded_key: bytes) -> bytes:
        return self.get(encoded_key)

    def __setitem__(self, encoded_key: bytes, encoded_value: bytes) -> None:
        self.update(encoded_key, encoded_value)

    def __delitem__(self, encoded_key: bytes) -> None:
        self.delete(encoded_key)

    def __hash__(self) -> int:
        return int(keccak_hash(self._root), 16)

    def __eq__(self, other: "MPT") -> bool:
        if not isinstance(other, MPT):
            return False
        return self.__hash__() == other.__hash__()

    # TREE FUNCTIONS
    def root(self) -> Union[bytes, None]:
        """
        Return a root node of the trie.

        Returns
        -------
        Node
            Root node of the trie. Type is `bytes` if trie isn't empty and `None` otherwise.
        """
        return self._root

    def root_hash(self) -> bytes:
        """
        Returns a hash of the trie's root node.

        For empty trie it's the hash of the RLP-encoded empty string.

        Returns
        -------
        bytes
            Hash of the trie's root node.
        """
        if not self._root:
            return Node.EMPTY_HASH
        elif len(self._root) == 32:  # Root is already a hash
            return self._root
        else:
            return keccak_hash(self._root)

    def get(self, encoded_key: bytes) -> bytes:
        """
        This method gets a value associtated with provided key.

        This method does not RLP-encode or hash the key.
        If you use encoded keys, you should encode it yourself.

        Parameters
        ----------
        encoded_key: bytes
            Key or RLP-encoded key.

        Returns
        -------
        bytes
            Stored value associated with provided key.

        Raises
        ------
        KeyError
            KeyError is raised if there is no value assotiated with provided key.
        """
        if not self._root:
            raise ValueError("Trie is empty")

        if self._secure:
            encoded_key = keccak_hash(encoded_key)

        path = NibblePath(encoded_key)
        result_node = self._get(self._root, path)
        return result_node.data

    def update(self, encoded_key: bytes, encoded_value: bytes) -> ...:
        """
        This method updates a provided key-value pair into the trie.

        If there is no such a key in the trie, a new entry will be created.
        Otherwise value associtaed with key is updated.

        This method does not RLP-encode the key and value.
        If you use encoded keys and values, you should encode them yourself.

        Parameters
        ----------
        encoded_key: bytes
            Key or RLP-encoded key.
        encoded_value: bytes
            Value or RLP-encoded value.
        """
        if self._secure:
            encoded_key = keccak_hash(encoded_key)

        path = NibblePath(encoded_key)
        result = self._update(self._root, path, encoded_value)
        self._root = result

    # Find out if the key is in the trie
    def contains(self, key: bytes, hash_key: bool = True) -> bool:
        """
        This method checks if the key is in the trie.

        This method does not RLP-encode the key.
        If you use encoded keys, you should encode them yourself.
        """
        if not self._root:
            return False

        if self._secure and hash_key:
            key = keccak_hash(key)

        path = NibblePath(key)
        node = self._contains(self._root, path)

        # If the node is a branch check if it has a value
        if isinstance(node, Branch):
            if node.data != None and node.data != b"":
                return True
            else:
                return False

        # If the node is an extension the key is not in the trie
        # Extension nodes dont hold data
        if isinstance(node, Extension):
            return False

        # If the node is a leaf the key is in the trie
        if isinstance(node, Leaf):
            if node.path == path:
                return True
            else:
                return False
        else:
            # Path doesnt match so key is not in the trie
            return False

        raise Exception("This should never happen")

    def delete(self, encoded_key: bytes) -> ...:
        """
        This method removes a value associtated with provided key.

        This method does not RLP-encode the key.
        If you use encoded keys, you should encode it yourself.

        Parameters
        ----------
        encoded_key: bytes
            The key or RLP-encoded key.

        Raises
        ------
        KeyError
            KeyError is raised if there is no value assotiated with provided key.
        """

        if self._root is None or self._root == Node.EMPTY_HASH:
            raise ValueError("Trie is empty")

        if self._secure:
            encoded_key = keccak_hash(encoded_key)

        path = NibblePath(encoded_key)
        action, info = self._delete(self._root, path)

        if action == MPT._DeleteAction.DELETED:
            # Trie is empty
            self._root = None
        elif action == MPT._DeleteAction.UPDATED:
            new_root = info
            self._root = new_root
        elif action == MPT._DeleteAction.USELESS_BRANCH:
            _, new_root = info
            self._root = new_root

    # PROOF FUNCTIONS
    def get_proof_of_inclusion(self, encoded_key: bytes) -> Proof:
        """
        This method returns a proof of inclusion for a key.

        Proof is a list of nodes that are necessary to reconstruct the trie.

        .. attention::
            This method does not RLP-encode the key.
            If you use encoded keys, you should encode it yourself.

        Parameters
        ----------
        encoded_key: bytes
            Key or RLP-encoded key.

        Returns
        -------
        proof : Proof
            The proof object for the proof of inclusion

        Raises
        ------
        ValueError
            ValueError is raised if the trie is empty.
        """
        if self._root is None or self._root == Node.EMPTY_HASH:
            raise ValueError("Cannot generate a proof for empty trie")

        if self._secure:
            encoded_key = keccak_hash(encoded_key)

        proof_list = self._get_proof_of_inclusion(
            self._root, NibblePath(encoded_key), []
        )
        return Proof(
            target_key=encoded_key,
            root_hash=self.root(),
            proof=tuple(proof_list),
            proof_type=b"MPT-POI",
        )

    def verify_proof_of_inclusion(self, proof: Proof) -> bool:
        """
        This method verifies a proof object containing a proof of inclusion.

        Parameters
        ----------
        proof : Proof
            The proof object to verify.

        Returns
        -------
        bool
            True if the proof is valid, False otherwise.

        Raises
        ------
        ValueError
            ValueError is raised if the trie is empty.
        TypeError
            TypeError is raised if the proof is not a proof of inclusion.
        """
        if proof.type != b"MPT-POI":
            raise TypeError("The given proof is not a proof of inclusion.")
        if self._root is None or self._root == Node.EMPTY_HASH:
            raise ValueError("Cannot verify a proof for empty trie.")

        # Compare the root hashes
        if self.root_hash() != keccak_hash(proof.proof[0]):
            return False

        # Recreate a partial trie from the proof and walk down from root to taget
        # node.
        proof_storage = {}
        for encoded_node in proof.proof:
            try:
                proof_storage[
                    Node.into_reference(Node.decode(encoded_node))
                ] = encoded_node
            except rlp.DecodingError:
                return False
        valid = self._verify_proof_of_inclusion(
            self._root, NibblePath(proof.target_key), proof_storage
        )
        # Check if the current trie hash is the sam as the proof root
        if valid and self.root_hash() == proof.trie_root:
            return True
        else:
            return False

    def get_proof_of_exclusion(self, encoded_key: bytes) -> Proof:
        """
        This method returns a proof of exclusion for a key.

        Proof is a list of nodes that are necessary to reconstruct the trie.
        This method does not RLP-encode the key. If you use encoded keys,
        you should encode it yourself.

        Parameters
        ----------
        encoded_key: bytes
            Key or RLP-encoded key.

        Returns
        -------
        proof : Proof
            The Proof object for the proof of exclusion.

        Raises
        ------
        ValueError
            ValueError is raised if the trie is empty.
        PoeError
            PoeError is raised if the key is in the trie.
        """
        if self._root is None or self._root == Node.EMPTY_HASH:
            raise ValueError("Cannot generate a proof for empty trie")

        # Check if the key is in the trie
        if self.contains(encoded_key):
            raise PoeError("Cannot generate a proof for a key that is in the trie")

        if self._secure:
            encoded_key = keccak_hash(encoded_key)

        path = NibblePath(encoded_key)
        node, proof_list = self._get_proof_of_exclusion(self._root, path, [])

        # Add a leaf node with the key to the proof
        proof_list.append(Leaf(path, b"null").encode())

        # If the node is a branch check if i thas a value
        # Can be None or b'' (b'' is used when trie is in secure mode)
        if isinstance(node, Branch):
            if node.data != None and node.data != b"":
                raise PoeError("This should never happen")

        # If the node is a leaf the key is in the trie
        if isinstance(node, Leaf):
            if node.path == path:
                raise PoeError("This should never happen")

        return Proof(
            target_key=encoded_key,
            root_hash=self.root_hash(),
            proof=tuple(proof_list),
            proof_type=b"MPT-POE",
        )

    def verify_proof_of_exclusion(self, proof: Proof) -> bool:
        """
        This method verifies a proof of exclusion for a key.

        This method does not RLP-encode the key. If you use encoded keys,
        you should encode it yourself.

        Parameters
        ----------
        encoded_key: bytes
            Key or RLP-encoded key.
        proof: list of bytes
            Proof of exclusion hash for a key.

        Returns
        -------
        bool
            True if the proof is valid, False otherwise.

        Raises
        ------
        ValueError
            ValueError is raised if the trie is empty.
        TypeError
            TypeError is raised if the proof is not a proof of exclusion.
        """
        if proof.type != b"MPT-POE":
            raise TypeError("The given proof is not a proof of exclusion.")

        if self._root is None or self._root == Node.EMPTY_HASH:
            raise ValueError("Cannot verify a proof for empty trie")

        # Compare the root hashes
        if self.root_hash() != keccak_hash(proof.proof[0]):
            return False

        if Node.decode(proof.proof[-1]).data != b"null":
            return False

        # Recreate a partial trie from the proof and walk down from root to taget
        # node.
        proof_storage = {}
        for encoded_node in proof.proof[:-1]:  # Exclude the null leaf.
            # print(type(encoded_node))
            proof_storage[Node.into_reference(Node.decode(encoded_node))] = encoded_node

        node, keys_left = self._verify_proof_of_exclusion(
            self.root(), NibblePath(proof.target_key), proof_storage
        )

        # There should be no keys left in the proof
        if len(keys_left.keys()) != 0:
            return False

        # Check if the result node is valid
        # If the node is a branch check if it has a value
        if isinstance(node, Branch):
            if node.data == None:
                return False

        # If the node is a leaf the key is in the trie

        if isinstance(node, Leaf):
            if node.path == NibblePath(proof.target_key):
                return False

        # Proof passed
        return True

    # CODEC
    def encode(self) -> bytes:
        """Encode the trie into rlp."""
        storage_list = [
            _prepare_reference_for_encoding(node) for node in self._storage.values()
        ]
        content = [self.root(), storage_list, self._secure]
        return rlp.encode(content)

    @staticmethod
    def decode(encoded_data: bytes) -> "MPT":
        """
        Decode the trie from rlp.

        Parameters
        ----------
        encoded_data : bytes
            The rlp encoded trie.

        Returns
        -------
        MMPT
            The decoded trie.
        """
        sedes = rlp.sedes.List(
            [
                rlp.sedes.binary,
                rlp.sedes.CountableList(rlp.sedes.binary),
                rlp.sedes.boolean,
            ]
        )
        root, storage_list, secure = rlp.decode(encoded_data, sedes=sedes)
        storage = {}
        for encoded_node in storage_list:
            # Nodes are stored as the RPL encoded version of the full node
            storage[keccak_hash(encoded_node)] = _prepare_reference_for_usage(
                encoded_node
            )

        return MPT(storage=storage, root=root, secure=secure)

    # SUPPORTING METHODS
    def _get_node(self, node_ref: bytes) -> Node:
        """This method gets a node from storage."""
        raw_node = None

        # Okey maybe it is alright like this because an RLP encoded node will
        # still get decoded
        # If the node_ref is already a node, just return it
        if (
            isinstance(node_ref, Extension)
            or isinstance(node_ref, Leaf)
            or isinstance(node_ref, Branch)
        ):
            return node_ref

        # Otherwise try to get it from storage or decode it from RLP
        if len(node_ref) == 32:
            raw_node = self._storage[node_ref]
            if isinstance(raw_node, Node):
                return raw_node
        else:
            raw_node = node_ref

        decoded_node = Node.decode(raw_node)
        if not (
            isinstance(decoded_node, Extension)
            or isinstance(decoded_node, Leaf)
            or isinstance(decoded_node, Branch)
        ):
            raise InvalidNodeError("Invalid node type {}".format(type(decoded_node)))
        return decoded_node

    def _get(self, node_ref: bytes, path: NibblePath) -> bytes:
        """
        Get support method.

        Returns a value associated with provided key.

        Parameters
        ----------
        node_ref: bytes
            Reference to a node.
        path: NibblePath
            Path to a value.

        Returns
        -------
        bytes
            Value associated with provided key.

        Raises
        ------
        KeyNotFoundError
            KeyError is raised if there is no value assotiated with provided key.
        ExtensionPathError, BranchPathError, LeafPathError, InvalidNodeError, ExtentionPathError
            Raised if the path is not valid.
        """
        node = self._get_node(node_ref)

        # If path is empty, our travel is over. Main `get` method
        # will check if this node has a value.
        if len(path) == 0:
            return node

        if type(node) is Leaf:
            # If we've found a leaf, it's either the leaf we're
            # looking for or wrong leaf.
            if node.path == path:
                return node
            else:
                raise KeyNotFoundError(
                    "The leaf key and search key do not match."
                    " Leaf key: {}, search key: {}".format(node.path, path)
                )

        elif type(node) is Extension:
            # If we've found an extension, we need to go deeper.
            if path.starts_with(node.path):
                rest_path = path.consume(len(node.path))
                return self._get(node.next_ref, rest_path)
            else:
                raise ExtensionPathError(
                    "Something wrong with the path in the extension."
                    " Extension path: {}, search path: {}".format(node.path, path)
                )

        elif type(node) is Branch:
            # If we've found a branch node, go to the appropriate branch.
            branch = node.branches[path.at(0)]
            if len(branch) > 0:
                return self._get(branch, path.consume(1))
            else:
                raise BranchPathError(
                    "Branch slot is empty."
                    " Branch: {}, search path: {}".format(node.branches, path)
                )

        raise InvalidNodeError("Invalid node type {}".format(type(node)))

    def _contains(self, node_ref: bytes, path: NibblePath) -> bool:
        """
        contains support method.

        Only returns the node as close to the end of the path as possible.
        The main contains method will check if this node has a value, and
        if this value is the one we're looking for.
        """
        if self._root is None or self._root == Node.EMPTY_HASH:
            return False
        
        node = self._get_node(node_ref)

        # If path is empty, our travel is over. Main `get` method
        # will check if this node has a value.
        if len(path) == 0:
            return node

        if type(node) is Leaf:
            # If we've found a leaf, it's either the leaf we're
            # looking for or wrong leaf.(we hope its the wrong leaf but
            # that is up to the main method).
            return node

        elif type(node) is Extension:
            # If we've found an extension, we need to go deeper.
            if path.starts_with(node.path):
                rest_path = path.consume(len(node.path))
                return self._contains(node.next_ref, rest_path)
            else:
                return node

        elif type(node) is Branch:
            # If we've found a branch node, go to the appropriate branch.
            branch = node.branches[path.at(0)]
            if len(branch) > 0:
                return self._contains(branch, path.consume(1))
            else:
                # This is the furthest node we can go.
                return node

        raise InvalidNodeError("Invalid node type {}".format(type(node)))

    def _get_proof_of_inclusion(
        self, node_ref: bytes, path: NibblePath, proof: dict
    ) -> dict:
        """
        Get proof of inclusion support method.

        Used to iterate over the trie and get a proof of inclusion for a node ref.

        Parameters
        ----------
        node_ref: bytes
            Reference to a node.
        path: NibblePath
            Path to a value.
        proof: dict
            Dictionary with nodes. (empty in the beginning)

        Returns
        -------
        dict
            Dictionary with nodes in the proof up untill now.

        Raises
        ------
        KeyError
            KeyError is raised if there is no node assotiated with provided key.
        LeafPathError, InvalidNodeError, ExtentionPathError, BranchPathError
            Raised if the path is not valid.
        """
        # Get the node from the reference
        node = self._get_node(node_ref)

        # print(type(node))

        if len(path) == 0:
            # If path is empty, we've found the node.
            # The node doesnt have to be a leaf.
            proof.append(node.encode())
            return proof

        if isinstance(node, Leaf):
            # If we've found a leaf, it's either the leaf we're
            # looking for or wrong leaf.
            if node.path == path:
                proof.append(node.encode())
                return proof
            else:
                raise LeafPathError(
                    "The leaf key and search key do not match"
                    " Leaf key: {}, search key: {}".format(node.path, path)
                )

        elif type(node) is Extension:
            # If we've found an extension, we need to go deeper.
            if path.starts_with(node.path):
                rest_path = path.consume(len(node.path))
                proof.append(node.encode())
                return self._get_proof_of_inclusion(node.next_ref, rest_path, proof)
            else:
                raise ExtensionPathError(
                    "Something wrong with the path in the extension"
                    " Extension path: {}, search path: {}".format(node.path, path)
                )

        elif type(node) is Branch:
            # If we've found a branch node, go to the appropriate branch.
            branch = node.branches[path.at(0)]
            if len(branch) > 0:
                proof.append(node.encode())
                return self._get_proof_of_inclusion(branch, path.consume(1), proof)
            else:
                raise BranchPathError(
                    "Branch slot is empty."
                    " Branch: {}, search path: {}".format(node.branches, path)
                )

        raise InvalidNodeError("Unknown node type {}".format(node))

    def _verify_proof_of_inclusion(
        self, node_ref: bytes, path: NibblePath, proof_storage: dict
    ) -> bool:
        """
        Verify proof of inclusion support method.

        Used to verify a proof of inclusion for a node ref.

        Parameters
        ----------
        node_ref: bytes
            Reference to a node.
        path: NibblePath
            Path to a value.
        proof: dict
            Dictionary with nodes. (empty in the beginning)

        Returns
        -------
        bool
            True if the proof is valid, False otherwise.

        Raises
        ------
        KeyError
            KeyError is raised if there is no node assotiated with provided key.
        ExtensionPathError, InvalidNodeError, LeafPathError, BranchPathError, InvalidNodeError
            Raised if the path is not valid.
        """
        # Get the right node from the proof storage
        if not (
            isinstance(node_ref, Leaf)
            or isinstance(node_ref, Extension)
            or isinstance(node_ref, Branch)
        ):
            # Otherwise try to get it from storage or decode it from RLP
            if len(node_ref) == 32:
                try:
                    raw_node = proof_storage[node_ref]
                except KeyError:
                    return False
            else:
                raw_node = node_ref
            node = Node.decode(raw_node)
        else:
            node = node_ref

        # If path is empty, our travel is over. Main `get` method
        # will check if this node has a value.
        if len(path) == 0:
            # check extension and node, leaf already handeled
            if isinstance(node, Extension):
                return False
            if isinstance(node, Branch):
                # Check if the branch has data
                if node.data != None:
                    return True
                else:
                    return False
            return True

        if type(node) is Leaf:
            # If we've found a leaf, it's either the leaf we're
            # looking for or wrong leaf.
            if node.path == path:
                return True
            else:
                return False

        elif type(node) is Extension:
            # If we've found an extension, we need to go deeper.
            if path.starts_with(node.path):
                rest_path = path.consume(len(node.path))
                return self._verify_proof_of_inclusion(
                    node.next_ref, rest_path, proof_storage
                )
            else:
                raise ExtensionPathError(
                    "Something wrong with the path in the extension."
                    " Extension path: {}, search path: {}".format(node.path, path)
                )

        elif type(node) is Branch:
            # If we've found a branch node, go to the appropriate branch.
            branch = node.branches[path.at(0)]
            if len(branch) > 0:
                return self._verify_proof_of_inclusion(
                    branch, path.consume(1), proof_storage
                )
            else:
                raise BranchPathError(
                    "Branch slot is empty."
                    " Branch: {}, search path: {}".format(node.branches, path)
                )

        raise InvalidNodeError("Unknown node type {}".format(node))

    def _get_proof_of_exclusion(
        self, node_ref: bytes, path: NibblePath, proof: dict
    ) -> dict:
        """
        Get proof of exclusion support method.

        Used to iterate over the trie and get a proof of exclusion for a node ref.

        Parameters
        ----------
        node_ref: bytes
            Reference to a node.
        path: NibblePath
            Path to a value.
        proof: dict
            Dictionary with nodes. (empty in the beginning)

        Returns
        -------
        dict
            Dictionary with nodes. (empty in the beginning)

        Raises
        ------
        KeyError
            KeyError is raised if there is no node assotiated with provided key.
        """
        node = self._get_node(node_ref)

        # print(type(node))

        # If path is empty, our travel is over. Main `get` method
        # will check if this node has a value.
        if len(path) == 0:
            proof.append(node.encode())
            return node, proof

        if type(node) is Leaf:
            # If we've found a leaf, it's either the leaf we're
            # looking for or wrong leaf.(we hope its the wrong leaf but
            # that is up to the main method).
            proof.append(node.encode())
            return node, proof

        elif type(node) is Extension:
            # If we've found an extension, we need to go deeper.
            if path.starts_with(node.path):
                rest_path = path.consume(len(node.path))
                proof.append(node.encode())
                return self._get_proof_of_exclusion(node.next_ref, rest_path, proof)
            else:
                return node, proof

        elif type(node) is Branch:
            # If we've found a branch node, go to the appropriate branch.
            branch = node.branches[path.at(0)]
            proof.append(node.encode())
            if len(branch) > 0:
                return self._get_proof_of_exclusion(branch, path.consume(1), proof)
            else:
                # This is the furthest node we can go.
                return node, proof

        raise InvalidNodeError("Invalid node type {}".format(type(node)))

    def _verify_proof_of_exclusion(
        self,
        node_ref: Union[bytes, Leaf, Branch, Extension],
        path: NibblePath,
        proof_storage: dict,
    ) -> Tuple[bool, dict]:
        """
        Verify proof of exclusion support method.

        Used to verify a proof of exclusion for a node ref.

        Parameters
        ----------
        node_ref: bytes, Leaf, Branch, Extension
            Reference to a node or the node itself.
        path: NibblePath
            Path to a value.
        proof: dict
            Dictionary with nodes. (empty in the beginning)

        Returns
        -------
        bool, node_ref
            True if this the last node in the proof, the next node ref otherwise.
        proof_storage: dict
            Dictionary with nodes.

        Raises
        ------
        PoeError
            PoeError when there is something wrong with the proof.
        InvalidNodeError
            InvalidNodeError when there is an invalid node in the proof.
        """
        # Get the right node from the proof storage
        if not (
            isinstance(node_ref, Leaf)
            or isinstance(node_ref, Extension)
            or isinstance(node_ref, Branch)
        ):
            # Otherwise try to get it from storage or decode it from RLP
            if len(node_ref) == 32:
                try:
                    raw_node = proof_storage[node_ref]
                except KeyError:
                    # TODO: Figure out in wich cases this shouldnt be True
                    # I still dont really trust this statement,
                    # but it is necessary for the tests to pass
                    # By checking the proof_dict at the end of the function
                    # there should be 1 node left in the dict, the null leaf
                    return True, proof_storage
            else:
                raw_node = node_ref
            node = Node.decode(raw_node)
        else:
            node = node_ref

        # Remove the used reference and node from the dictionary
        if proof_storage.pop(node_ref, None) == None:
            raise PoeError(
                "The proof storage returned a node with value None,"
                " this should not be possible."
            )

        # If path is empty, our travel is over. Main `get` method
        # will check if this node has a value.
        if len(path) == 0:
            return node, proof_storage

        if type(node) is Leaf:
            # If we've found a leaf, it's either the leaf we're
            # looking for or wrong leaf.(we hope its the wrong leaf but
            # that is up to the main method).
            return node, proof_storage

        elif type(node) is Extension:
            # If we've found an extension, we need to go deeper.
            if path.starts_with(node.path):
                rest_path = path.consume(len(node.path))
                return self._verify_proof_of_exclusion(
                    node.next_ref, rest_path, proof_storage
                )
            else:
                return node, proof_storage

        elif type(node) is Branch:
            # If we've found a branch node, go to the appropriate branch.
            branch = node.branches[path.at(0)]
            if len(branch) > 0:
                return self._verify_proof_of_exclusion(
                    branch, path.consume(1), proof_storage
                )
            else:
                # This is the furthest node we can go.
                return node, proof_storage

        raise InvalidNodeError("Invalid node type {}".format(type(node)))

    def _update(self, node_ref: bytes, path: NibblePath, value: bytes) -> bytes:
        """
        Update support method.

        Updates a value associated with provided key.

        Parameters
        ----------
        node_ref: bytes
            Reference to a node.
        path: NibblePath
            Path to a value.
        value: bytes
            Value to be stored.

        Returns
        -------
        bytes
            New root of the trie.

        Raises
        ------
        KeyError
            KeyError is raised if there is no value assotiated with provided key.
        """
        if not node_ref or node_ref == Node.EMPTY_HASH:
            return self._store_node(Leaf(path, value))

        node = self._get_node(node_ref)

        if type(node) == Leaf:
            # If we're updating the leaf there are 2 possible ways:
            # 1. Path is equals to the rest of the key. Then we should
            #    just update value of this leaf.
            # 2. Path differs. Then we should split this node into several nodes.

            if node.path == path:
                # Path is the same. Just change the value.
                node.data = value
                return self._store_node(node)

            # If we are here, we have to split the node.

            # Find the common part of the key and leaf's path.
            common_prefix = path.common_prefix(node.path)

            # Cut off the common part.
            path.consume(len(common_prefix))
            node.path.consume(len(common_prefix))

            # Create branch node to split paths.
            branch_reference = self._create_branch_node(
                path, value, node.path, node.data
            )

            # If common part isn't empty, we have to create an extension node before branch node.
            # Otherwise, we need just branch node.
            if len(common_prefix) != 0:
                return self._store_node(Extension(common_prefix, branch_reference))
            else:
                return branch_reference

        elif type(node) == Extension:
            # If we're updating an extenstion there are 2 possible ways:
            # 1. Key starts with the extension node's path.
            #    Then we just go ahead and all the work will be done there.
            # 2. Key doesn't start with extension node's path. Then we have to split extension node.

            if path.starts_with(node.path):
                # Just go ahead.
                new_reference = self._update(
                    node.next_ref, path.consume(len(node.path)), value
                )
                return self._store_node(Extension(node.path, new_reference))

            # Split extension node.

            # Find the common part of the key and extension's path.
            common_prefix = path.common_prefix(node.path)

            # Cut off the common part.
            path.consume(len(common_prefix))
            node.path.consume(len(common_prefix))

            # Create an empty branch node. It may have or have not the value depending on the length
            # of the rest of the key.
            branches = [b""] * 16
            branch_value = value if len(path) == 0 else b""

            # If needed, create leaf branch for the value we're inserting.
            self._create_branch_leaf(path, value, branches)
            # If needed, create an extension node for the rest of the extension's path.
            self._create_branch_extension(node.path, node.next_ref, branches)

            branch_reference = self._store_node(Branch(branches, branch_value))

            # If common part isn't empty, we have to create an extension node before branch node.
            # Otherwise, we need just branch node.
            if len(common_prefix) != 0:
                return self._store_node(Extension(common_prefix, branch_reference))
            else:
                return branch_reference

        elif type(node) == Branch:
            # For branch node things are easy.
            # 1. If key is empty, just store value in this node.
            # 2. If key isn't empty, just call `_update` with appropiate branch reference.

            if len(path) == 0:
                return self._store_node(Branch(node.branches, value))

            idx = path.at(0)
            new_reference = self._update(node.branches[idx], path.consume(1), value)

            node.branches[idx] = new_reference

            return self._store_node(node)

    def _create_branch_node(
        self, path_a: NibblePath, value_a: bytes, path_b: NibblePath, value_b: bytes
    ) -> bytes:
        """
        Create a branch node with up to two leaves and maybe value.

        Parameters
        ----------
        path_a: NibblePath
            Path to a leaf.
        value_a: bytes
            Value to be stored in a leaf.
        path_b: NibblePath
            Path to a leaf.
        value_b: bytes
            Value to be stored in a leaf.

        Returns
        -------
        bytes
            Reference to created node.
        """

        assert len(path_a) != 0 or len(path_b) != 0

        branches = [b""] * 16

        branch_value = b""
        if len(path_a) == 0:
            branch_value = value_a
        elif len(path_b) == 0:
            branch_value = value_b

        self._create_branch_leaf(path_a, value_a, branches)
        self._create_branch_leaf(path_b, value_b, branches)

        return self._store_node(Branch(branches, branch_value))

    def _create_branch_leaf(
        self, path: NibblePath, value: bytes, branches: List[bytes]
    ) -> ...:
        """
        If path isn't empty, creates leaf node and stores reference in appropriate branch.

        Parameters
        ----------
        path: NibblePath
            Path to a leaf.
        value: bytes
            Value to be stored in a leaf.
        branches: list of bytes
            List of references to nodes.

        Returns
        -------
        None
        """
        if len(path) > 0:
            idx = path.at(0)

            leaf_ref = self._store_node(Leaf(path.consume(1), value))
            branches[idx] = leaf_ref

    def _create_branch_extension(
        self, path: NibblePath, next_ref: bytes, branches: List[bytes]
    ) -> ...:
        """
        If needed, create an extension node and stores reference in appropriate branch.
        Otherwise just stores provided reference.

        Parameters
        ----------
        path: NibblePath
            Path to an extension node.
        next_ref: bytes
            Reference to a node.
        branches: list of bytes
            List of references to nodes.

        Returns
        -------
        None
        """
        assert (
            len(path) >= 1
        ), "Path for extension node should contain at least one nibble"

        if len(path) == 1:
            branches[path.at(0)] = next_ref
        else:
            idx = path.at(0)
            reference = self._store_node(Extension(path.consume(1), next_ref))
            branches[idx] = reference

    def _store_node(self, node: Node) -> bytes:
        """
        Build the reference from the node and if needed saves node in the storage.

        Parameters
        ----------
        node: Node
            Node to be stored.

        Returns
        -------
        bytes
            Reference to the node.
        """
        reference = Node.into_reference(node)
        if len(reference) == 32:
            self._storage[reference] = node.encode()
        return reference

    class _DeleteAction(Enum):
        """
        Enum that shows which action was performed on the previous step of the deletion.
        """

        # Node was deleted. Returned value should be (_DeleteAction, None).
        DELETED = (1,)
        # Node was updated. Returned value should be (_DeleteAction, new_node_reference)
        UPDATED = (2,)
        # Branch became useless. Returned value should be
        # (_DeleteAction, (path_to_new_reference, new_node_reference))
        USELESS_BRANCH = 3

    def _delete(
        self, node_ref: bytes, path: NibblePath
    ) -> Tuple[_DeleteAction, Optional[bytes]]:
        """
        Delete method helper.

        Parameters
        ----------
        node_ref: bytes
            Reference to the node.
        path: NibblePath
            Path to the node.

        Returns
        -------
        _DeleteAction
            Action that was performed on the previous step of the deletion.

        """

        node = self._get_node(node_ref)

        if type(node) == Leaf:
            # If it's leaf node, then it's either node we need or incorrect key provided.
            if path == node.path:
                return MPT._DeleteAction.DELETED, None
            else:
                raise LeafPathError("Incorrect or non existing path provided")

        elif type(node) == Extension:
            # Extension node can't be removed directly, it passes delete request to the next node.
            # After that several options are possible:
            # 1. Next node was deleted. Then this node should be deleted too.
            # 2. Next node was updated. Then we should update stored reference.
            # 3. Next node was useless branch. Then we have to update our node depending on the next node type.

            if not path.starts_with(node.path):
                raise ExtensionPathError("Incorrect path provided")

            action, info = self._delete(node.next_ref, path.consume(len(node.path)))

            if action == MPT._DeleteAction.DELETED:
                # Next node was deleted. This node should be deleted also.
                return action, None
            elif action == MPT._DeleteAction.UPDATED:
                # Next node was updated. Update this node too.
                child_ref = info
                new_ref = self._store_node(Extension(node.path, child_ref))
                return action, new_ref
            elif action == MPT._DeleteAction.USELESS_BRANCH:
                # Next node was useless branch.
                stored_path, stored_ref = info

                child = self._get_node(stored_ref)

                new_node = None
                if type(child) == Leaf:
                    # If next node is the leaf, our node is unnecessary.
                    # Concat our path with leaf path and return reference to the leaf.
                    path = NibblePath.combine(node.path, child.path)
                    new_node = Leaf(path, child.data)
                elif type(child) == Extension:
                    # If next node is the extension, merge this and next node into one.
                    path = NibblePath.combine(node.path, child.path)
                    new_node = Extension(path, child.next_ref)
                elif type(child) == Branch:
                    # If next node is the branch, concatenate paths and update stored reference.
                    path = NibblePath.combine(node.path, stored_path)
                    new_node = Extension(path, stored_ref)

                new_reference = self._store_node(new_node)
                return MPT._DeleteAction.UPDATED, new_reference

        elif type(node) == Branch:
            # For branch node things are quite complicated.
            # If rest of the key is empty and there is stored value, just clear value field.
            # Otherwise call _delete for the appropriate branch.
            # At this step we will have delete action and (possibly) index of the branch we're working with.
            #
            # Then, if next node was updated or was useless branch, just update reference.
            # If `_DeleteAction` is `DELETED` then either the next node or value of this node was removed.
            # We have to check if there is at least 2 branches or 1 branch and value still persist in this node.
            # If there are no branches and no value left, delete this node completely.
            # If there is a value but no branches, create leaf node with value and empty path
            # and return `USELESS_BRANCH` action.
            # If there is an only branch and no value, merge nibble of this branch and path of the underlying node
            # and return `USELESS_BRANCH` action.
            # Otherwise our branch isn't useless and was updated.

            action = None
            idx = None
            info = None

            assert (
                len(path) != 0 or len(node.data) != 0
            ), "Empty path or empty branch node in _delete"

            # Decide if we need to remove value of this node or go deeper.
            if len(path) == 0 and len(node.data) == 0:
                # This branch node has no value thus we can't delete it.
                raise BranchPathError("Branch node has no value so cannot be deleted")
            elif len(path) == 0 and len(node.data) != 0:
                node.data = b""
                action = MPT._DeleteAction.DELETED
            else:
                # Store idx of the branch we're working with.
                idx = path.at(0)

                if len(node.branches[idx]) == 0:
                    raise BranchPathError(
                        "Empty branch in _delete, could not delete the value."
                    )

                action, info = self._delete(node.branches[idx], path.consume(1))
                node.branches[idx] = b""

            if action == MPT._DeleteAction.DELETED:
                non_empty_count = sum(
                    map(lambda x: 1 if len(x) > 0 else 0, node.branches)
                )

                if non_empty_count == 0 and len(node.data) == 0:
                    # Branch node is empty, just delete it.
                    return MPT._DeleteAction.DELETED, None
                elif non_empty_count == 0 and len(node.data) != 0:
                    # No branches, just value.
                    path = NibblePath([])
                    reference = self._store_node(Leaf(path, node.data))

                    return MPT._DeleteAction.USELESS_BRANCH, (
                        path,
                        reference,
                    )
                elif non_empty_count == 1 and len(node.data) == 0:
                    # No value and one branch
                    return self._build_new_node_from_last_branch(node.branches)
                else:
                    # Branch has value and 1+ branches or no value and 2+ branches.
                    # It isn't useless, so action is `UPDATED`.
                    reference = self._store_node(node)
                    return MPT._DeleteAction.UPDATED, reference
            elif action == MPT._DeleteAction.UPDATED:
                # Just update reference.
                next_ref = info
                node.branches[idx] = next_ref
                reference = self._store_node(node)
                return MPT._DeleteAction.UPDATED, reference
            elif action == MPT._DeleteAction.USELESS_BRANCH:
                # Just update reference.
                _, next_ref = info
                node.branches[idx] = next_ref
                reference = self._store_node(node)
                return MPT._DeleteAction.UPDATED, reference

    def _build_new_node_from_last_branch(
        self, branches: List[bytes]
    ) -> Tuple[_DeleteAction, bytes]:
        """
        Combine nibble of the only branch left with underlying node and creates new node.

        Parameters
        ----------
        branches : list of bytes
            List of references to the branches.

        Returns
        -------
        tuple
            Tuple of `_DeleteAction` and reference to the new node.

        Raises
        ------
        KeyError
            If there is no branches left.

        """

        # Find the index of the only stored branch.
        idx = 0
        for i in range(len(branches)):
            if len(branches[i]) > 0:
                idx = i
                break

        # Path in leaf will contain one nibble (at this step).
        prefix_nibble = NibblePath([idx], offset=1)

        child = self._get_node(branches[idx])

        path = None
        node = None

        # Build new node.
        # If next node is leaf or extension, merge it.
        # If next node is branch, create an extension node with one nibble in path.
        if type(child) == Leaf:
            path = NibblePath.combine(prefix_nibble, child.path)
            node = Leaf(path, child.data)
        elif type(child) == Extension:
            path = NibblePath.combine(prefix_nibble, child.path)
            node = Extension(path, child.next_ref)
        elif type(child) == Branch:
            path = prefix_nibble
            node = Extension(path, branches[idx])

        reference = self._store_node(node)

        return MPT._DeleteAction.USELESS_BRANCH, (path, reference)
