from .merkletools import MerkleTools
from .proof import Proof
from typing import Union, List, Tuple


class MerkleTree(MerkleTools):
    def __init__(self, secure: bool = True, hash_type: str = "sha256") -> ...:
        """
        Initialize the MerkleTree object.

        Parameters
        ----------
        secure : bool
            If True, the MerkleTree will use a secure hash function before
            the values are stored in the tree. If False, the values will be
            stored in the tree as is. Default is True.
        hash_type : str
            The hash function to use. Default is 'sha256'.

        """
        if not isinstance(secure, bool):
            raise TypeError("`secure` must be a bool not {}".format(type(secure)))

        super().__init__(hash_type=hash_type, secure=secure)

    # TRIE FUNCTIONS
    def put(self, value: bytes) -> ...:
        """
        Add a leaf to the Merkle tree.

        .. important::
            The values are not RLP encoded before they are stored in the tree.
            If you want to store RLP encoded values they need to be encoded before they are
            passed to this function.

        Parameters
        ----------
        value : bytes, str or dict
            The leaf key to add to the tree. If a dict is passed, make sure the keys and
            values are also bytes, str or dict.

        Raises
        ------
        TypeError
            If a value is not a bytes, str or dict.
        """
        if not isinstance(value, bytes):
            raise TypeError("`value` must be a bytes not {}".format(type(value)))
        self.add_leaf(value)

    def put_list(self, values: Union[List, Tuple]) -> ...:
        """Add a list of leaves to the Merkle tree."""
        if not isinstance(values, (list, tuple)):
            raise TypeError(
                "`values` must be a list or tuple not {}".format(type(values))
            )
        for value in values:
            self.put(value)

    def get(self, index: int):
        """
        Get the leaf value at the given index.

        Parameters
        ----------
        index : int
            The index of the leaf to get.

        Returns
        -------
        bytes
            The leaf value at the given index.
        """
        if not isinstance(index, int):
            raise TypeError("`index` must be an int not {}".format(type(index)))
        return self.get_leaf(index)

    def get_count(self) -> int:
        """Get the number of leaves in the tree."""
        return self.get_leaf_count()

    def make_tree(self) -> ...:
        """Make the Merkle tree."""
        super().make_tree()

    def reset_tree(self) -> ...:
        """Reset the MerkleTree object to its initial state."""
        super().reset_tree()

    def get_merkle_root(self) -> bytes:
        """Get the root of the Merkle tree."""
        if not self.is_ready:
            self.make_tree()

        return super().get_merkle_root().encode()

    # PROOF FUNCTIONS
    def get_proof_of_inclusion(self, key: bytes) -> Proof:
        """
        Get the proof of inclusion for the leaf at the given index.

        .. important::
            The values are not RLP encoded before they are stored in the tree.
            If you want to store RLP encoded values they need to be encoded before they are
            passed to this function.

        Parameters
        ----------
        key : bytes
            The key of the leaf to get the proof of inclusion for.

        Returns
        -------
        Proof
            The proof of inclusion for the leaf at the given index.
        """
        if not isinstance(key, bytes):
            raise TypeError(
                "Invalid key, type should be bytes, not {}".format(type(key))
            )
        proof = super().get_proof_of_inclusion(key)
        byte_proof = []
        for p in proof:
            for k, v in p.items():
                byte_proof.append((k.encode(), v.encode()))

        return Proof(
            target_key=key,
            root_hash=self.get_merkle_root(),
            proof=tuple(byte_proof),
            proof_type=b"MT-POI",
        )

    def verify_proof_of_inclusion(self, proof: Proof) -> bool:
        """
        Verify the given proof.

        Parameters
        ----------
        proof : Proof
            The proof to verify.

        Returns
        -------
        bool
            True if the proof is valid, False otherwise.
        """
        if not isinstance(proof, Proof):
            raise TypeError("`proof` must be a Proof object not {}".format(type(proof)))
        str_proof = []
        for p in proof.proof:
            str_proof.append({p[0].decode(): p[1].decode()})

        merkle_root = bytes.fromhex(proof.trie_root.decode())
        target_hash = proof.target_key

        try:
            valid = super().verify_proof_of_inclusion(
                str_proof, merkle_root=merkle_root, target_hash=target_hash
            )
        except ValueError:
            return False

        # Compare the proof hash to the current root hash
        if valid:
            return self.get_merkle_root() == proof.trie_root
        else:
            return False

        raise Exception("This should never happen")

    def get_proof_of_exclusion(self):
        raise NotImplementedError(
            "get_proof_of_exclusion is not implemented for this merkle tree."
        )

    def verify_proof_of_exclusion():
        raise NotImplementedError(
            "verify_proof_of_exclusion is not implemented for this merkle tree."
        )
