import hashlib
import binascii
import sys
from typing import List, Union, Tuple


if sys.version_info < (3, 6):
    try:
        import sha3
    except:
        from warnings import warn

        warn("sha3 is not working!")


class MerkleTools(object):
    def __init__(self, hash_type: str = "sha256", secure: bool = False) -> ...:
        """
        Initialize the MerkleTools object

        Parameters
        ----------
        hash_type : str
            The hash function to use. Can be "sha256" or "sha3"
        """
        hash_type = hash_type.lower()
        if hash_type in [
            "sha256",
            "md5",
            "sha224",
            "sha384",
            "sha512",
            "sha3_256",
            "sha3_224",
            "sha3_384",
            "sha3_512",
        ]:
            self.hash_function = getattr(hashlib, hash_type)
        else:
            raise Exception("`hash_type` {} nor supported".format(hash_type))

        self._secure = secure
        self.reset_tree()

    @property
    def secure(self) -> bool:
        """Check if the Merkle tree is secure."""
        return self._secure

    # SPECIAL METHODS
    def __len__(self) -> int:
        return self.get_leaf_count()

    def __str__(self) -> str:
        """Get the string representation of the Merkle tree."""
        if self.get_tree_ready_state():
            return str(self.levels)
        else:
            return "Tree not ready"

    def __hash__(self) -> int:
        """Get the hash of the Merkle tree."""
        return int(self.get_merkle_root(), 16)

    def __eq__(self, other: "MerkleTools") -> bool:
        """Check if two Merkle trees are equal."""
        return self.__hash__() == other.__hash__()

    def __repr__(self) -> str:
        """Get the string representation of the Merkle tree."""
        return self.__str__()

    # LEAF METHODS
    def _to_hex(self, x: bytes) -> ...:
        """
        Convert a byte array to hex string

        Parameters
        ----------
        x : bytearray
            The byte array to convert

        Returns
        -------
        str
            The hex string representation of the byte array
        """
        try:  # python3
            return x.hex()
        except:  # python2
            return binascii.hexlify(x)

    def reset_tree(self) -> ...:
        """Reset the MerkleTools object to its initial state."""
        self.leaves = list()
        self.levels = None
        self.is_ready = False

    def add_leaf(self, value: bytes) -> ...:
        """
        Add a leaf to the Merkle tree.

        Parameters
        ----------
        value : bytes
            The leaf value to add to the tree.
        """
        if self._secure:
            value = self.hash_function(value).hexdigest()
            value = bytearray.fromhex(value)
        else:
            value = bytearray(value)
        self.leaves.append(value)

    def get_leaf(self, index: int) -> str:
        """Get the leaf value at the given index."""
        return self._to_hex(self.leaves[index])

    def get_leaf_count(self) -> int:
        """Get the number of leaves in the tree."""
        return len(self.leaves)

    def get_tree_ready_state(self) -> bool:
        """Check if the tree is ready to generate proofs."""
        return self.is_ready

    def _calculate_next_level(self) -> ...:
        """Calculate the next level of the tree."""
        solo_leave = None
        N = len(self.levels[0])  # number of leaves on the level
        if N % 2 == 1:  # if odd number of leaves on the level
            solo_leave = self.levels[0][-1]
            N -= 1

        new_level = []
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(self.hash_function(l + r).digest())
        if solo_leave is not None:
            new_level.append(solo_leave)
        self.levels = [
            new_level,
        ] + self.levels  # prepend new level

    def make_tree(self) -> ...:
        """Make the Merkle tree."""
        self.is_ready = False
        if self.get_leaf_count() > 0:
            self.levels = [
                self.leaves,
            ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
        self.is_ready = True

    def get_merkle_root(self) -> str:
        """
        Get the Merkle root of the tree.

        Raises
        ------
        ValueError
            If the tree is not ready.

        Returns
        -------
        str
        """
        if not (self.is_ready and self.levels is not None):
            raise ValueError("Tree is not ready. Call `make_tree` first.")
        return self._to_hex(self.levels[0][0])

    def get_proof_of_inclusion(self, key: bytes) -> list:
        """
        Get the proof for the leaf at the given index.

        Parameters
        ----------
        key : bytes
            The key to get the proof for.

        Raises
        ------
        ValueError
            If the tree is not ready or the index is out of range.

        Returns
        -------
        list
            The proof for the leaf at the given index.

        Raises
        ------
        ValueError
            If the tree is not ready or the index is out of range.
        """
        if self._secure:
            key = self.hash_function(key).hexdigest()
            key = bytearray.fromhex(key)
        else:
            key = bytearray(key)

        index = self.leaves.index(key)
        if self.levels is None or not self.is_ready:
            raise ValueError("Tree is not ready. Call `make_tree()` first.")
        elif index > len(self.leaves) - 1 or index < 0:
            raise ValueError("`index` {} is out of range".format(index))
        else:
            proof = []
            for x in range(len(self.levels) - 1, 0, -1):
                level_len = len(self.levels[x])
                if (index == level_len - 1) and (
                    level_len % 2 == 1
                ):  # skip if this is an odd end node
                    index = int(index / 2.0)
                    continue
                is_right_node = index % 2
                sibling_index = index - 1 if is_right_node else index + 1
                sibling_pos = "left" if is_right_node else "right"
                sibling_value = self._to_hex(self.levels[x][sibling_index])
                proof.append({sibling_pos: sibling_value})
                index = int(index / 2.0)
            return proof

    def verify_proof_of_inclusion(
        self, proof: list, target_hash: bytes, merkle_root: bytes
    ) -> bool:
        """
        Validate the proof for the leaf at the given index.

        Parameters
        ----------
        proof : list
            The proof for the leaf at the given index.
        target_hash : bytes
            The hash of the leaf to validate the proof for.
        merkle_root : bytes
            The Merkle root of the tree.

        Returns
        -------
        bool
            True if the proof is valid, False otherwise.
        """
        if len(proof) == 0:
            return target_hash == merkle_root
        else:
            proof_hash = target_hash
            for p in proof:
                try:
                    # the sibling is a left node
                    sibling = bytearray.fromhex(p["left"])
                    proof_hash = self.hash_function(sibling + proof_hash).digest()
                except:
                    # the sibling is a right node
                    sibling = bytearray.fromhex(p["right"])
                    proof_hash = self.hash_function(proof_hash + sibling).digest()
            return proof_hash == merkle_root
