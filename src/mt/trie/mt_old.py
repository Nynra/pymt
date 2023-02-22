from .merkletools import MerkleTools
from .proof import Proof
from typing import Union, List, Tuple
from typeguard import typechecked
import hashlib
import binascii


class MerkleTree:

    @typechecked
    def __init__(self, hash_type : str="sha256") -> ...:
        """
        Initialize the MerkleTools object
        
        Parameters
        ----------
        hash_type : str
            The hash function to use. Can be "sha256" or "sha3"
        """
        hash_type = hash_type.lower()
        if hash_type in ['sha256', 'md5', 'sha224', 'sha384', 'sha512',
                         'sha3_256', 'sha3_224', 'sha3_384', 'sha3_512']:
            self.hash_function = getattr(hashlib, hash_type)
        else:
            raise Exception('`hash_type` {} nor supported'.format(hash_type))
        self.reset_tree()

    # PROPERTIES
    @property
    def is_ready(self) -> bool:
        """Get the tree ready state."""
        return self._is_ready

    # SPECIAL METHODS
    def __len__(self) -> int:
        return self.get_leaf_count()

    def __str__(self) -> str:
        """Get the string representation of the Merkle tree."""
        if self._is_ready:
            return str(self.levels)
        else:
            return 'Tree not ready'

    def __hash__(self) -> int:
        """Get the hash of the Merkle tree."""
        return int(self.get_merkle_root(), 16)

    def __eq__(self, other : 'MerkleTools') -> bool:
        """Check if two Merkle trees are equal."""
        return self.__hash__() == other.__hash__()

    def __repr__(self) -> str:
        """Get the string representation of the Merkle tree."""
        return self.__str__()

    # LEAF METHODS
    def reset_tree(self) -> ...:
        """Reset the MerkleTools object to its initial state."""
        self.leaves = list()
        self.levels = None
        self._is_ready = False

    # TRIE FUNCTIONS
    @typechecked
    def put(self, value : bytes) -> ...:
        """
        Add a leaf to the Merkle tree.

        .. important:: 
            The values are not RLP encoded before they are stored in the tree.
            If you want to store RLP encoded values they need to be encoded before they are
            passed to this function.
        
        Parameters
        ----------
        value : bytes
            The leaf key to add to the tree.
        """
        self._add_leaf(value)

    @typechecked
    def put_list(self, values : List[bytes]) -> ...:
        """Add a list of leaves to the Merkle tree."""
        for value in values:
            self.put(value)

    @typechecked
    def get(self, index : int):
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
        return self._get_leaf(index)

    # PROOF FUNCTIONS
    @typechecked
    def get_proof_of_inclusion(self, key : bytes) -> Proof:
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

        Raises
        ------
        IndexError
            If the index is out of range.
        """
        if not key in self.leaves:
            raise IndexError('{} not in tree'.format(key))

        # Convert the proof from str to bytes    	
        proof = self._get_proof_of_inclusion(key)
        return Proof(target_key=key, root_hash=self.get_merkle_root().encode(),
                     proof=proof, type='MT-POI')

    @typechecked
    def verify_proof_of_inclusion(self, proof : Proof) -> bool:
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
        str_proof = []
        for p in proof.proof:
            for k, v in p:
                str_proof.append({k.decode(): v.decode()})

        return self._verify_proof_of_inclusion(str_proof, proof.target.decode(), proof.trie_root.decode())

    def get_proof_of_exclusion(self):
        raise NotImplementedError('get_proof_of_exclusion is not implemented for this merkle tree.')

    def verify_proof_of_exclusion():
        raise NotImplementedError('verify_proof_of_exclusion is not implemented for this merkle tree.')

    def make_tree(self) -> ...:
        """Make the Merkle tree."""
        self._is_ready = False
        if self.get_leaf_count() > 0:
            self.levels = [self.leaves, ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
        self._is_ready = True

    @typechecked
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
            raise ValueError('Tree is not ready. Call `make_tree` first.')
        return self._to_hex(self.levels[0][0])

    # SUPPORT METHODS
    def _to_hex(self, x : bytes) -> str:
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

    def _add_leaf(self, value : bytes) -> ...:
        """
        Add a leaf to the Merkle tree.

        Parameters
        ----------
        values : bytes
            The leaf values to add to the tree.
        """
        self.leaves.append(value)

    def _get_leaf(self, index : int) -> str:
        """Get the leaf value at the given index."""
        #return self._to_hex(self.leaves[index])
        return self.leaves[index]

    def get_leaf_count(self) -> int:
        """Get the number of leaves in the tree."""
        return len(self.leaves)

    # @typechecked
    # def _convert_dict_to_string(self, dict_value : dict) -> str:
    #     """
    #     Convert the dict to a string.
        
    #     Parameters
    #     ----------
    #     dict_value : dict
    #         The dict to convert.

    #     Raises
    #     ------
    #     TypeError
    #         If the dict value is not a dict, str or bytes.

    #     Returns
    #     -------
    #     str
    #     """
    #     new_value = ''
    #     for key, val in dict_value.items():
    #         # Check if the key and val are allowed datatypes
    #         if not (isinstance(key, bytes), isinstance(key, str), isinstance(val, bytes), isinstance(val, str), isinstance(val, dict)):
    #             raise TypeError('`key` and `val` must be a bytes, str, or dict not {}'.format(type(key)))
    #         if isinstance(val, dict):
    #             new_value += self._convert_dict_to_string(val)
    #         else: 
    #             new_value += str(key) + str(val)
    #     return new_value

    def _calculate_next_level(self) -> ...:
        """Calculate the next level of the tree."""
        solo_leave = None
        N = len(self.levels[0])  # number of leaves on the level
        if N % 2 == 1:  # if odd number of leaves on the level
            solo_leave = self.levels[0][-1]
            N -= 1

        new_level = []
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(self.hash_function(l+r).digest())
        if solo_leave is not None:
            new_level.append(solo_leave)
        self.levels = [new_level, ] + self.levels  # prepend new level
        
    def _get_proof_of_inclusion(self, key: bytes) -> list:
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
        index = self.leaves.index(key)
        if self.levels is None or not self.is_ready:
            raise ValueError('Tree is not ready. Call `make_tree()` first.')
        elif index > len(self.leaves)-1 or index < 0:
            raise ValueError('`index` {} is out of range'.format(index))
        else:
            proof = []
            for x in range(len(self.levels) - 1, 0, -1):
                level_len = len(self.levels[x])
                if (index == level_len - 1) and (level_len % 2 == 1):  # skip if this is an odd end node
                    index = int(index / 2.)
                    continue
                is_right_node = index % 2
                sibling_index = index - 1 if is_right_node else index + 1
                sibling_pos = "left" if is_right_node else "right"
                sibling_value = self._to_hex(self.levels[x][sibling_index])
                proof.append((sibling_pos, sibling_value))
                index = int(index / 2.)
            return proof

    def _verify_proof_of_inclusion(self, proof : list, target_hash : bytes, 
            merkle_root : str) -> bool:
        """
        Validate the proof for the leaf at the given index.
        
        Parameters
        ----------
        proof : list
            The proof for the leaf at the given index.
        target_hash : str
            The hash of the leaf to validate the proof for.
        merkle_root : str
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
                    sibling = bytearray.fromhex(p['left'])
                    proof_hash = self.hash_function(sibling + proof_hash).digest()
                except:
                    # the sibling is a right node
                    sibling = bytearray.fromhex(p['right'])
                    proof_hash = self.hash_function(proof_hash + sibling).digest()
            return proof_hash == merkle_root

