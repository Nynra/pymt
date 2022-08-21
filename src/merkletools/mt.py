from .merkletools import MerkleTools
from .proof import Proof


class MerkleTree(MerkleTools):

    def __init__(self, secure=True, hash_type='sha256'):
        """
        Initialize the MerkleTree object.
        
        Parameters
        ----------
        secure : bool
            If True, the MerkleTree will use a secure hash function before
            the values are stored in the tree. If False, the values will be
            stored in the tree as is. Default is True.
        """
        if not isinstance(secure, bool):
            raise TypeError('`secure` must be a bool not {}'.format(type(secure)))

        self._secure = secure
        super().__init__(hash_type=hash_type)

    # TRIE FUNCTIONS
    def put(self, value):
        """
        Add a leaf to the Merkle tree.

        IMPORTANT: The values are not RLP encoded before they are stored in the tree.
        If you want to store RLP encoded values they need to be encoded before they are
        passed to this function.
        
        Parameters
        ----------
        value : bytes
            The leaf key to add to the tree.
        do_hash : bool
            If True, the key will be hashed before being added.
            If False, the key will be added as is.
        """
        if not isinstance(value, bytes):
            raise TypeError('`value` must be a bytes not {}'.format(type(value)))
        self.add_leaf(value, do_hash=self._secure)

    def get(self, index):
        """
        Get the leaf value at the given index.
        
        Parameters
        ----------
        index : int
            The index of the leaf to get.
        
        Returns
        -------
        str
            The leaf value at the given index.

        """
        if not isinstance(index, int):
            raise TypeError('`index` must be an int not {}'.format(type(index)))
        return self.get_leaf(index)

    def get_count(self):
        """
        Get the number of leaves in the tree.
        
        Returns
        -------
        int
            The number of leaves in the tree.
        
        """
        return self.get_leaf_count()

    def make_tree(self):
        """Make the Merkle tree."""
        super().make_tree()

    def reset_tree(self):
        """Reset the MerkleTree object to its initial state."""
        return super().reset_tree()

    def get_merkle_root(self):
        """
        Get the root of the Merkle tree.
        
        Returns
        -------
        str
            The root of the Merkle tree.

        """
        if not self.is_ready:
            self.make_tree()

        return super().get_merkle_root()

    # PROOF FUNCTIONS
    def _get_key(self, value):
        """
        Get the key of the leaf with the given value.

        The key is the value as wich the original value was stored in the tree.
        If the tree is secure, the key will be the hashed value.

        IMPORTANT: The values are not RLP encoded before they are stored in the tree.
        If you want to store RLP encoded values they need to be encoded before they are
        passed to this function.
        
        Parameters
        ----------
        value : bytes
            The value of the leaf to get the key of.
        
        Returns
        -------
        bytes
            The key as wich the value is stored in the tree.
        
        """
        # check if the value is allowed
        if not isinstance(value, tuple) and not isinstance(value, list):
            if not(isinstance(value, bytes) or isinstance(value, str)):
                raise TypeError('`value` must be a list, tuple, bytes or str not {}'.format(
                                type(value)))

            value = [value]

        for v in value:
            if self._secure:
                if isinstance(v, str):
                    v = v.encode('utf-8')

                # Hash the value with the set hash function
                v = self.hash_function(v).hexdigest()
            v = bytearray.fromhex(v)
        return v
    
    def get_proof_of_inclusion(self, key, index, do_hash=False):
        """
        Get the proof of inclusion for the leaf at the given index.

        IMPORTANT: The values are not RLP encoded before they are stored in the tree.
        If you want to store RLP encoded values they need to be encoded before they are
        passed to this function.
        
        Parameters
        ----------
        key : bytes
            The leaf value as wich the original value was stored in the tree.
        index : int
            The index of the leaf in the tree.
        
        Returns
        -------
        Proof
            The proof of inclusion for the leaf at the given index.
        
        """
        if not isinstance(key, bytes):
            raise TypeError('`key` must be a bytes not {}'.format(type(key)))
        if not isinstance(index, int):
            raise TypeError('`index` must be an int not {}'.format(type(index)))
        if not isinstance(do_hash, bool):
            raise TypeError('`do_hash` must be a bool not {}'.format(type(do_hash)))

        # Check if the key should be hashed (only if the key wasnt already hashed)
        if do_hash:
            key = self.hash_function(key).digest()

        return Proof(target_key_hash=key, root_hash=self.get_merkle_root(),
                     proof_hash=super().get_proof_of_inclusion(index),
                     type='MT POI')

    def verify_proof_of_inclusion(self, proof):
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
            raise TypeError('`proof` must be a Proof not {}'.format(type(proof)))

        return super().verify_proof_of_inclusion(proof.proof)

    def get_proof_of_exclusion(self):
        raise NotImplementedError('get_proof_of_exclusion is not implemented for this merkle tree.')

    def verify_proof_of_exclusion():
        raise NotImplementedError('verify_proof_of_exclusion is not implemented for this merkle tree.')
