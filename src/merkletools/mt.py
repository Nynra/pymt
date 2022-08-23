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
        hash_type : str
            The hash function to use. Default is 'sha256'.
        
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

        Returns
        -------
        None

        """
        if not isinstance(value, bytes):
            raise TypeError('`value` must be a bytes not {}'.format(type(value)))
        self.add_leaf(value, do_hash=self._secure)

    def convert_value(self, value):
        """
        Convert the value to what it will be saved in the tree.
        
        Parameters
        ----------
        value : bytes
            The value to convert.
        
        Returns
        -------
        bytes
            The converted bytes.
        """
        if not isinstance(value, bytes):
            raise TypeError('`value` must be a bytes not {}'.format(type(value)))

        return self.hash_function(value).hexdigest().encode() if self._secure else value

    def get(self, index):
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
            raise TypeError('`index` must be an int not {}'.format(type(index)))
        return self.get_leaf(index).encode()

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
    def get_proof_of_inclusion(self, index):
        """
        Get the proof of inclusion for the leaf at the given index.

        IMPORTANT: The values are not RLP encoded before they are stored in the tree.
        If you want to store RLP encoded values they need to be encoded before they are
        passed to this function.
        
        Parameters
        ----------
        index : int
            The index of the leaf in the tree.
        
        Returns
        -------
        Proof
            The proof of inclusion for the leaf at the given index.
        
        """
        if not isinstance(index, int):
            raise TypeError('`index` must be an int not {}'.format(type(index)))

        # Check if the key should be hashed (only if the key wasnt already hashed)
        key = self.get_leaf(index)

        # Convert the proof from str to bytes    	
        proof = super().get_proof_of_inclusion(index)
        byte_proof = []
        for p in proof:
            for k, v in p.items():
                byte_proof.append({k.encode(): v.encode()})

        return Proof(target_key_hash=key.encode(), root_hash=self.get_merkle_root().encode(),
                     proof_hash=byte_proof, type='MT POI')

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

        # Convert the proof from bytes to string
        str_proof = []
        for p in proof.proof:
            for k, v in p.items():
                str_proof.append({k.decode(): v.decode()})

        return super().verify_proof_of_inclusion(str_proof, proof.target.decode(), proof.trie_root.decode())

    def get_proof_of_exclusion(self):
        raise NotImplementedError('get_proof_of_exclusion is not implemented for this merkle tree.')

    def verify_proof_of_exclusion():
        raise NotImplementedError('verify_proof_of_exclusion is not implemented for this merkle tree.')
