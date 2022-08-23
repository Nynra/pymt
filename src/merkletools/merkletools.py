import hashlib
import binascii
import sys


if sys.version_info < (3, 6):
    try:
        import sha3
    except:
        from warnings import warn
        warn("sha3 is not working!")


class MerkleTools(object):
    def __init__(self, hash_type="sha256"):
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

    def _to_hex(self, x):
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

    def reset_tree(self):
        """Reset the MerkleTools object to its initial state."""
        self.leaves = list()
        self.levels = None
        self.is_ready = False

    def add_leaf(self, values, do_hash=False):
        """
        Add a leaf to the Merkle tree.

        Parameters
        ----------
        values : list, str or bytes
            The leaf values to add to the tree.
        do_hash : bool
            If True, the values will be hashed before being added.
            If False, the values will be added as is.
        """
        # check if single leaf
        if not isinstance(values, tuple) and not isinstance(values, list):
            if not(isinstance(values, bytes) or isinstance(values, str)):
                raise TypeError('`values` must be a list, tuple, bytes or str not {}'.format(
                                type(values)))

            values = [values]

        for v in values:
            if do_hash:
                if isinstance(v, str):
                    v = v.encode()
                v = self.hash_function(v).hexdigest()
            v = bytearray.fromhex(v)
            self.leaves.append(v)

    def get_leaf(self, index):
        """
        Get the leaf value at the given index.

        Parameters
        ----------
        index : int
            The index of the leaf to get.
        raw : bool
            If True, the leaf value will be returned as a byte array.

        Returns
        -------
        str
            The leaf value at the given index.

        """
        return self._to_hex(self.leaves[index])

    def get_leaf_count(self):
        """
        Get the number of leaves in the tree.

        Returns
        -------
        int
            The number of leaves in the tree.
        
        """
        return len(self.leaves)

    def get_tree_ready_state(self):
        """
        Get the state of the tree.

        Returns
        -------
        bool
            True if the tree is ready, False otherwise.
        
        """
        return self.is_ready

    def _calculate_next_level(self):
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

    def make_tree(self):
        """Make the Merkle tree."""
        self.is_ready = False
        if self.get_leaf_count() > 0:
            self.levels = [self.leaves, ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
        self.is_ready = True

    def get_merkle_root(self):
        """
        Get the Merkle root of the tree.

        Returns
        -------
        str
            The Merkle root of the tree.
        
        """
        if self.is_ready:
            if self.levels is not None:
                return self._to_hex(self.levels[0][0])
            else:
                return None
        else:
            return None

    def get_proof_of_inclusion(self, index):
        """
        Get the proof for the leaf at the given index.

        Parameters
        ----------
        index : int
            The index of the leaf to get the proof for.

        Returns
        -------
        list
            The proof for the leaf at the given index.

        """
        if self.levels is None:
            return None
        elif not self.is_ready or index > len(self.leaves)-1 or index < 0:
            return None
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
                proof.append({sibling_pos: sibling_value})
                index = int(index / 2.)
            return proof

    def verify_proof_of_inclusion(self, proof, target_hash, merkle_root):
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
        merkle_root = bytearray.fromhex(merkle_root)
        target_hash = bytearray.fromhex(target_hash)
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
