import sys, os
from pymt import MerkleTools

# Create the trie and add some data to the trie
trie = MerkleTools()
trie.add_leaf(b"hello")
trie.add_leaf(b"world")
trie.add_leaf(b"here")
trie.add_leaf(b"i")
trie.add_leaf(b"am")

# Check if the tree is ready
trie.make_tree()
print(trie.is_ready)
key = trie.get_leaf(2)
merkle_hash = trie.get_merkle_root()  # Get the root hash
proof = trie.get_proof_of_inclusion(
    b"world"
)  # Get the proof of inclusion for index 2 (here)
valid = trie.verify_proof_of_inclusion(proof, key, merkle_hash)  # Validate the proof

# Print the result
print("Proof is valid: {}".format(valid))
print("Proof: {}".format(proof))
print("Merkle root: {}".format(trie.get_merkle_root()))
