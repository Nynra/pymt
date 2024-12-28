import sys, os
from pymt import MerkleTree

# Create the trie and add some data to the trie
trie = MerkleTree()
trie.put(b"hello")
trie.put(b"world")
trie.put(b"here")
trie.put(b"i")
trie.put(b"am")

# Check if the tree is ready
trie.make_tree()
print(trie.is_ready)
key = trie.get(2)
print(type(key), key)
merkle_hash = trie.get_merkle_root()  # Get the root hash
proof = trie.get_proof_of_inclusion(
    b"world"
)  # Get the proof of inclusion for index 2 (here)
valid = trie.verify_proof_of_inclusion(proof)  # Validate the proof

# Print the result
print("Proof")
for k, v in proof.items():
    print(k, v)
