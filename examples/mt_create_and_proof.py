import sys, os
try:
    from merkletools.mt import MerkleTree
except ImportError:
    #Following lines are for assigning parent directory dynamically.
    dir_path = os.path.dirname(os.path.realpath(__file__))
    parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
    sys.path.insert(0, parent_dir_path)
    from src.merkletools.mt import MerkleTree

# Create the trie and add some data to the trie
trie = MerkleTree()
trie.put(b'hello')
trie.put(b'world')
trie.put(b'here')
trie.put(b'i')
trie.put(b'am')

# Check if the tree is ready
trie.make_tree()
print(trie.is_ready)
key = trie.get(2)
print(type(key), key)
merkle_hash = trie.get_merkle_root()  # Get the root hash
proof = trie.get_proof_of_inclusion(2)  # Get the proof of inclusion for index 2 (here)
valid = trie.verify_proof_of_inclusion(proof)  # Validate the proof

# Print the result
print('Proof')
for k, v in proof.items():
    print(k, v)