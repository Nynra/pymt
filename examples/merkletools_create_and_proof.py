import sys, os
try:
    from merkletools.merkletools import MerkleTools
except ImportError:
    #Following lines are for assigning parent directory dynamically.
    dir_path = os.path.dirname(os.path.realpath(__file__))
    parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
    sys.path.insert(0, parent_dir_path)
    from src.merkletools.merkletools import MerkleTools

# Create the trie and add some data to the trie
trie = MerkleTools()
trie.add_leaf('hello', do_hash=True)
trie.add_leaf('world', do_hash=True)
trie.add_leaf('here', do_hash=True)
trie.add_leaf('i', do_hash=True)
trie.add_leaf('am', do_hash=True)

# Check if the tree is ready
trie.make_tree()
print(trie.is_ready)
key = trie.get_leaf(2)
merkle_hash = trie.get_merkle_root()  # Get the root hash
proof = trie.get_proof_of_inclusion(2)  # Get the proof of inclusion for index 2 (here)
valid = trie.validate_proof_of_inclusion(proof, key, merkle_hash)  # Validate the proof

# Print the result
print('Proof is valid: {}'.format(valid))
print('Proof: {}'.format(proof))
print('Merkle root: {}'.format(trie.get_merkle_root()))
