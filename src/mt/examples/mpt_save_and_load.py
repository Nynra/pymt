import sys, os

# Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)
from trie.mpt import MPT


# Create the storage
storage = {}
trie = MPT(storage)

# Insert some data
trie.update(b"do", b"a deer")
trie.update(b"dog", b"a doge")
trie.update(b"doge", b"a Doge")
trie.update(b"doggo", b"a Doggo")
trie.update(b"horse", b"a horse")

trie_bytes = trie.encode()  # Encode the trie to bytes
trie_from_bytes = MPT.decode(trie_bytes)  # Create a new trie from the bytes

# Get a key from the original and the value from the new trie
print("Value in original: {}".format(trie.get(b"doge")))
print("Value from copy : {}".format(trie_from_bytes.get(b"doge")))
