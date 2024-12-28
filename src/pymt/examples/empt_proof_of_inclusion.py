import sys, os
from pymt import EMPT


# Create the storage
storage = {}
trie = EMPT(storage)

# Insert some data
trie.update(b"do", b"g")
trie.update(b"dog", b"cat")
trie.update(b"doge", b"mice")
trie.update(b"horse", b"bird")
trie.update(b"dogecoin", b"eliphant")
trie.update(b"bitcoin", b"panda")
trie.update(b"ethereum", b"penguin")

proof = trie.get_proof_of_inclusion(b"dog")

print("Proof dict:")
print(dict(proof))

print("\nProof valid: {}".format(trie.verify_proof_of_inclusion(proof)))
