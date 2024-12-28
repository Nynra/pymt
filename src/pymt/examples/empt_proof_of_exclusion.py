import sys, os
from pymt import EMPT

# Create the storage
storage = {}
trie = EMPT(storage)

# Insert some data
trie.update(b"do", b"verb")
trie.update(b"dog", b"puppy")
trie.update(b"doge", b"coin")
trie.update(b"horse", b"poney")
trie.update(b"dogecoin", b"crypto")

proof = trie.get_proof_of_exclusion(b"wolf")

print("Proof dict: {}".format(proof.__dict__()))
print("\nProof valid: {}".format(trie.verify_proof_of_exclusion(proof)))
