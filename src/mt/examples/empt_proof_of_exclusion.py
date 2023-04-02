import sys, os
#Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)
from trie.empt import EMPT


# Create the storage
storage = {}
trie = EMPT(storage)

# Insert some data
trie.update(b'do', b'verb')
trie.update(b'dog', b'puppy')
trie.update(b'doge', b'coin')
trie.update(b'horse', b'poney')
trie.update(b'dogecoin', b'crypto')

proof = trie.get_proof_of_exclusion(b'wolf')

print('Proof dict: {}'.format(proof.__dict__()))
print('\nProof valid: {}'.format(trie.verify_proof_of_exclusion(proof)))
