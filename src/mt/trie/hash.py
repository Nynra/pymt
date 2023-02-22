from Crypto.Hash import keccak
from typing import Tuple, List
from typeguard import typechecked


@typechecked
def keccak_hash(data : bytes, hexdigest : bool=False) -> bytes:
    """Hash data with keccak256 algorithm."""
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(data)
    if hexdigest:
        return keccak_hash.hexdigest().encode()
    else:
        return keccak_hash.digest()


@typechecked
def keccak_hash_list(data :List[bytes], hexdigest : bool=False) -> bytes:
    """Hash list of data with keccak256 algorithm."""
    keccak_hash = keccak.new(digest_bits=256)
    for item in data:
        keccak_hash.update(item)
    if hexdigest:
        return keccak_hash.hexdigest().encode()
    else:
        return keccak_hash.digest()