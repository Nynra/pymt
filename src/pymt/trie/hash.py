from Crypto.Hash import keccak
from typing import Tuple, List


def keccak_hash(data: bytes, hexdigest: bool = False) -> bytes:
    """
    Hash data with keccak256 algorithm.
    
    Parameters
    ----------
    data : bytes
        Data to hash.
    hexdigest : bool, optional
        If True, return hexdigest, otherwise return digest, by default False

    Returns
    -------
    bytes
        Hashed data.
    """
    hash = keccak.new(digest_bits=256)
    hash.update(data)
    if hexdigest:
        return hash.hexdigest().encode()
    else:
        return hash.digest()


def keccak_hash_list(data: List[bytes], hexdigest: bool = False) -> bytes:
    """
    Hash list of data with keccak256 algorithm.
    
    Parameters
    ----------
    data : List[bytes]
        List of data to hash.
    hexdigest : bool, optional
        If True, return hexdigest, otherwise return digest, by default False

    Returns
    -------
    bytes
        Hashed data.
    """
    keccak_hash = keccak.new(digest_bits=256)
    for item in data:
        keccak_hash.update(item)
    if hexdigest:
        return keccak_hash.hexdigest().encode()
    else:
        return keccak_hash.digest()


if __name__ == "__main__":
    data = b"Hello World"
    print(keccak_hash(data))
    print(keccak_hash(data, hexdigest=True))
    print(keccak_hash_list([data, data]))
    print(keccak_hash_list([data, data], hexdigest=True))
