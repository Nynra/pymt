from datetime import datetime
import pickle
from typing import List, Union
from .utils.hash import keccak_hash
import rlp
import json


class Proof:
    """Class to hold the information for different kind of proofs."""

    accepted_types = [b"MPT-POI", b"MPT-POE", b"MT-POI"]

    def __init__(
        self,
        target_key: bytes,
        root_hash: bytes,
        proof: Union[list, bytes],
        proof_type: tuple,
    ) -> ...:
        """
        Initialize the proof.

        Parameters
        ----------
        target_key : bytes
            The target key.
        root_hash : bytes
            Hash of the root of the trie.
        proof : tuple
            The proof.
        proof_type : bytes
            Type of the proof.
        """
        self._timestamp = str(datetime.now()).encode()
        if not isinstance(target_key, bytes):
            raise TypeError(
                "Invalid target key, type should be bytes, not {}".format(
                    type(target_key)
                )
            )
        else:
            self._target_key = target_key

        if not isinstance(root_hash, bytes):
            raise TypeError(
                "Invalid root hash, type should be bytes, not {}".format(
                    type(root_hash)
                )
            )
        else:
            self._root_hash = root_hash

        if not isinstance(proof, tuple):
            raise TypeError(
                "Invalid proof, type should be tuple, not {}".format(type(proof))
            )
        self._proof = proof

        if not isinstance(proof_type, bytes):
            raise TypeError(
                "Invalid proof type, type should be bytes, not {}".format(
                    type(proof_type)
                )
            )
        if proof_type not in self.accepted_types:
            raise TypeError("Invalid proof type: {}".format(proof_type))
        else:
            self._type = proof_type

    # DUNDER METHODS
    def __dict__(self) -> dict:
        """Return the proof as a dictionary."""
        return {
            "proof_type": self._type,
            "timestamp": self._timestamp,
            "target_key": self._target_key,
            "root_hash": self.trie_root,
            "proof": self._proof,
        }

    def __repr__(self) -> str:
        """Return the proof as a string."""
        return "Proof(type={}, timestamp={}, target_key={}, root_hash={}, proof={})".format(
            self._type, self._timestamp, self._target_key, self._root_hash, self._proof
        )

    def __hash__(self) -> int:
        """Return the hash of the proof."""
        return int(keccak_hash(str(self.__dict__()).encode(), hexdigest=True), 16)

    def __eq__(self, other: "Proof") -> bool:
        """Compare two proofs."""
        if not isinstance(other, Proof):
            return False

        return self.__hash__() == other.__hash__()

    def __iter__(self) -> "Proof":
        """Return the proof as an iterator."""
        self._data = list(self.items())
        self._offset = 0
        return self

    def __next__(self) -> tuple:
        """Return the next item of the proof."""
        if self._offset >= len(self._data):
            raise StopIteration
        else:
            self._offset += 1
            return self._data[self._offset - 1]

    # ATTRIBUTES
    @property
    def timestamp(self) -> str:
        """Get the timestamp of the proof."""
        return self._timestamp

    @property
    def target_key(self) -> bytes:
        """Get the hash of the target key."""
        return self._target_key

    @property
    def trie_root(self) -> bytes:
        """Get the hash of the root of the trie."""
        return self._root_hash

    @property
    def proof(self) -> list:
        """
        Get the hash of the proof.

        The proof list contains the encoded nodes of the proof.

        .. note::
            The content of the proof list depends on the type of the proof.
            This library only generates MPT proofs, but the Proof class can be used
            to store any kind of proof (for example a merkle proof).
        """
        return self._proof

    @property
    def type(self) -> bytes:
        """
        Get the type of the proof.

        For this library the type can be either 'POI' or 'POE'.
        """
        return self._type

    def items(self):
        return self.__dict__().items()

    # CODEC
    def encode_json(self) -> dict:
        """Convert the proof to a json object."""
        content = self.__dict__().copy()
        for key, value in content.items():
            if key.lower() == "proof":
                if "MT" in self._type.decode():
                    content[key] = [i.decode() for i in value]
                elif "MPT" in self._type.decode():
                    raise NotImplementedError(
                        "Encoding MPT proofs is not supported yet"
                    )
            else:
                content[key] = value.decode()
        return json.dumps(content)

    @staticmethod
    def decode_json(json_proof: str) -> "Proof":
        """Create a proof from a json object."""
        if not isinstance(json_proof, str):
            raise TypeError(
                "Invalid json proof, type should be str, not {}".format(
                    type(json_proof)
                )
            )
        json_proof = json.loads(json_proof)
        encoded_proof_list = json_proof["proof"]

        if "MPT" in json_proof["proof_type"]:
            # Build the mmpt proof from string
            raise NotImplementedError("MPT proofs are not supported yet")

        elif "MT" in json_proof["proof_type"]:
            # Build the mpt proof from string
            proof = []
            for i in encoded_proof_list:
                proof.append(i.encode())

        else:
            raise TypeError("Invalid proof type {}".format(json_proof["proof_type"]))

        proof = Proof(
            target_key=json_proof["target_key"].encode(),
            root_hash=json_proof["root_hash"].encode(),
            proof=tuple(proof),
            proof_type=json_proof["proof_type"].encode(),
        )
        proof._timestamp = json_proof["timestamp"].encode()
        return proof

    def encode_rlp(self) -> bytes:
        """
        Encode the proof object into rlp.

        Returns
        -------
        bytes
            The proof encoded in rlp.
        """
        if "MT" not in self._type.decode():
            # For now only MT proofs are supported as this is always
            # one list of bytes entries. MPT proofs contain nested lists
            raise NotImplementedError("RLP encoding MPT proofs is not supported yet")

        return rlp.encode(
            [
                self._type,
                self._timestamp,
                self._target_key,
                self._root_hash,
                self._proof,
            ]
        )

    @staticmethod
    def decode_rlp(rlp_bytes: bytes) -> "Proof":
        """
        Decode the proof object from rlp.

        Parameters
        ----------
        rlp_bytes : bytes
            The rlp encoded proof.

        Returns
        -------
        Proof
            The decoded proof.
        """
        if not isinstance(rlp_bytes, bytes):
            raise TypeError(
                "Invalid rlp bytes, type should be bytes, not {}".format(
                    type(rlp_bytes)
                )
            )

        sedes = rlp.sedes.List(
            [
                rlp.sedes.binary,
                rlp.sedes.binary,
                rlp.sedes.binary,
                rlp.sedes.binary,
                rlp.sedes.CountableList(rlp.sedes.binary),
            ]
        )
        decoded = rlp.decode(rlp_bytes, sedes=sedes)
        proof = Proof(
            target_key=decoded[2],
            root_hash=decoded[3],
            proof=decoded[4],
            proof_type=decoded[0],
        )
        proof._timestamp = decoded[1]
        return proof
