from datetime import datetime
import pickle
from typeguard import typechecked
from typing import List, Union
from .hash import keccak_hash
import rlp
import json


class Proof:
    """Class to hold the information for different kind of proofs."""
    accepted_types = [b"MPT-POI", b"MPT-POE", b"MT-POI"]

    @typechecked
    def __init__(
        self,
        target_key: bytes,
        root_hash: bytes,
        proof: Union[list, bytes],
        type: bytes,
    ) -> ...:
        """
        Initialize the proof.

        Parameters
        ----------
        target_key : bytes
            The target key.
        root_hash : bytes
            Hash of the root of the trie.
        proof_hash : bytes
            Hash of the proof.
        type : str
            Type of the proof (MPT-POI or MPT-POE).

        Raises
        ------
        TypeError
            If the type is not MMPT-POI or MMPT-POE type.
        """
        self._timestamp = str(datetime.now())
        self._target_key = target_key
        self._root_hash = root_hash
        self._proof = proof
        if type not in self.accepted_types:
            raise TypeError("Invalid proof type")
        self._type = type

    # DUNDER METHODS
    def __dict__(self) -> dict:
        """Return the proof as a dictionary."""
        return {
            "type": self._type.decode(),
            "timestamp": self._timestamp,
            "target_key": self._target_key.decode(),
            "root_hash": self._root_hash.decode(),
            "proof": str(self._proof),
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
            This library only generates MMPT proofs, but the Proof class can be used
            to store any kind of proof (for example a merkle proof).
        """
        return self._proof

    @property
    def type(self) -> bytes:
        """
        Get the type of the proof.

        For this library the type can be either 'MMPT-POI' or 'MMPT-POE'.
        """
        return self._type

    # CODEC
    def encode_json(self) -> dict:
        """Convert the proof to a json object."""
        return json.dumps(self.__dict__())

    @staticmethod
    def decode_json(json: dict) -> "Proof":
        """Create a proof from a json object."""
        encoded_proof_list = json["proof"][1:-1]
        proof_list = []
        for encoded_proof in encoded_proof_list.split(","):
            proof_list.append(encoded_proof.encode())
        proof = Proof(
            json["target_key"], json["root_hash"], json["proof"], json["type"]
        )
        proof._timestamp = json["timestamp"]
        return proof

    def encode_rlp(self) -> bytes:
        """
        Encode the proof object into rlp.

        Returns
        -------
        bytes
            The proof encoded in rlp.
        """
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
        sedes = rlp.sedes.List(
            [
                rlp.sedes.binary,
                rlp.sedes.binary,
                rlp.sedes.binary,
                rlp.sedes.binary,
                rlp.sedes.binary,
            ]
        )
        decoded = rlp.decode(rlp_bytes, sedes=sedes)
        proof = Proof(decoded[2], decoded[3], decoded[4])
        proof._timestamp = decoded[1]
        proof._type = decoded[0]
        return proof
