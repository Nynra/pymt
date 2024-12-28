"""This module contains all the abstract base classes for the package"""

from abc import ABC, abstractmethod
from typing import Any


class _BaseAbstractKeyPair(ABC):
    """An base class to represent a key pair"""

    # DUNDER METHODS
    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def __hash__(self) -> int:
        """Hash the public key."""
        pass

    @abstractmethod
    def __eq__(self, other: Any) -> bool:
        """Compare the hashes of the public keys."""
        pass

    # PROPERTIES
    @property
    @abstractmethod
    def public_key_string(self) -> str:
        pass

    @property
    @abstractmethod
    def public_key(self) -> bytes:
        pass

    @property
    @abstractmethod
    def nickname(self) -> str:
        pass

    @nickname.setter
    @abstractmethod
    def nickname(self, name: str) -> ...:
        pass

    # METHODS
    @abstractmethod
    def generate_keypair(self) -> ...:
        pass

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def signature_valid(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        pass

    @abstractmethod
    def encrypt(self, data: bytes, receiver_public_key: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes, sender_public_key: bytes) -> bytes:
        pass

    # CODEC
    @classmethod
    @abstractmethod
    def from_key_file(cls, file: str) -> "_BaseAbstractKeyPair":
        """Load the key from a file.

        The file should be a json document with the following format:
        {
            "nickname": <str>,
            "public_key": <str>, # In PEM format
            "private_key": <str> # In PEM format
        }
        """
        pass

    @abstractmethod
    def to_key_file(self, file: str) -> ...:
        """Save the key to a file.

        The file should be a json document with the following format:
        {
            "nickname": <str>,
            "public_key": <str>, # In PEM format
            "private_key": <str> # In PEM format
        }
        """
        pass

    @classmethod
    @abstractmethod
    def from_key_string(cls, key: str) -> "_BaseAbstractKeyPair":
        """Load the key from a string.

        The string should be a json string with the following content:
        {
            "nickname": <str>,
            "public_key": <str>, # In PEM format
            "private_key": <str> # In PEM format
        }
        """
        pass

    @abstractmethod
    def to_key_string(self) -> str:
        """Save the key to a string.

        The string should be a json string with the following content:
        {
            "nickname": <str>,
            "public_key": <str>, # In PEM format
            "private_key": <str> # In PEM format
        }
        """
        pass


class AbstractKeyPair(_BaseAbstractKeyPair):
    """An abstract class to represent a key pair.

    This class defines the common methods all key pair that can sign
    and encrypt data should have.
    """


class AbstractAuthKeyPair(_BaseAbstractKeyPair):
    """An abstract class to represent a key pair that can sign data.

    This class defines the common methods all key pair that can sign
    data should have. The implementation should only sign data and verify
    signatures. When the user tries to encrypt or decrypt data, the
    implementation should raise a NotImplementedError.
    """


class AbstractEncKeyPair(_BaseAbstractKeyPair):
    """An abstract class to represent a key pair that can encrypt data.

    This class defines the common methods all key pair that can encrypt
    data should have. The implementation should only encrypt data and decrypt
    data. When the user tries to sign data or verify signatures, the
    implementation should raise a NotImplementedError.
    """


class _BaseAbstractKeyRing(ABC):
    """An abstract class used for class inheritance

    This class should not be used directly. It is used to define the
    common methods and properties for the :class:`AbstractCombiKeyRing`,
    :class:`AbstractAuthKeyRing`, and :class:`AbstractEncKeyRing` classes.
    """

    # The storage can be changed to any class that inherits from MutableMapping
    _storage = {}

    # DUNDER METHODS
    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def __hash__(self) -> int:
        """Hash the public key."""
        pass

    @abstractmethod
    def __eq__(self, other: Any) -> bool:
        """Compare the hashes of the public keys."""
        pass

    # METHODS
    @abstractmethod
    def generate_keypair(self) -> ...:
        pass

    @abstractmethod
    def sign(self, key_name, data: bytes) -> bytes:
        pass

    @abstractmethod
    def signature_valid(self, data: bytes, signature: bytes) -> bool:
        pass

    @abstractmethod
    def encrypt(self, data: bytes, receiver_public_key: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes, sender_public_key: bytes) -> bytes:
        pass

    # CODEC
    @classmethod
    @abstractmethod
    def from_key_file(cls, file: str) -> "_BaseAbstractKeyRing":
        """Load the key from a file.

        The file should be a json document with the following format:
        {
            "keyring_name": <str>,
            "keypairs": [
                {
                    "nickname": <str>,
                    "public_key": <str>, # In PEM format
                    "private_key": <str> # In PEM format
                },
                ... # More keypairs
            ]
        }
        """
        pass

    @abstractmethod
    def to_key_file(self, file: str) -> ...:
        """Save the key to a file.

        The file should be a json document with the following format:
        {
            "keyring_name": <str>,
            "keypairs": [
                {
                    "nickname": <str>,
                    "public_key": <str>, # In PEM format
                    "private_key": <str> # In PEM format
                },
                ...
            ]
        }
        """
        pass

    @classmethod
    @abstractmethod
    def from_key_string(self, key: str) -> "_BaseAbstractKeyRing":
        """Load the key from a string.

        The string should be a json string with the following content:
        {
            "keyring_name": <str>,
            "keypairs": [
                {
                    "nickname": <str>,
                    "public_key": <str>, # In PEM format
                    "private_key": <str> # In PEM format
                },
                ...
            ]
        }
        """
        pass

    @abstractmethod
    def to_key_string(self) -> str:
        """Save the key to a string.

        The string should be a json string with the following content:
        {
            "keyring_name": <str>,
            "keypairs": [
                {
                    "nickname": <str>,
                    "public_key": <str>, # In PEM format
                    "private_key": <str> # In PEM format
                },
                ...
            ]
        }
        """
        pass


class AbstractKeyRing(_BaseAbstractKeyRing):
    """An abstract class to represent a keyring that can sign and encrypt data.

    This class defines the common methods all keyring classes that can sign
    and encrypt data should have.
    """


class AbstractAuthKeyRing(_BaseAbstractKeyRing):
    """An abstract class to represent a keyring that can sign data.

    This class defines the common methods all keyring classes that can sign
    data should have. The implementation should only sign data and verify
    signatures. When the user tries to encrypt or decrypt data, the
    implementation should raise a NotImplementedError.
    """


class AbstractEncKeyRing(_BaseAbstractKeyRing):
    """An abstract class to represent a keyring that can encrypt data.

    This class defines the common methods all keyring classes that can encrypt
    data should have. The implementation should only encrypt data and decrypt
    data. When the user tries to sign data or verify signatures, the
    implementation should raise a NotImplementedError.
    """
