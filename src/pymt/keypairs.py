from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from typing import Any
import json
from .base import AbstractKeyPair, AbstractAuthKeyPair, AbstractEncKeyPair
from .utils.utils import Utils
from uuid import uuid4
import os


class RsaKeyPair(AbstractKeyPair):
    """A class to represent an RSA keypair.

    To make handeling and encoding easier all keys are stored as strings.
    """

    def __init__(self, nickname: str = None, _generate_keys: bool = True) -> ...:
        """Create a new RSA keypair.

        Parameters
        ----------
        nickname : str, optional
            The nickname of the keypair. If none a UUID will be generated. Default is None.
        _generate_keys : bool, optional
            If True the keypair will be generated. Default is True.

        .. attention::

            Be careful when setting `_generate_keys` to False. The keypair will not be
            generated and the keypair will be None. This will cause unforseen errors
            if the keypair is used without loading keys first.

        """
        if not isinstance(nickname, str) and nickname is not None:
            raise ValueError(
                "Nickname must be a string or None, not {}".format(type(nickname))
            )

        if nickname is None:
            self._nickname = uuid4().hex
        else:
            self._nickname = nickname

        if _generate_keys:
            self.generate_keypair()
        else:
            self._key_pair = None

    # DUNDER MEHTHODS
    def __str__(self) -> str:
        return f"RsaKeyPair(nickname={self._nickname})"

    def __repr__(self) -> str:
        return f"RsaKeyPair(nickname={self._nickname}, public_key={self.public_key_string})"

    def __hash__(self) -> int:
        return Utils.hash_data(self.public_key)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return (
                self.public_key == other.public_key and self.nickname == other.nickname
            )
        return False

    # PROPERTIES
    @property
    def public_key_string(self) -> str:
        return self._key_pair.publickey().export_key().decode("utf-8")

    @public_key_string.setter
    def public_key_string(self, key: str) -> ...:
        raise ValueError("Cannot set the public key string.")

    @public_key_string.deleter
    def public_key_string(self) -> ...:
        raise ValueError("Cannot delete the public key string.")

    @property
    def public_key(self) -> bytes:
        return self._key_pair.publickey().export_key()

    @public_key.setter
    def public_key(self, key: bytes) -> ...:
        raise ValueError("Cannot set the public key, please create a new keypair.")

    @public_key.deleter
    def public_key(self) -> ...:
        raise ValueError("Cannot delete the public key, please create a new keypair.")

    @property
    def nickname(self) -> str:
        """The nickname of the keypair.

        The nickname is used to identify the keypair in a keyring.

        Parameters
        ----------
        name : str

        Returns
        -------
        str
        """
        return self._nickname

    @nickname.setter
    def nickname(self, name: str) -> ...:
        self._nickname = name

    @nickname.deleter
    def nickname(self) -> ...:
        raise ValueError("Cannot delete the nickname, please create a new keypair.")

    # METHODS
    def generate_keypair(self, length: int = 4096) -> ...:
        """Generate a new RSA 2048 bit keypair.

        Parameters
        ----------
        length : int, optional
            The length of the keypair. Default is 4096.
        """
        if not isinstance(length, int):
            raise ValueError("Length must be an integer, not {}".format(type(length)))
        self._key_pair = RSA.generate(length)

    # CODEC
    def sign(self, data: bytes) -> bytes:
        """Sign the data with the private key.

        Parameters
        ----------
        data : bytes
            The data to sign.

        Returns
        -------
        bytes
            The signature.
        """
        if not isinstance(data, bytes):
            raise ValueError("Data must be bytes, not {}".format(type(data)))
        h = SHA256.new(data)
        signature = pkcs1_15.new(self._key_pair).sign(h)
        return signature

    def signature_valid(
        self, data: bytes, signature: bytes, public_key: bytes = None
    ) -> bool:
        """Check if the signature is valid.

        Parameters
        ----------
        data : bytes
            The data that was signed.
        signature : bytes
            The signature to check.
        public_key : bytes, optional
            The public key to use. If None the public key of the keypair will be used.
            Default is None.

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        if not isinstance(data, bytes):
            raise ValueError("Data must be bytes, not {}".format(type(data)))
        if not isinstance(signature, bytes):
            raise ValueError("Signature must be bytes, not {}".format(type(signature)))
        if not isinstance(public_key, bytes) and public_key is not None:
            raise ValueError(
                "Public key must be bytes or None, not {}".format(type(public_key))
            )
        if public_key is None:
            public_key = self.public_key
        rsa_key = RSA.import_key(public_key)
        h = SHA256.new(data)
        try:
            pkcs1_15.new(rsa_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def encrypt(self, data: bytes, receiver_public_key: bytes) -> bytes:
        """Encrypt the data with the public key of the receiver.

        Parameters
        ----------
        data : bytes
            The data to encrypt.
        receiver_public_key : bytes
            The public key of the receiver.

        Returns
        -------
        bytes
            The encrypted data.
        """
        if not isinstance(data, bytes):
            raise ValueError("Data must be bytes, not {}".format(type(data)))
        if not isinstance(receiver_public_key, bytes):
            raise ValueError(
                "Receiver public key must be bytes, not {}".format(
                    type(receiver_public_key)
                )
            )
        recipient_key = RSA.import_key(receiver_public_key)
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        encrypted_data = json.dumps(
            {
                "enc_session_key": enc_session_key.hex(),
                "nonce": cipher_aes.nonce.hex(),
                "tag": tag.hex(),
                "ciphertext": ciphertext.hex(),
                "signature": self.sign(ciphertext).hex(),
            }
        ).encode("utf-8")

        return encrypted_data

    def decrypt(self, data: bytes, sender_public_key: bytes) -> bytes:
        """Decrypt the data with the private key.

        Parameters
        ----------
        data : bytes
            The data to decrypt.
        sender_public_key : bytes
            The public key of the sender.

        Returns
        -------
        bytes
            The decrypted data.

        Raises
        ------
        ValueError
            If the signature is invalid.
        """
        if not isinstance(data, bytes):
            raise ValueError("Data must be bytes, not {}".format(type(data)))
        if not isinstance(sender_public_key, bytes):
            raise ValueError(
                "Sender public key must be bytes, not {}".format(
                    type(sender_public_key)
                )
            )
        data = json.loads(data.decode("utf-8"))
        enc_session_key = bytes.fromhex(data["enc_session_key"])
        nonce = bytes.fromhex(data["nonce"])
        tag = bytes.fromhex(data["tag"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        signature = bytes.fromhex(data["signature"])

        if not self.signature_valid(ciphertext, signature, sender_public_key):
            raise ValueError("Invalid signature.")

        cipher_rsa = PKCS1_OAEP.new(self._key_pair)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        return decrypted_data

    # CODEC
    @classmethod
    def from_key_file(cls, file: str, passphrase: str) -> "RsaKeyPair":
        """Load the keypair from a file.

        Parameters
        ----------
        file : str
            The file to load the keypair from.
        passphrase : str
            The passphrase to decrypt the private key with.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        """
        if not isinstance(file, str):
            raise ValueError("File must be a string, not {}".format(type(file)))
        if not isinstance(passphrase, str):
            raise ValueError(
                "Passphrase must be a string, not {}".format(type(passphrase))
            )
        if not os.path.isfile(file):
            raise FileNotFoundError("Could not find the file {}.".format(file))

        key_pair = cls(_generate_keys=False)
        with open(file, "r") as key_file:
            key_data = json.load(key_file)
            key_pair._nickname = key_data["nickname"]
            key_pair._key_pair = RSA.import_key(
                bytes.fromhex(key_data["private_key"]), passphrase=passphrase
            )

        return key_pair

    def to_key_file(self, file: str, passphrase: str) -> ...:
        """Save the keypair to a file.

        Parameters
        ----------
        file : str
            The file to save the keypair to.
        passphrase : str
            The passphrase to encrypt the private key with.

        .. attention::

            This method exposes the private key.

        """
        if not isinstance(file, str):
            raise ValueError("File must be a string, not {}".format(type(file)))
        if not isinstance(passphrase, str):
            raise ValueError(
                "Passphrase must be a string, not {}".format(type(passphrase))
            )
        data = {
            "nickname": self._nickname,
            "public_key": self.public_key_string,
            "private_key": self._key_pair.export_key(passphrase=passphrase).hex(),
        }
        # Dump the data to the file
        with open(file, "w") as key_file:
            json.dump(data, key_file)

    @classmethod
    def from_key_string(cls, key: str, passphrase: str) -> "RsaKeyPair":
        """Load the keypair from a string.

        Parameters
        ----------
        key : str
            The keypair as a string.
        passphrase : str
            The passphrase to decrypt the private key with.

        Returns
        -------
        RsaKeyPair
            The keypair.
        """
        if not isinstance(key, str):
            raise ValueError("Key must be a string, not {}".format(type(key)))
        if not isinstance(passphrase, str):
            raise ValueError(
                "Passphrase must be a string, not {}".format(type(passphrase))
            )

        key_pair = cls(_generate_keys=False)
        key_data = json.loads(key)
        key_pair._nickname = key_data["nickname"]
        key_pair._key_pair = RSA.import_key(
            bytes.fromhex(key_data["private_key"]), passphrase=passphrase
        )

        return key_pair

    def to_key_string(self, passphrase: str) -> str:
        """Save the keypair to a string.

        Parameters
        ----------
        passphrase : str
            The passphrase to encrypt the private key with.

        .. attention::

            This method exposes the private key.

        """
        if not isinstance(passphrase, str):
            raise ValueError(
                "Passphrase must be a string, not {}".format(type(passphrase))
            )
        return json.dumps(
            {
                "nickname": self._nickname,
                "public_key": self.public_key_string,
                "private_key": self._key_pair.export_key(passphrase=passphrase).hex(),
            }
        )


class RsaAuthKeyPair(RsaKeyPair, AbstractAuthKeyPair):
    """A class to represent an RSA authentication keypair."""

    def __init__(self, nickname: str = None, _generate_keys: bool = True) -> ...:
        super().__init__(nickname, _generate_keys)

    def __str__(self) -> str:
        return f"RsaAuthKeyPair(nickname={self._nickname})"

    def __repr__(self) -> str:
        return f"RsaAuthKeyPair(nickname={self._nickname}, public_key={self.public_key_string})"

    def encrypt(self, data, receiver_public_key):
        raise NotImplementedError("Cannot encrypt data with an authentication keypair.")

    def decrypt(self, data: bytes, sender_public_key: bytes) -> bytes:
        raise NotImplementedError("Cannot decrypt data with an authentication keypair.")


class RsaEncKeyPair(RsaKeyPair, AbstractEncKeyPair):
    """A class to represent an RSA encryption keypair."""

    def __init__(self, nickname: str = None, _generate_keys: bool = True) -> ...:
        super().__init__(nickname, _generate_keys)

    def __str__(self) -> str:
        return f"RsaEncKeyPair(nickname={self._nickname})"

    def __repr__(self) -> str:
        return f"RsaEncKeyPair(nickname={self._nickname}, public_key={self.public_key_string})"

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError("Cannot sign data with an encryption keypair.")

    def signature_valid(
        self, data: bytes, signature: bytes, public_key: bytes = None
    ) -> bool:
        raise NotImplementedError("Cannot verify signature with an encryption keypair.")
