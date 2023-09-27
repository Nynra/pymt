import rlp
from .nibble_path import NibblePath
from .hash import keccak_hash
from typing import List, Union, Tuple, Optional


def _prepare_reference_for_usage(ref: Union[list, bytes]) -> bytes:
    """
    Encode the reference into RLP if needed so stored references will appear as bytes.

    Parameters
    ----------
    ref : bytes or bytearray
        Reference to encode.

    Returns
    -------
    bytes or bytearray
        Encoded reference.

    """
    if not isinstance(ref, (list, bytes, bytearray)):
        raise TypeError("Reference must be list, bytes or bytearray")
    if isinstance(ref, list):
        return rlp.encode(ref)

    return ref


def _prepare_reference_for_encoding(ref: "Node") -> bytes:
    """
    Decode the RLP-encoded reference if needed so the full node will be encoded correctly.

    Parameters
    ----------
    ref : bytes or bytearray
        Reference to decode.

    Returns
    -------
    bytes or bytearray
        Decoded reference.

    """ 
    if isinstance(ref, Node):
        return ref.encode()
    
    if 0 < len(ref) < 32:
        return rlp.decode(ref)

    return ref


class Node:
    """
    Node class.
    """

    EMPTY_HASH = keccak_hash(rlp.encode(b""))

    @staticmethod
    def decode(encoded_data: bytes, include_data: bool = True) -> "Node":
        """
        Decode the node from RLP.

        Parameters
        ----------
        encoded_data : bytes or bytearray
            RLP encoded node.
        include_data : bool
            Whether to include the data in the node. Used for skeleton trie.

        Returns
        -------
        Node
            Decoded node.
        """
        if not isinstance(encoded_data, (bytes, bytearray)):
            raise TypeError("Encoded data must be bytes or bytearray, not {}".format(type(encoded_data)))
        if not isinstance(include_data, bool):
            raise TypeError("Include data must be bool, not {}".format(type(include_data)))
        
        data = rlp.decode(encoded_data)

        assert len(data) == 17 or len(data) == 2  # TODO #1 throw exception

        if len(data) == 17:
            # Its a branch node
            branches = list(map(_prepare_reference_for_usage, data[:16]))
            node_data = data[16]
            if include_data:
                return Branch(branches, node_data)
            elif node_data != None:
                # Add a marker instead of the data
                return Branch(branches, b"1")
            else:
                return Branch(branches, None)

        path, is_leaf = NibblePath.decode_with_type(data[0])
        if is_leaf:
            # Its a leaf node
            if include_data:
                return Leaf(path, data[1])
            elif data[1] != None:
                # Add a marker instead of the data
                return Leaf(path, b"1")
            else:
                return Leaf(path, None)
        else:
            # Its an extension node
            ref = _prepare_reference_for_usage(data[1])
            return Extension(path, ref)

    @staticmethod
    def into_reference(node: "Node") -> bytes:
        """
        Returns reference to the given node.

        If length of encoded node is less than 32 bytes, the reference is encoded node itseld (In-place reference).
        Otherwise reference is keccak hash of encoded node.

        Parameters
        ----------
        node : Node
            Node to get reference for.

        Returns
        -------
        bytes or bytearray

        """
        if not isinstance(node, Node):
            raise TypeError("Node must be Node, not {}".format(type(node)))
        
        encoded_node = node.encode()
        if len(encoded_node) < 32:
            return encoded_node
        else:
            return keccak_hash(encoded_node)


class Leaf(Node):
    """
    Leaf class for the mpt tree.

    The leaf class is used to store data in the tree and is the end of a path.

    Attributes
    ----------
    path : NibblePath
        Path to the data.
    data : bytes
        Data to store.

    Methods
    -------
    encode()
        Encodes the leaf into RLP.

    """

    def __init__(self, path: "NibblePath", data: bytes) -> ...:
        """
        Initializes the leaf.

        Parameters
        ----------
        path : NibblePath
            Path to the data.
        data : bytes
            Data to store.
        """
        if not isinstance(path, NibblePath):
            raise TypeError("Path must be NibblePath, not {}".format(type(path)))
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be bytes or bytearray, not {}".format(type(data)))
        self.path = path
        self.data = data

    def encode(self, include_data: bool = True) -> bytes:
        """
        Encodes the leaf into RLP.

        Returns
        -------
        bytes
            Encoded leaf.

        """
        if not isinstance(include_data, bool):
            raise TypeError("Include data must be bool, not {}".format(type(include_data)))
        if include_data:
            return rlp.encode([self.path.encode(True), self.data])
        else:
            return rlp.encode([self.path.encode(True)])


class Extension(Node):
    """
    Extension class for the mpt tree.

    The extension class is used to store references to other nodes in the tree and is the middle of a path.

    Attributes
    ----------
    path : NibblePath
        Path to the node.
    ref : bytes or bytearray
        Reference to the node.

    Methods
    -------
    encode()
        Encodes the extension into RLP.

    """

    def __init__(self, path: "NibblePath", next_ref: bytes) -> ...:
        """
        Initializes the extension.

        Parameters
        ----------
        path : NibblePath
            Path to the node.
        next_ref : bytes or bytearray
            Reference to the next node.
        """
        if not isinstance(path, NibblePath):
            raise TypeError("Path must be NibblePath, not {}".format(type(path)))
        if not isinstance(next_ref, (bytes, bytearray)):
            raise TypeError("Next ref must be bytes or bytearray, not {}".format(type(next_ref)))
        self.path = path
        self.next_ref = next_ref

    def encode(self, include_data=True):
        """
        Encodes the extension into RLP.

        Parameters
        ----------
        include_data : bool
            Include the reference to the next node.

        Returns
        -------
        bytes
            Encoded extension.
        """
        if not isinstance(include_data, bool):
            raise TypeError("Include data must be bool, not {}".format(type(include_data)))
        
        next_ref = _prepare_reference_for_encoding(self.next_ref)
        if include_data:
            return rlp.encode([self.path.encode(False), next_ref])
        else:
            return rlp.encode([self.path.encode(False)])


class Branch(Node):
    """
    Branch class for the mpt tree.

    The branch class is used to store references to other nodes in the tree and
    is the middle of a path. It is also used to store data in the tree.
    """

    def __init__(self, branches: List[bytes], data: Union[bytes, None] = None) -> ...:
        """
        Initializes the branch.

        Parameters
        ----------
        branches : list of bytes or bytearray
            References to the nodes.
        data : bytes or bytearray
            Data to store.
        """
        if not isinstance(branches, list):
            raise TypeError("Branches must be list, not {}".format(type(branches)))
        for branch in branches:
            if not isinstance(branch, (bytes, bytearray)):
                raise TypeError("Branch must be bytes or bytearray, not {}".format(type(branch)))
        if not isinstance(data, (bytes, bytearray)) and data is not None:
            raise TypeError("Data must be bytes or bytearray, not {}".format(type(data)))
        
        self.branches = branches
        if data is None:
            self.data = b""
        else:
            self.data = data

    def encode(self, include_data: bool = True) -> ...:
        """
        Encodes the branch into RLP.

        Returns
        -------
        bytes
            Encoded branch.
        """
        if not isinstance(include_data, bool):
            raise TypeError("Include data must be bool, not {}".format(type(include_data)))
        branches = list(map(_prepare_reference_for_encoding, self.branches))
        if include_data:
            return rlp.encode(branches + [self.data])
        else:
            return rlp.encode(branches)
