# Some custom errors to easier identify problems and catch errors.
class KeyNotFoundError(Exception):
    """
    Exception raised when a key is not found in the trie.

    .. note::
        This error is meanth to create a different error for dictionary KeyErrors
        and Trie KeyErrors.
    """

    def __init__(self, message) -> ...:
        super().__init__(message)


# For distinction between proof of inclusion and exclusion
class PoeError(Exception):
    """Exception raised when POE cannot be generated."""

    def __init__(self, message) -> ...:
        super().__init__(message)


class PoiError(Exception):
    """Exception raised when POI cannot generated."""

    def __init__(self, message) -> ...:
        super().__init__(message)
