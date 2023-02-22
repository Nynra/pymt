import unittest
from .test_mpt import *
from .test_empt import *
from .test_utils import *
from .test_vectors import *
from .test_merkle_tools import *
from .test_mt import *


def run_tests(
    mt: bool = True,
    mpt: bool = True,
    empt: bool = True,
    utils: bool = True,
    vectors: bool = True,
) -> ...:
    """
    A function to run some tests on the package.

    Parameters
    ----------
    mt : bool, optional
        Run the tests on the MT. The default is True.
    mpt : bool, optional
        Run the tests on the MPT. The default is True.
    empt : bool, optional
        Run the tests on the EMPT. The default is True.
    utils : bool, optional
        Run the tests on the utils. The default is True.
    vectors : bool, optional
        Run the tests on the vectors. The default is True.
    """
    # Add the tests to the test suite
    suite = unittest.TestSuite()
    if mt:
        suite.addTests(
            [
                unittest.makeSuite(TestMerkleTools),
                unittest.makeSuite(TestMerkleTree),
            ]
        )
    if mpt:
        suite.addTests(
            [
                unittest.makeSuite(TestMptSecure),
                unittest.makeSuite(TestMptNonSecure),
            ]
        )

    if empt:
        suite.addTests(
            [
                unittest.makeSuite(TestDataReference),
                unittest.makeSuite(TestFullEmptSecure),
                unittest.makeSuite(TestFullEmptNonSecure),
                unittest.makeSuite(TestSparseEmptNonSecure),
                unittest.makeSuite(TestSparseEmptSecure),
                unittest.makeSuite(TestRootEmptNonSecure),
                unittest.makeSuite(TestRootEmptSecure),
            ]
        )
    if utils:
        suite.addTests(
            [
                unittest.makeSuite(TestProof),
                unittest.makeSuite(TestNode),
                unittest.makeSuite(TestNibblePath),
            ]
        )
    if vectors:
        suite.addTest(unittest.makeSuite(TestVectors))

    # Run the test suite
    runner = unittest.TextTestRunner()
    runner.run(suite)
