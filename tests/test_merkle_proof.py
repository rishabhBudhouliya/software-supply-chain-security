"""
Test suite for merkle_proof.py - Merkle tree operations.

Note: Test structure and implementation assisted by Claude AI (Anthropic).
Reviewed, understood, and verified by Rishabh Budhouliya.
"""

import pytest
import hashlib
import base64
from assignment1.merkle_proof import (
    Hasher,
    compute_leaf_hash,
    DEFAULT_HASHER,
    RFC6962_LEAF_HASH_PREFIX,
    RFC6962_NODE_HASH_PREFIX,
)


def test_hasher_empty_root():
    """Test Hasher.empty_root() produces correct empty hash."""
    hasher = Hasher(hashlib.sha256)
    empty_hash = hasher.empty_root()

    # Should return SHA256 digest of empty input
    expected = hashlib.sha256().digest()
    assert empty_hash == expected
    assert len(empty_hash) == 32  # SHA256 produces 32 bytes


def test_hasher_hash_leaf():
    """Test Hasher.hash_leaf() produces correct leaf hash with RFC 6962 prefix."""
    hasher = Hasher(hashlib.sha256)
    test_data = b"test data"

    leaf_hash = hasher.hash_leaf(test_data)

    # Verify it's 32 bytes (SHA256)
    assert len(leaf_hash) == 32

    # Manually compute expected value
    expected = hashlib.sha256(bytes([RFC6962_LEAF_HASH_PREFIX]) + test_data).digest()
    assert leaf_hash == expected


def test_hasher_hash_children():
    """Test Hasher.hash_children() combines two hashes correctly."""
    hasher = Hasher(hashlib.sha256)

    # Create two dummy hashes (32 bytes each)
    left = b"a" * 32
    right = b"b" * 32

    node_hash = hasher.hash_children(left, right)

    # Verify it's 32 bytes
    assert len(node_hash) == 32

    # Manually compute expected value
    expected = hashlib.sha256(bytes([RFC6962_NODE_HASH_PREFIX]) + left + right).digest()
    assert node_hash == expected


def test_hasher_size():
    """Test Hasher.size() returns correct digest size."""
    hasher = Hasher(hashlib.sha256)
    assert hasher.size() == 32  # SHA256 produces 32 bytes


def test_compute_leaf_hash():
    """Test compute_leaf_hash() function with base64 encoded data."""
    # Test data
    test_data = b"test entry data"
    # Base64 encode it (as the function expects)
    encoded_data = base64.b64encode(test_data)

    # Compute leaf hash
    leaf_hash_hex = compute_leaf_hash(encoded_data)

    # Should return hex string
    assert isinstance(leaf_hash_hex, str)
    assert len(leaf_hash_hex) == 64  # 32 bytes = 64 hex characters

    # Verify it's valid hex
    bytes.fromhex(leaf_hash_hex)  # Should not raise


def test_default_hasher_instance():
    """Test that DEFAULT_HASHER is properly initialized."""
    # Verify it's a Hasher instance
    assert isinstance(DEFAULT_HASHER, Hasher)

    # Test that it can compute hashes
    test_data = b"test"
    leaf_hash = DEFAULT_HASHER.hash_leaf(test_data)
    assert len(leaf_hash) == 32


def test_hash_consistency():
    """Test that hashing the same data produces same result (deterministic)."""
    hasher = Hasher(hashlib.sha256)
    test_data = b"consistency test"

    # Hash the same data multiple times
    hash1 = hasher.hash_leaf(test_data)
    hash2 = hasher.hash_leaf(test_data)
    hash3 = hasher.hash_leaf(test_data)

    # All should be identical
    assert hash1 == hash2 == hash3


def test_hasher_different_data_different_hash():
    """Test that different data produces different hashes."""
    hasher = Hasher(hashlib.sha256)

    hash1 = hasher.hash_leaf(b"data1")
    hash2 = hasher.hash_leaf(b"data2")

    # Should be different
    assert hash1 != hash2


def test_hasher_new_creates_fresh_instance():
    """Test that hasher.new() creates a new hash instance."""
    hasher = Hasher(hashlib.sha256)

    h1 = hasher.new()
    h2 = hasher.new()

    # Should be separate instances
    assert h1 is not h2

    # Both should be usable
    h1.update(b"test")
    assert len(h1.digest()) == 32


def test_compute_leaf_hash_empty_data():
    """Test compute_leaf_hash with empty base64 data."""
    # Empty data encoded
    empty_encoded = base64.b64encode(b"")

    result = compute_leaf_hash(empty_encoded)

    # Should still return a valid hash
    assert isinstance(result, str)
    assert len(result) == 64


def test_compute_leaf_hash_returns_hex():
    """Test that compute_leaf_hash returns hexadecimal string."""
    test_data = base64.b64encode(b"test data for hashing")

    result = compute_leaf_hash(test_data)

    # Should be valid hex
    assert all(c in '0123456789abcdefABCDEF' for c in result)
    assert len(result) == 64


def test_verify_match_success():
    """Test verify_match() with matching hashes."""
    from assignment1.merkle_proof import verify_match

    hash1 = b"a" * 32
    hash2 = b"a" * 32

    # Should not raise - hashes match
    verify_match(hash1, hash2)


def test_verify_match_failure():
    """Test verify_match() with non-matching hashes."""
    from assignment1.merkle_proof import verify_match, RootMismatchError

    hash1 = b"a" * 32
    hash2 = b"b" * 32

    # Should raise RootMismatchError
    with pytest.raises(RootMismatchError):
        verify_match(hash1, hash2)


def test_inner_proof_size():
    """Test inner_proof_size() calculation."""
    from assignment1.merkle_proof import inner_proof_size

    # Test various index/size combinations
    assert inner_proof_size(0, 8) == 3  # 0 ^ 7 = 7, 7.bit_length() = 3
    assert inner_proof_size(1, 8) == 3  # 1 ^ 7 = 6, 6.bit_length() = 3
    assert inner_proof_size(0, 1) == 0  # 0 ^ 0 = 0, 0.bit_length() = 0


def test_decomp_incl_proof():
    """Test decomp_incl_proof() decomposes proof correctly."""
    from assignment1.merkle_proof import decomp_incl_proof

    # Test decomposition
    inner, border = decomp_incl_proof(5, 8)

    # Verify it returns two integers
    assert isinstance(inner, int)
    assert isinstance(border, int)
    assert inner >= 0
    assert border >= 0


def test_chain_inner():
    """Test chain_inner() chains hashes correctly."""
    from assignment1.merkle_proof import chain_inner

    hasher = Hasher(hashlib.sha256)
    seed = b"a" * 32
    proof = [b"b" * 32, b"c" * 32]
    index = 3

    result = chain_inner(hasher, seed, proof, index)

    # Should return a hash
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_chain_border_right():
    """Test chain_border_right() chains border hashes."""
    from assignment1.merkle_proof import chain_border_right

    hasher = Hasher(hashlib.sha256)
    seed = b"a" * 32
    proof = [b"b" * 32, b"c" * 32]

    result = chain_border_right(hasher, seed, proof)

    # Should return a hash
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_verify_inclusion_simple():
    """Test verify_inclusion() with a simple case."""
    from assignment1.merkle_proof import verify_inclusion

    hasher = Hasher(hashlib.sha256)

    # Create a simple tree with 2 leaves
    # leaf0 = hash(0x00 || "leaf0")
    # leaf1 = hash(0x00 || "leaf1")
    # root = hash(0x01 || leaf0 || leaf1)

    leaf0_data = b"leaf0"
    leaf0_hash = hasher.hash_leaf(leaf0_data)

    leaf1_hash = hasher.hash_leaf(b"leaf1")
    root = hasher.hash_children(leaf0_hash, leaf1_hash)

    # Proof for leaf0 at index 0 in tree of size 2
    # The proof is just leaf1's hash
    proof_hashes = [leaf1_hash.hex()]
    root_hex = root.hex()
    leaf0_hex = leaf0_hash.hex()

    # This should not raise
    verify_inclusion(hasher, 0, 2, leaf0_hex, proof_hashes, root_hex, debug=False)


def test_verify_consistency_simple():
    """Test verify_consistency() with a simple matching case."""
    from assignment1.merkle_proof import verify_consistency

    hasher = Hasher(hashlib.sha256)

    # Create a tree that grows from size 1 to 2
    # Tree at size 1: just leaf0
    leaf0 = hasher.hash_leaf(b"leaf0")
    root1 = leaf0

    # Tree at size 2: leaf0 and leaf1
    leaf1 = hasher.hash_leaf(b"leaf1")
    root2 = hasher.hash_children(leaf0, leaf1)

    # Consistency proof from size 1 to 2 is: [leaf1]
    proof = [leaf1.hex()]

    # This should not raise
    verify_consistency(
        hasher,
        1,  # old size
        2,  # new size
        proof,
        root1.hex(),
        root2.hex()
    )


def test_verify_consistency_equal_sizes():
    """Test verify_consistency() when both sizes are equal."""
    from assignment1.merkle_proof import verify_consistency

    hasher = Hasher(hashlib.sha256)
    leaf0 = hasher.hash_leaf(b"leaf0")

    # Same size means same tree - no proof needed
    verify_consistency(
        hasher,
        1,  # old size
        1,  # new size (same)
        [],  # empty proof
        leaf0.hex(),
        leaf0.hex()
    )


def test_root_mismatch_error():
    """Test that RootMismatchError contains expected and calculated hashes."""
    from assignment1.merkle_proof import RootMismatchError
    import binascii

    expected = b"expected_hash"
    calculated = b"calculated_hash"

    error = RootMismatchError(expected, calculated)

    assert error.expected_root == binascii.hexlify(expected)
    assert error.calculated_root == binascii.hexlify(calculated)
