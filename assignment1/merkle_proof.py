"""
Merkle tree proof verification implementation.

This module implements RFC 6962 Certificate Transparency proof verification
for Merkle tree inclusion and consistency proofs.
"""

import hashlib
import binascii
import base64
from typing import List, Tuple, Callable

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """Hasher implements RFC 6962 hashing for Certificate Transparency."""

    def __init__(self, hash_func: Callable = hashlib.sha256) -> None:
        """Initialize hasher with a hash function."""
        self.hash_func = hash_func

    def new(self):  # type: ignore[no-untyped-def]
        """Create a new hash instance."""
        return self.hash_func()

    def empty_root(self) -> bytes:
        """Return the hash of an empty tree."""
        h = self.new()
        return h.digest()  # type: ignore[no-any-return]

    def hash_leaf(self, leaf: bytes) -> bytes:
        """
        Hash a leaf node with RFC 6962 leaf prefix.

        Args:
            leaf: The leaf data to hash

        Returns:
            bytes: The hashed leaf digest
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()  # type: ignore[no-any-return]

    def hash_children(self, left: bytes, right: bytes) -> bytes:
        """
        Hash two child nodes with RFC 6962 node prefix.

        Args:
            left: The left child hash
            right: The right child hash

        Returns:
            bytes: The combined hash digest
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()  # type: ignore[no-any-return]

    def size(self) -> int:
        """Return the hash digest size in bytes."""
        h = self.new()
        return h.digest_size  # type: ignore[no-any-return]


# DEFAULT_HASHER is a SHA256 based LogHasher
DEFAULT_HASHER = Hasher(hashlib.sha256)


def verify_consistency(
    hasher: Hasher, size1: int, size2: int, proof: List[str], root1: str, root2: str
) -> None:
    """
    Verify consistency proof between two tree states.

    Args:
        hasher: The hasher instance to use
        size1: Size of the first tree
        size2: Size of the second tree
        proof: Consistency proof hashes
        root1: Root hash of the first tree
        root2: Root hash of the second tree

    Raises:
        ValueError: If proof verification fails
    """
    # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    # All parameters are required by RFC 6962 consistency proof verification
    # change format of args to be bytearray instead of hex strings
    root1_bytes = bytes.fromhex(root1)
    root2_bytes = bytes.fromhex(root2)
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1_bytes, root2_bytes)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                f"expected empty bytearray_proof, but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1_bytes, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"wrong bytearray_proof size {len(bytearray_proof)}, want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1_bytes)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2_bytes)


def verify_match(calculated: bytes, expected: bytes) -> None:
    """
    Verify that calculated hash matches expected hash.

    Args:
        calculated: The calculated hash
        expected: The expected hash

    Raises:
        RootMismatchError: If hashes don't match
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index: int, size: int) -> Tuple[int, int]:
    """
    Decompose inclusion proof into inner and border components.

    Args:
        index: The leaf index
        size: The tree size

    Returns:
        tuple: (inner, border) proof sizes
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index: int, size: int) -> int:
    """
    Calculate the inner proof size.

    Args:
        index: The leaf index
        size: The tree size

    Returns:
        int: The inner proof size
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher: Hasher, seed: bytes, proof: List[bytes], index: int) -> bytes:
    """
    Chain inner proof hashes based on index bits.

    Args:
        hasher: The hasher instance
        seed: Initial hash value
        proof: List of proof hashes
        index: The index bits to determine order

    Returns:
        bytes: The chained hash result
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(
    hasher: Hasher, seed: bytes, proof: List[bytes], index: int
) -> bytes:
    """
    Chain inner proof hashes to the right.

    Args:
        hasher: The hasher instance
        seed: Initial hash value
        proof: List of proof hashes
        index: The index bits to determine order

    Returns:
        bytes: The chained hash result
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher: Hasher, seed: bytes, proof: List[bytes]) -> bytes:
    """
    Chain border proof hashes to the right.

    Args:
        hasher: The hasher instance
        seed: Initial hash value
        proof: List of proof hashes

    Returns:
        bytes: The chained hash result
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """Exception raised when calculated root doesn't match expected root."""

    def __init__(self, expected_root: bytes, calculated_root: bytes) -> None:
        """
        Initialize the error with expected and calculated roots.

        Args:
            expected_root: The expected root hash
            calculated_root: The calculated root hash
        """
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))
        super().__init__()

    def __str__(self) -> str:
        """Return string representation of the error."""
        calc_root_str = self.calculated_root.decode("ascii")
        exp_root_str = self.expected_root.decode("ascii")
        return (
            f"calculated root:\n{calc_root_str}\n "
            f"does not match expected root:\n{exp_root_str}"
        )


def root_from_inclusion_proof(
    hasher: Hasher, index: int, size: int, leaf_hash: bytes, proof: List[bytes]
) -> bytes:
    """
    Calculate root hash from inclusion proof.

    Args:
        hasher: The hasher instance
        index: The leaf index
        size: The tree size
        leaf_hash: The leaf hash
        proof: The inclusion proof hashes

    Returns:
        bytes: The calculated root hash

    Raises:
        ValueError: If index or proof is invalid
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(
    hasher: Hasher,
    index: int,
    size: int,
    leaf_hash: str,
    proof: List[str],
    root: str,
    debug: bool = False,
) -> None:
    """
    Verify inclusion proof for a leaf in the Merkle tree.

    Args:
        hasher: The hasher instance
        index: The leaf index
        size: The tree size
        leaf_hash: The leaf hash to verify
        proof: The inclusion proof hashes
        root: The expected root hash
        debug: Enable debug output

    Raises:
        ValueError: If verification fails
    """
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    # All parameters are required by RFC 6962 inclusion proof verification
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body: bytes) -> str:
    """
    Compute leaf hash according to RFC 6962 spec.

    Args:
        body: The base64 encoded entry body

    Returns:
        str: The hexadecimal leaf hash
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
