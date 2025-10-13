"""
Utility functions for cryptographic operations and validation.

This module provides helper functions for extracting public keys from certificates,
verifying signatures, and validating various input parameters.
"""

import base64
import json
import os
import re
from typing import Dict, Any, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import requests

from constants import GET_LOG_ENTRY, REQUEST_TIMEOUT


# extracts and returns public key from a given cert (in pem format)
def extract_public_key(cert: bytes) -> bytes:
    """
    Extract public key from a PEM certificate.

    Args:
        cert: PEM formatted certificate bytes

    Returns:
        bytes: The public key in PEM format
    """

    # load the certificate
    certificate = x509.load_pem_x509_certificate(cert, default_backend())

    # extract the public key
    public_key = certificate.public_key()

    pem_public_key: bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key


def verify_artifact_signature(
    signature: bytes, public_key: bytes, artifact_filename: str
) -> None:
    """
    Verify artifact signature using public key.

    Args:
        signature: The signature bytes
        public_key: The public key in PEM format
        artifact_filename: Path to the artifact file

    Raises:
        ValueError: If signature is invalid
    """

    loaded_public_key = load_pem_public_key(public_key)
    # load the data to be verified
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        loaded_public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))  # type: ignore[attr-defined]
    except InvalidSignature as e:
        print("Signature is invalid", e)
        raise ValueError("Signature is invalid") from e
    except Exception as e:
        print("Exception in verifying artifact signature:", e)
        raise e


def validate_log_index(log_index: int, debug: bool) -> bool:
    """
    Validate that log index exists in Rekor.

    Args:
        log_index: The log index to validate
        debug: Enable debug output

    Returns:
        bool: True if valid, False otherwise

    Raises:
        ValueError: If log index format is invalid
    """
    if not isinstance(log_index, int) or log_index < 0:
        raise ValueError(f"Log index should be a non-negative integer, {log_index}")
    try:
        response = requests.get(
            GET_LOG_ENTRY.format(log_index), timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            if debug:
                print(f"Validation failed: Log index {log_index} not found")
        else:
            print(f"Network call failed: {e}")
        return False
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Unable to execute /log/entries request: {e}")
        return False

    return True


# derive signature and public key from given log entry
def get_user_auth(log_entry: Dict[str, Any]) -> Tuple[bytes, bytes]:
    """
    Extract signature and public certificate from log entry.

    Args:
        log_entry: The Rekor log entry

    Returns:
        tuple: (signature bytes, public certificate bytes)
    """
    # Rekor API returns log entries with UUID as the single top-level key
    uuid = list(log_entry.keys())[0]
    encoded_bytes = log_entry[uuid]["body"].encode("utf-8")
    decoded_bytes = base64.b64decode(encoded_bytes)
    decoded_string = decoded_bytes.decode("utf-8")
    body = json.loads(decoded_string)
    signature = body["spec"]["signature"]["content"]
    public_cert = body["spec"]["signature"]["publicKey"]["content"]
    decoded_signature = base64.b64decode(signature.encode("utf-8"))
    decoded_public_cert = base64.b64decode(public_cert.encode("utf-8"))
    return decoded_signature, decoded_public_cert


def validate_artifact_path(artifact_path: str) -> bool:
    """
    Validate that artifact path exists.

    Args:
        artifact_path: Path to the artifact

    Returns:
        bool: True if valid

    Raises:
        ValueError: If path is invalid or doesn't exist
    """
    if not artifact_path:
        raise ValueError("Artifact path can't be empty")
    if not os.path.exists(artifact_path):
        raise ValueError(f"Given artifact path: {artifact_path} doesn't exist")
    return True


def validate_tree_size(tree_size: int) -> bool:
    """
    Validate tree size is a non-negative integer.

    Args:
        tree_size: The tree size to validate

    Returns:
        bool: True if valid

    Raises:
        ValueError: If tree size is invalid
    """
    if not isinstance(tree_size, int) or tree_size < 0:
        raise ValueError(f"Tree size should be a non-negative integer, {tree_size}")
    return True


# Used ChatGPT to generate this function
def validate_root_hash(root_hash: str) -> bool:
    """
    Validate root hash is a 64-character hex string.

    Args:
        root_hash: The root hash to validate

    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(root_hash, str):
        return False

    # Check for 64 hexadecimal characters, case-insensitive
    return bool(re.match(r"^[0-9a-fA-F]{64}$", root_hash))
