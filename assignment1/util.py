from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

import base64
import json
import requests
import os
import re
from constants import GET_LOG_ENTRY, REQUEST_TIMEOUT


# extracts and returns public key from a given cert (in pem format)
def extract_public_key(cert):
    # read the certificate
    #    with open("cert.pem", "rb") as cert_file:
    #        cert_data = cert_file.read()

    # load the certificate
    certificate = x509.load_pem_x509_certificate(cert, default_backend())

    # extract the public key
    public_key = certificate.public_key()

    # save the public key to a PEM file
    #    with open("cert_public.pem", "wb") as pub_key_file:
    #        pub_key_file.write(public_key.public_bytes(
    #            encoding=serialization.Encoding.PEM,
    #            format=serialization.PublicFormat.SubjectPublicKeyInfo
    #        ))
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem_public_key


def verify_artifact_signature(signature, public_key, artifact_filename):
    # load the public key
    # with open("cert_public.pem", "rb") as pub_key_file:
    #    public_key = load_pem_public_key(pub_key_file.read())

    # load the signature
    #    with open("hello.sig", "rb") as sig_file:
    #        signature = sig_file.read()

    public_key = load_pem_public_key(public_key)
    # load the data to be verified
    with open(artifact_filename, "rb") as data_file:
        data = data_file.read()

    # verify the signature
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        print("Signature is invalid", e)
        raise ValueError("Signature is invalid")
    except Exception as e:
        print("Exception in verifying artifact signature:", e)
        raise e


def validate_log_index(log_index, debug):
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
    except Exception as e:
        print(f"Unable to execute /log/entries request: {e}")
        return False

    return True


# derive signature and public key from given log entry
def get_user_auth(log_entry):
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


def validate_artifact_path(artifact_path):
    if not artifact_path:
        raise ValueError("Artifact path can't be empty")
    if not os.path.exists(artifact_path):
        raise ValueError(f"Given artifact path: {artifact_path} doesn't exist")
    return True


def validate_tree_size(tree_size):
    if not isinstance(tree_size, int) or tree_size < 0:
        raise ValueError(f"Tree size should be a non-negative integer, {tree_size}")
    return True


# Used ChatGPT to generate this function
def validate_root_hash(hash):
    if not isinstance(hash, str):
        return False

    # Check for 64 hexadecimal characters, case-insensitive
    return bool(re.match(r"^[0-9a-fA-F]{64}$", hash))
