import argparse
from util import (
    extract_public_key,
    verify_artifact_signature,
    validate_artifact_path,
    validate_log_index,
    validate_root_hash,
    validate_tree_size,
    get_user_auth,
)
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)
from constants import GET_LOG, GET_LOG_ENTRY, GET_PROOF, REQUEST_TIMEOUT

import requests
import json


def get_log_entry(log_index, debug=False):
    response = requests.get(GET_LOG_ENTRY.format(log_index), timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    data = response.json()
    try:
        uuid = list(data.keys())[0]
        log_index = data[uuid]["logIndex"]
        if not isinstance(log_index, int) or log_index < 0:
            raise ValueError(f"Log index should be a non-negative integer, {log_index}")
        if not data[uuid]["verification"]["inclusionProof"]:
            raise ValueError(f"Given log index: {log_index} is invalid")
        return data
    except ValueError as e:
        raise e


def get_verification_proof(log_entry):
    # forgoeing the cost of additional network call for log index validation with below call
    try:
        if not log_entry:
            raise ValueError("Log entry can't be empty")
        uuid = list(log_entry.keys())[0]
        proof = log_entry[uuid]["verification"]["inclusionProof"]
    except Exception as e:
        raise e
    return proof


def inclusion(log_index, artifact_filepath, debug=False):
    try:
        if not validate_log_index(log_index, debug):
            raise ValueError(
                f"Inclusion failed: Unable to validate log index: {log_index}"
            )
        validate_artifact_path(artifact_filepath)
        if debug:
            print(f"Given log index validated: {log_index}")
            print(f"Given artifact path validated: {artifact_filepath}")
        data = get_log_entry(log_index)
        if not data:
            raise ValueError(
                f"Log entrysource venv/bin/activate missing/invalid: {data}"
            )
        signature, public_cert = get_user_auth(data)
        public_key = extract_public_key(public_cert)

        verify_artifact_signature(signature, public_key, artifact_filepath)

        proof = get_verification_proof(data)
        if not proof:
            raise ValueError(f"Verification proof not found/invalid: {proof}")
        index = proof["logIndex"]
        root_hash = proof["rootHash"]
        tree_size = proof["treeSize"]
        hashes = list(proof["hashes"])
        uuid = list(data.keys())[0]
        leaf_hash = compute_leaf_hash(data[uuid]["body"].encode("utf-8"))

        verify_inclusion(
            DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, debug
        )
    except ValueError as e:
        print(f"Validation error: {e}")
        return False
    except Exception as e:
        print(f"Inclusion verification failed due to: {e}")
        return False

    print("Signature is valid.\nOffline root hash calculation for inclusion verified.")
    return True


def get_latest_checkpoint(debug=False):
    response = requests.get(GET_LOG, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    data = response.json()
    if debug:
        with open("checkpoint.json", "w") as f:
            json.dump(data, f, indent=4)
    return data


def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    try:
        latest_checkpoint = get_latest_checkpoint()
        tree_id = prev_checkpoint["treeID"]
        tree_size = prev_checkpoint["treeSize"]
        root_hash = prev_checkpoint["rootHash"]

        size_1 = tree_size
        size_2 = int(latest_checkpoint["treeSize"])
        latest_root_hash = latest_checkpoint["rootHash"]

        if not validate_tree_size(size_1):
            raise ValueError(f"Invalid old checkpoint tree size: {size_1}")
        if not validate_tree_size(size_2):
            raise ValueError(f"Invalid latest checkpoint tree size: {size_2}")
        if not validate_root_hash(root_hash):
            raise ValueError(f"Invalid old checkpoint root hash: {root_hash}")
        if not validate_root_hash(latest_root_hash):
            raise ValueError(f"Invalid latest checkpoint root hash: {latest_root_hash}")

        response = requests.get(
            GET_PROOF.format(size_1, size_2, tree_id), timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        verify_consistency(
            DefaultHasher,
            size_1,
            size_2,
            response.json()["hashes"],
            root_hash,
            latest_root_hash,
        )

    except Exception as e:
        print(f"Failed consistency check: {e}")
        return False

    print("Consistency verification successful")
    return True


def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        if not args.artifact:
            print("please specify artifact filepath for inclusion proof")
            return
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
