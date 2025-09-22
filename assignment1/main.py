import argparse
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

import requests
import json
import base64

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    response = requests.get('https://rekor.sigstore.dev/api/v1/log/entries?logIndex={0}'.format(log_index))
    response.raise_for_status()
    data = response.json()
    uuid = list(data.keys())[0]
    encoded_bytes = data[uuid]['body'].encode('utf-8')
    decoded_bytes = base64.b64decode(encoded_bytes)
    decoded_string = decoded_bytes.decode('utf-8')
    body = json.loads(decoded_string)
    signature = body['spec']['signature']['content']
    public_cert = body['spec']['signature']['publicKey']['content']
    # first decode the base64 encoded public cert

    decoded_signature = base64.b64decode(signature.encode('utf-8'))

    decoded_public_cert = base64.b64decode(public_cert.encode('utf-8'))
    public_key = extract_public_key(decoded_public_cert)

    # verify the validity of the signature given artifact using the utility function
    verify_artifact_signature(decoded_signature, public_key, 'artifact.md')

    # print(public_key)
    pass

def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    response = requests.get('https://rekor.sigstore.dev/api/v1/log/entries?logIndex={0}'.format(log_index))
    response.raise_for_status()
    data = response.json()
    uuid = list(data.keys())[0]
    proof = data[uuid]['verification']['inclusionProof']
    index = proof['logIndex']
    root_hash = proof['rootHash']
    tree_size = proof['treeSize']
    hashes = list(proof['hashes'])
    leaf_hash = compute_leaf_hash(data[uuid]['body'].encode('utf-8'))
    verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, True)
    # print(index, root_hash, tree_size, hashes, leaf_hash)
    pass

def inclusion(log_index, artifact_filepath, debug=False):
    # verify that log index and artifact filepath values are sane
    # extract_public_key(certificate)
    # verify_artifact_signature(signature, public_key, artifact_filepath)
    # get_verification_proof(log_index)
    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    pass

def get_latest_checkpoint(debug=False):
    response = requests.get('https://rekor.sigstore.dev/api/v1/log')
    response.raise_for_status()
    data = response.json()
    tree_id = data['treeID']
    tree_size = data['treeSize']
    root_hash = data['rootHash']
    latest_checkpoint = data['signedTreeHead']
    return tree_id, tree_size, root_hash, latest_checkpoint
    pass

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    # get_latest_checkpoint()
    tree_id, tree_size, root_hash, latest_checkpoint =  get_latest_checkpoint()
    size_1 = int.from_bytes(tree_size) - 1
    size_1 = size_1.to_bytes
    size_2 = tree_size
    response = requests.get('https://rekor.sigstore.dev/api/v1/log/proof?firstSize={0}&lastSize={1}&treeId={2}'.format(size_1, size_2, tree_id))
    response.raise_for_status()

    print(size_1, size_2, response)
    # verify_consistency(DefaultHasher, )
    pass

def test_consistency():
    tree_id, tree_size, root_hash, latest_checkpoint =  get_latest_checkpoint()
    size_1 = tree_size - 1
    # size_1 = size_1.to_bytes
    size_2 = tree_size
    response = requests.get('https://rekor.sigstore.dev/api/v1/log/proof?firstSize={0}&lastSize={1}&treeId={2}'.format(size_1, size_2, tree_id))
    response.raise_for_status()

    print(size_1, size_2, response.json())

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    # get_log_entry(515701802)
    # get_verification_proof(515701802)
    # get_latest_checkpoint()
    test_consistency()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
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