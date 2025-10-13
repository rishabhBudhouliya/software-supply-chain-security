# Rekor Verifier

A Python tool for verifying inclusion and consistency proofs in the Rekor transparency log.

## What it does

This tool lets you:
- Verify that an artifact exists in the Rekor transparency log (inclusion proof)
- Verify that the log hasn't been tampered with between two checkpoints (consistency proof)
- Check cryptographic signatures on artifacts

It implements the RFC 6962 Certificate Transparency specification for Merkle tree verification.

## Requirements

- Python 3.11+
- Dependencies listed in `requirements.txt`

Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Get the latest checkpoint

```bash
python assignment1/main.py --checkpoint
```

### Verify inclusion of an artifact

You need the log index and the artifact file:

```bash
python assignment1/main.py --inclusion 126574567 --artifact ./path/to/artifact
```

This will:
1. Fetch the log entry from Rekor
2. Verify the artifact's signature
3. Calculate and verify the Merkle tree root hash

### Verify consistency between checkpoints

You need the tree ID, tree size, and root hash from a previous checkpoint:

```bash
python assignment1/main.py --consistency \
  --tree-id <tree-id> \
  --tree-size <size> \
  --root-hash <hash>
```

This compares your checkpoint against the current state of the log.

### Debug mode

Add `-d` or `--debug` to any command for verbose output:

```bash
python assignment1/main.py -d --checkpoint
```

## How it works

**Inclusion proof**: Given a log index and artifact, the tool fetches the entry from Rekor, extracts the public key from the certificate, verifies the signature, and uses the inclusion proof hashes to recalculate the Merkle tree root. If it matches the root in the proof, the artifact is verified.

**Consistency proof**: Given an old checkpoint (tree size + root hash) and the current state, the tool uses consistency proof hashes to verify that the old tree is a prefix of the new tree. This proves the log hasn't been retroactively modified.

## Project structure

- `main.py` - CLI interface and main verification logic
- `merkle_proof.py` - RFC 6962 Merkle tree proof verification
- `util.py` - Cryptographic utilities (signature verification, key extraction)
- `constants.py` - API endpoints and configuration

## Development

Run linters:
```bash
ruff check assignment1/
pylint assignment1/*.py
```

Run type checker:
```bash
mypy assignment1/
```

Run security scanner:
```bash
bandit -r assignment1/
```
