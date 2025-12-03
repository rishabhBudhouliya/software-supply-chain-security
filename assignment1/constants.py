"""
API configuration constants for Rekor transparency log.

This module contains API endpoints and configuration values for interacting
with the Rekor transparency log service.
"""

# API Configurations

GET_LOG_ENTRY = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex={0}"

GET_LOG = "https://rekor.sigstore.dev/api/v1/log"

GET_PROOF = "https://rekor.sigstore.dev/api/v1/log/proof?firstSize={0}&lastSize={1}&treeId={2}"

REQUEST_TIMEOUT = 10
