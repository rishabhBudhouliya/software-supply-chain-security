"""
Test suite for main.py - Main module functions.
Note: Test structure and implementation assisted by Claude AI (Anthropic).
Reviewed, understood, and verified by Rishabh Budhouliya.
"""

import pytest
from unittest.mock import patch, Mock
import requests
from assignment1.main import (
    get_log_entry,
    get_latest_checkpoint,
)


def test_get_log_entry_success():
    """Test get_log_entry() with successful API response."""
    with patch("assignment1.main.requests.get") as mock_get:
        # Create mock response
        mock_response = Mock()
        mock_response.json.return_value = {
            "test-uuid-123": {
                "logIndex": 12345,
                "body": "eyJ0ZXN0IjogImRhdGEifQ==",  # base64 encoded {"test": "data"}
                "integratedTime": 1234567890,
                "verification": {
                    "inclusionProof": {
                        "hashes": ["hash1", "hash2"],
                        "logIndex": 12345,
                        "rootHash": "a" * 64,
                        "treeSize": 10000,
                    }
                },
            }
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Call the function
        result = get_log_entry(12345, debug=False)

        # Verify result structure
        assert "test-uuid-123" in result
        assert result["test-uuid-123"]["logIndex"] == 12345
        assert "body" in result["test-uuid-123"]


def test_get_log_entry_http_error():
    """Test get_log_entry() handles HTTP errors correctly."""
    with patch("assignment1.main.requests.get") as mock_get:
        # Mock HTTP error
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
        mock_get.return_value = mock_response

        # Should raise HTTPError
        with pytest.raises(requests.HTTPError):
            get_log_entry(99999, debug=False)


def test_get_latest_checkpoint_success():
    """Test get_latest_checkpoint() with successful API response."""
    with patch("assignment1.main.requests.get") as mock_get:
        # Create mock response - the API returns JSON, not text
        checkpoint_json = {
            "treeSize": 100000,
            "rootHash": "Y7Z3pSC0nPkflzFCfPBFx7E/GYvY7xvQw6J8sWx+nKY=",
            "timestamp": 1234567890,
        }
        mock_response = Mock()
        mock_response.json.return_value = checkpoint_json
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Call the function
        result = get_latest_checkpoint(debug=False)

        # Verify result structure
        assert "treeSize" in result
        assert "rootHash" in result
        assert result["treeSize"] == 100000


def test_get_latest_checkpoint_connection_error():
    """Test get_latest_checkpoint() handles connection errors."""
    with patch("assignment1.main.requests.get") as mock_get:
        # Mock connection error
        mock_get.side_effect = requests.ConnectionError("Connection refused")

        # Should raise ConnectionError
        with pytest.raises(requests.ConnectionError):
            get_latest_checkpoint(debug=False)


def test_get_log_entry_with_debug(capsys):
    """Test get_log_entry() with debug mode enabled."""
    with patch("assignment1.main.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "test-uuid": {
                "logIndex": 123,
                "body": "test-body",
                "integratedTime": 1234567890,
                "verification": {
                    "inclusionProof": {
                        "logIndex": 123,
                        "rootHash": "a" * 64,
                        "treeSize": 1000,
                        "hashes": ["hash1", "hash2"],
                    }
                },
            }
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = get_log_entry(123, debug=True)

        # Should print debug info
        captured = capsys.readouterr()
        assert "test-uuid" in result


def test_get_verification_proof_success():
    """Test get_verification_proof() extracts proof correctly."""
    from assignment1.main import get_verification_proof

    log_entry = {
        "test-uuid": {
            "verification": {
                "inclusionProof": {
                    "logIndex": 123,
                    "rootHash": "a" * 64,
                    "treeSize": 1000,
                    "hashes": ["hash1", "hash2"],
                }
            }
        }
    }

    proof = get_verification_proof(log_entry)

    assert proof["logIndex"] == 123
    assert proof["rootHash"] == "a" * 64
    assert proof["treeSize"] == 1000


def test_get_verification_proof_empty():
    """Test get_verification_proof() raises error on empty entry."""
    from assignment1.main import get_verification_proof

    with pytest.raises(ValueError, match="can't be empty"):
        get_verification_proof({})


def test_inclusion_success(tmp_path):
    """Test inclusion() with successful verification."""
    from assignment1.main import inclusion

    # Create a temporary artifact file
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("test artifact content")

    with (
        patch("assignment1.main.validate_log_index") as mock_validate,
        patch("assignment1.main.get_log_entry") as mock_get_entry,
        patch("assignment1.main.get_user_auth") as mock_auth,
        patch("assignment1.main.extract_public_key") as mock_extract,
        patch("assignment1.main.verify_artifact_signature") as mock_verify_sig,
        patch("assignment1.main.verify_inclusion") as mock_verify_inc,
    ):
        # Setup mocks
        mock_validate.return_value = True
        mock_get_entry.return_value = {
            "test-uuid": {
                "body": "dGVzdCBkYXRh",  # base64 "test data"
                "verification": {
                    "inclusionProof": {
                        "logIndex": 123,
                        "rootHash": "a" * 64,
                        "treeSize": 1000,
                        "hashes": ["hash1", "hash2"],
                    }
                },
            }
        }
        mock_auth.return_value = (b"signature", b"cert")
        mock_extract.return_value = b"public_key"
        mock_verify_sig.return_value = None
        mock_verify_inc.return_value = None

        # Test inclusion
        result = inclusion(123, str(artifact), debug=False)

        assert result is True
        mock_validate.assert_called_once()
        mock_verify_sig.assert_called_once()


def test_inclusion_invalid_log_index():
    """Test inclusion() with invalid log index."""
    from assignment1.main import inclusion

    with patch("assignment1.main.validate_log_index") as mock_validate:
        mock_validate.return_value = False

        result = inclusion(99999, "/fake/path", debug=False)

        assert result is False


def test_inclusion_invalid_artifact_path():
    """Test inclusion() with nonexistent artifact path."""
    from assignment1.main import inclusion

    with patch("assignment1.main.validate_log_index") as mock_validate:
        mock_validate.return_value = True

        result = inclusion(123, "/nonexistent/path", debug=False)

        assert result is False


def test_inclusion_network_error():
    """Test inclusion() handles network errors gracefully."""
    from assignment1.main import inclusion

    with (
        patch("assignment1.main.validate_log_index") as mock_validate,
        patch("assignment1.main.validate_artifact_path") as mock_val_path,
        patch("assignment1.main.get_log_entry") as mock_get_entry,
    ):
        mock_validate.return_value = True
        mock_val_path.return_value = True
        mock_get_entry.side_effect = requests.RequestException("Network error")

        result = inclusion(123, "/some/path", debug=False)

        assert result is False


def test_consistency_success():
    """Test consistency() with successful verification."""
    from assignment1.main import consistency

    prev_checkpoint = {"treeID": "test-tree-id", "treeSize": 1000, "rootHash": "a" * 64}

    with (
        patch("assignment1.main.get_latest_checkpoint") as mock_latest,
        patch("assignment1.main.requests.get") as mock_get,
        patch("assignment1.main.verify_consistency") as mock_verify,
    ):
        # Mock latest checkpoint
        mock_latest.return_value = {"treeSize": 2000, "rootHash": "b" * 64}

        # Mock consistency proof response
        mock_response = Mock()
        mock_response.json.return_value = {"hashes": ["hash1", "hash2", "hash3"]}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        mock_verify.return_value = None

        result = consistency(prev_checkpoint, debug=False)

        assert result is True
        mock_verify.assert_called_once()


def test_consistency_invalid_tree_size():
    """Test consistency() with invalid tree size."""
    from assignment1.main import consistency

    prev_checkpoint = {
        "treeID": "test-tree-id",
        "treeSize": -1,  # Invalid
        "rootHash": "a" * 64,
    }

    with patch("assignment1.main.get_latest_checkpoint") as mock_latest:
        mock_latest.return_value = {"treeSize": 2000, "rootHash": "b" * 64}

        result = consistency(prev_checkpoint, debug=False)

        assert result is False


def test_consistency_invalid_root_hash():
    """Test consistency() with invalid root hash."""
    from assignment1.main import consistency

    prev_checkpoint = {
        "treeID": "test-tree-id",
        "treeSize": 1000,
        "rootHash": "invalid",  # Too short
    }

    with patch("assignment1.main.get_latest_checkpoint") as mock_latest:
        mock_latest.return_value = {"treeSize": 2000, "rootHash": "b" * 64}

        result = consistency(prev_checkpoint, debug=False)

        assert result is False


def test_consistency_network_error():
    """Test consistency() handles network errors."""
    from assignment1.main import consistency

    prev_checkpoint = {"treeID": "test-tree-id", "treeSize": 1000, "rootHash": "a" * 64}

    with patch("assignment1.main.get_latest_checkpoint") as mock_latest:
        mock_latest.side_effect = requests.RequestException("Network error")

        result = consistency(prev_checkpoint, debug=False)

        assert result is False


def test_inclusion_with_debug(tmp_path, capsys):
    """Test inclusion() with debug mode enabled."""
    from assignment1.main import inclusion

    artifact = tmp_path / "artifact.txt"
    artifact.write_text("test content")

    with (
        patch("assignment1.main.validate_log_index") as mock_validate,
        patch("assignment1.main.get_log_entry") as mock_get_entry,
        patch("assignment1.main.get_user_auth") as mock_auth,
        patch("assignment1.main.extract_public_key") as mock_extract,
        patch("assignment1.main.verify_artifact_signature") as mock_verify_sig,
        patch("assignment1.main.verify_inclusion") as mock_verify_inc,
    ):
        mock_validate.return_value = True
        mock_get_entry.return_value = {
            "uuid": {
                "body": "dGVzdA==",
                "verification": {
                    "inclusionProof": {
                        "logIndex": 123,
                        "rootHash": "a" * 64,
                        "treeSize": 1000,
                        "hashes": ["hash1"],
                    }
                },
            }
        }
        mock_auth.return_value = (b"sig", b"cert")
        mock_extract.return_value = b"key"
        mock_verify_sig.return_value = None
        mock_verify_inc.return_value = None

        result = inclusion(123, str(artifact), debug=True)

        captured = capsys.readouterr()
        assert "validated" in captured.out.lower()
        assert result is True


def test_consistency_with_debug(capsys):
    """Test consistency() with debug mode enabled."""
    from assignment1.main import consistency

    prev_checkpoint = {"treeID": "test-id", "treeSize": 1000, "rootHash": "a" * 64}

    with (
        patch("assignment1.main.get_latest_checkpoint") as mock_latest,
        patch("assignment1.main.requests.get") as mock_get,
        patch("assignment1.main.verify_consistency") as mock_verify,
    ):
        mock_latest.return_value = {"treeSize": 2000, "rootHash": "b" * 64}

        mock_response = Mock()
        mock_response.json.return_value = {"hashes": ["h1", "h2"]}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        mock_verify.return_value = None

        result = consistency(prev_checkpoint, debug=True)

        captured = capsys.readouterr()
        assert "consistency" in captured.out.lower()
        assert result is True


def test_get_latest_checkpoint_with_debug(tmp_path):
    """Test get_latest_checkpoint() saves to file in debug mode."""
    from assignment1.main import get_latest_checkpoint
    import os

    # Change to temp directory
    orig_dir = os.getcwd()
    os.chdir(tmp_path)

    try:
        with patch("assignment1.main.requests.get") as mock_get:
            mock_response = Mock()
            mock_response.json.return_value = {"test": "data"}
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response

            result = get_latest_checkpoint(debug=True)

            # Should create checkpoint.json
            assert (tmp_path / "checkpoint.json").exists()
            assert result == {"test": "data"}
    finally:
        os.chdir(orig_dir)
