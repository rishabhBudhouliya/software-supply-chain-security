"""
Test suite for util.py - Utility and validation functions.

Note: Test structure and implementation assisted by Claude AI (Anthropic).
Reviewed, understood, and verified by Rishabh Budhouliya.
"""

from unittest.mock import Mock, patch

import pytest

from assignment1.util import (
    validate_artifact_path,
    validate_log_index,
    validate_root_hash,
    validate_tree_size,
)


def test_validate_log_index_valid_with_mock():
    """Test that valid log indices are accepted when API responds successfully."""
    with patch("assignment1.util.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Test with various valid indices
        assert validate_log_index(0, debug=False) is True
        assert validate_log_index(1, debug=False) is True
        assert validate_log_index(100, debug=False) is True


def test_validate_log_index_negative():
    """Test that negative log indices raise ValueError."""
    with pytest.raises(ValueError, match="Log index should be a non-negative integer"):
        validate_log_index(-1, debug=False)

    with pytest.raises(ValueError, match="Log index should be a non-negative integer"):
        validate_log_index(-100, debug=False)


def test_validate_log_index_not_integer():
    """Test that non-integer log indices raise ValueError."""
    with pytest.raises(ValueError, match="Log index should be a non-negative integer"):
        validate_log_index("123", debug=False)  # type: ignore[arg-type]


def test_validate_tree_size_valid():
    """Test that valid tree sizes are accepted."""
    assert validate_tree_size(0) is True
    assert validate_tree_size(1) is True
    assert validate_tree_size(100) is True
    assert validate_tree_size(1000000) is True


def test_validate_tree_size_invalid():
    """Test that invalid tree sizes raise ValueError."""
    with pytest.raises(ValueError, match="Tree size should be a non-negative integer"):
        validate_tree_size(-1)

    with pytest.raises(ValueError, match="Tree size should be a non-negative integer"):
        validate_tree_size(-100)

    with pytest.raises(ValueError, match="Tree size should be a non-negative integer"):
        validate_tree_size("100")  # type: ignore[arg-type]


def test_validate_root_hash_valid():
    """Test that valid root hashes are accepted."""
    # Valid 64-character hex string
    valid_hash = "a" * 64
    assert validate_root_hash(valid_hash) is True

    # Another valid hash with mixed characters
    valid_hash2 = "0123456789abcdef" * 4
    assert validate_root_hash(valid_hash2) is True

    # Uppercase should also work
    valid_hash3 = "ABCDEF0123456789" * 4
    assert validate_root_hash(valid_hash3) is True


def test_validate_root_hash_invalid_length():
    """Test that root hashes with invalid length are rejected."""
    # Too short
    assert validate_root_hash("a" * 63) is False

    # Too long
    assert validate_root_hash("a" * 65) is False

    # Empty
    assert validate_root_hash("") is False


def test_validate_root_hash_invalid_characters():
    """Test that root hashes with non-hex characters are rejected."""
    # Contains invalid characters
    invalid_hash = "g" * 64
    assert validate_root_hash(invalid_hash) is False

    # Mix of valid and invalid
    invalid_hash2 = "xyz123" * 10 + "abcd"
    assert validate_root_hash(invalid_hash2) is False


def test_validate_root_hash_non_string():
    """Test that non-string root hashes are rejected."""
    assert validate_root_hash(123) is False  # type: ignore[arg-type]
    assert validate_root_hash(None) is False  # type: ignore[arg-type]


def test_validate_artifact_path_valid(tmp_path):
    """Test that valid file paths are accepted."""
    # Create a temporary file
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")

    # Should not raise any exception
    assert validate_artifact_path(str(test_file)) is True


def test_validate_artifact_path_nonexistent():
    """Test that nonexistent file paths raise ValueError."""
    with pytest.raises(ValueError, match="doesn't exist"):
        validate_artifact_path("/nonexistent/path/to/file.txt")


def test_validate_artifact_path_empty():
    """Test that empty paths raise ValueError."""
    with pytest.raises(ValueError, match="can't be empty"):
        validate_artifact_path("")


def test_validate_log_index_http_404():
    """Test validate_log_index when API returns 404."""
    with patch("assignment1.util.requests.get") as mock_get:
        # Create a proper HTTPError
        import requests

        mock_response = Mock()
        mock_response.status_code = 404
        http_error = requests.HTTPError("404 Not Found")
        http_error.response = mock_response

        mock_response.raise_for_status.side_effect = http_error
        mock_get.return_value = mock_response

        # Should return False for 404
        result = validate_log_index(99999, debug=False)
        assert result is False


def test_validate_log_index_network_error():
    """Test validate_log_index when network call fails."""
    with patch("assignment1.util.requests.get") as mock_get:
        mock_get.side_effect = Exception("Network error")

        # Should return False and handle the exception
        result = validate_log_index(123, debug=False)
        assert result is False


def test_get_user_auth():
    """Test get_user_auth() extracts signature and certificate."""
    import base64
    import json

    from assignment1.util import get_user_auth

    # Create a sample log entry structure
    signature_content = base64.b64encode(b"test_signature").decode("utf-8")
    public_key_content = base64.b64encode(b"test_public_key").decode("utf-8")

    body_data = {
        "spec": {
            "signature": {
                "content": signature_content,
                "publicKey": {"content": public_key_content},
            }
        }
    }

    body_json = json.dumps(body_data)
    body_encoded = base64.b64encode(body_json.encode("utf-8")).decode("utf-8")

    log_entry = {"test-uuid-123": {"body": body_encoded}}

    # Extract auth data
    signature, public_cert = get_user_auth(log_entry)

    # Verify extraction
    assert signature == b"test_signature"
    assert public_cert == b"test_public_key"
