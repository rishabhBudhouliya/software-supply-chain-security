# Contributing to Rekor Verifier

Thank you for your interest in contributing to Rekor Verifier! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors
- Follow professional communication standards

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git
- Poetry (for dependency management)

### Setting Up Development Environment

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/yourusername/software-supply-chain-security.git
   cd software-supply-chain-security
   ```

2. **Install Poetry**
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

3. **Install dependencies**
   ```bash
   poetry install
   ```

4. **Install pre-commit hooks**
   ```bash
   poetry run pre-commit install
   ```

5. **Verify setup**
   ```bash
   poetry run pytest
   poetry run mypy assignment1/
   ```

## How to Contribute

### Types of Contributions

We welcome:

- **Bug fixes**: Fix issues or incorrect behavior
- **Features**: Add new functionality
- **Documentation**: Improve README, docstrings, or comments
- **Tests**: Increase test coverage
- **Performance**: Optimize code performance
- **Security**: Fix security vulnerabilities

### Before Starting Work

1. **Check existing issues**: Look for related issues or PRs
2. **Create an issue**: Discuss major changes before implementing
3. **Get assignment**: Comment on an issue to claim it
4. **Create a branch**: Use descriptive branch names

## Pull Request Process

### 1. Create a Feature Branch

Use descriptive branch names:

```bash
# Feature
git checkout -b feature/add-batch-verification

# Bug fix
git checkout -b fix/merkle-tree-calculation

# Documentation
git checkout -b docs/update-api-examples
```

### 2. Make Your Changes

- Write clean, readable code
- Follow the coding standards (see below)
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 3. Test Your Changes

```bash
# Run tests
poetry run pytest

# Check test coverage (must be >=75%)
poetry run pytest --cov=assignment1 --cov-report=term-missing

# Run type checker
poetry run mypy assignment1/

# Run linters
poetry run ruff check assignment1/
poetry run pylint assignment1/*.py

# Run security scanner
poetry run bandit -r assignment1/

# Run formatter
poetry run ruff format assignment1/
```

### 4. Commit Your Changes

- Use clear, descriptive commit messages
- Follow conventional commit format:

```
type(scope): brief description

Detailed explanation of what changed and why.

Fixes #issue_number
```

**Commit types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or changes
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

**Examples**:
```bash
git commit -m "feat(merkle): add batch verification support

Implements batch verification for multiple inclusion proofs
to improve performance when verifying many artifacts.

Fixes #42"
```

```bash
git commit -m "fix(util): handle empty certificate chain

Added validation to prevent crashes when certificate
chain is empty or malformed.

Fixes #38"
```

### 5. Push and Create Pull Request

```bash
git push origin your-branch-name
```

Then create a PR on GitHub with:

- **Clear title**: Summarize the change
- **Description**: Explain what, why, and how
- **Issue reference**: Link to related issues
- **Testing**: Describe how you tested
- **Checklist**: Complete the PR template

### PR Review Process

1. Automated checks must pass (tests, linting, coverage)
2. Code review by maintainer
3. Address review feedback
4. Approval and merge

## Coding Standards

### Python Style Guide

We follow **PEP 8** with these specifications:

- **Line length**: Maximum 100 characters
- **Indentation**: 4 spaces (no tabs)
- **Imports**: Organized in three groups (standard library, third-party, local)
- **Quotes**: Double quotes for strings
- **Naming conventions**:
  - Functions/variables: `snake_case`
  - Classes: `PascalCase`
  - Constants: `UPPER_SNAKE_CASE`

### Type Hints

- **Required** for all function signatures
- Use `typing` module for complex types
- Example:
  ```python
  def verify_inclusion(
      log_index: int,
      artifact_path: str,
      checkpoint: dict[str, Any]
  ) -> bool:
      """Verify artifact inclusion in transparency log."""
      ...
  ```

### Documentation

- **Docstrings required** for all public functions and classes
- Use Google-style docstrings:
  ```python
  def compute_leaf_hash(data: bytes) -> bytes:
      """Compute RFC 6962 leaf hash.

      Args:
          data: Raw data to hash

      Returns:
          SHA256 hash with RFC 6962 leaf prefix

      Raises:
          ValueError: If data is empty
      """
      ...
  ```

### Code Quality Tools

All code must pass:

- **Ruff**: Linting and formatting
- **Pylint**: Additional code quality checks
- **Mypy**: Static type checking
- **Bandit**: Security vulnerability scanning
- **Pre-commit hooks**: Automated checks before commit

## Testing Requirements

### Test Coverage

- **Minimum coverage**: 75%
- **Target coverage**: 85%+
- All new features must include tests

### Writing Tests

- Use **pytest** framework
- Place tests in `tests/` directory
- Name test files: `test_<module>.py`
- Name test functions: `test_<functionality>()`

**Example**:
```python
# tests/test_merkle_proof.py
import pytest
from assignment1.merkle_proof import verify_inclusion

def test_verify_inclusion_valid_proof():
    """Test inclusion verification with valid proof."""
    # Arrange
    log_index = 12345
    proof_hashes = [...]
    root_hash = "..."

    # Act
    result = verify_inclusion(log_index, proof_hashes, root_hash)

    # Assert
    assert result is True

def test_verify_inclusion_invalid_proof():
    """Test inclusion verification with invalid proof."""
    # Arrange
    log_index = 12345
    proof_hashes = ["invalid"]
    root_hash = "..."

    # Act & Assert
    with pytest.raises(ValueError):
        verify_inclusion(log_index, proof_hashes, root_hash)
```

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run specific test file
poetry run pytest tests/test_merkle_proof.py

# Run with coverage
poetry run pytest --cov=assignment1

# Run with verbose output
poetry run pytest -v
```

## Reporting Issues

### Bug Reports

Include:

- **Description**: Clear explanation of the bug
- **Steps to reproduce**: Detailed steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Environment**: Python version, OS, dependencies
- **Logs/Screenshots**: Any relevant output

**Template**:
```markdown
**Bug Description**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: [e.g., macOS 14.0]
- Python: [e.g., 3.11.5]
- Version: [e.g., 3.0]

**Additional Context**
Any other information or logs.
```

## Development Workflow

### Typical Workflow

1. Check issue tracker for tasks
2. Create feature branch
3. Implement changes
4. Write tests
5. Run all quality checks
6. Commit with clear message
7. Push to your fork
8. Create pull request
9. Address review feedback
10. Merge after approval

### Quality Checklist

Before submitting PR:

- [ ] Code follows style guidelines
- [ ] Type hints added for all functions
- [ ] Docstrings added/updated
- [ ] Tests written and passing
- [ ] Coverage >=75%
- [ ] Mypy type checking passes
- [ ] Linting passes (Ruff, Pylint)
- [ ] Security scan passes (Bandit)
- [ ] Pre-commit hooks pass
- [ ] Documentation updated
- [ ] CHANGELOG updated (if applicable)

## Questions?

If you have questions:

- Check existing issues and PRs
- Review the README.md
- Create a discussion thread
- Reach out to maintainers

---

Thank you for contributing to Rekor Verifier!
