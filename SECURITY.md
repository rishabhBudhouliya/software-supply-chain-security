# Security Policy

## Supported Versions

Currently supported versions of Rekor Verifier:

| Version | Supported          |
| -------- | ------------------ |
| 1.x      | :white_check_mark: |
| < 1.0    | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of the following methods:

1. **Email**: Send details to the repository owner
2. **GitHub Security Advisories**: Use the "Security" tab in this repository to privately report a vulnerability
3. **Private Message**: Contact the maintainer directly through GitHub

### What to Include

When reporting a vulnerability, please include:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact and severity
- Your contact information for follow-up

## Security Best Practices

When using this tool:

1. **Keep dependencies updated**: Regularly update dependencies to get security patches
   ```bash
   pip install --upgrade -r requirements.txt
   ```

2. **Verify signatures**: Always use the inclusion verification feature to validate artifacts

3. **Secure credentials**: Never commit API keys, tokens, or credentials to the repository

4. **Use latest version**: Always use the most recent supported version for security fixes

5. **Review logs**: Monitor debug output for unexpected behavior

## Security Features

This tool implements several security measures:

- **Cryptographic verification**: Uses ECDSA signature verification to validate artifacts
- **Merkle tree validation**: Implements RFC 6962 for tamper-proof transparency log verification
- **Input validation**: Validates all user inputs (log indices, file paths, tree sizes, hashes)
- **Dependency scanning**: Uses Bandit SAST tool for security vulnerability detection
- **Secret scanning**: Pre-commit hooks prevent accidental credential commits

## Security Updates

Security updates are released as:

- **Patch releases** (x.x.X) for minor security fixes
- **Minor releases** (x.X.0) for moderate security improvements
- **Major releases** (X.0.0) for significant security architecture changes

All security updates are documented in the release notes and CHANGELOG.

## Known Security Considerations

1. **Network Security**: This tool communicates with the Rekor API over HTTPS. Ensure your network connection is secure.

2. **Certificate Validation**: The tool validates certificates but relies on the system's trusted certificate store.

3. **Input Sanitization**: While the tool validates inputs, always verify artifact sources before verification.

## Security Tooling

This project uses the following security tools:

- **Bandit**: Python security vulnerability scanner
- **Trufflehog**: Secret scanning to prevent credential leaks
- **Pre-commit hooks**: Automated security checks before commits
- **Mypy**: Static type checking to prevent type-related bugs
- **Pylint/Ruff**: Code quality and security linting

## Contact

For security concerns, please contact the repository maintainer.
---
