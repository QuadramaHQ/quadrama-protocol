# Contributing to Quadrama

Thank you for your interest in contributing to Quadrama.

## Development Philosophy

- Additive changes only — never break existing functionality
- One file at a time — review and test each change independently
- Security first — all changes must maintain or improve the security model
- Document security-relevant changes with a CP number

## How to Contribute

### Reporting Bugs

Open a GitHub issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Browser and OS information

### Security Issues

Do not open public issues for security vulnerabilities.
See SECURITY.md for responsible disclosure.

### Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test in at least two browsers (desktop and mobile)
5. Submit a pull request with a clear description of what changed and why

### Code Style

- Vanilla JavaScript only — no frameworks, no build tools
- Keep comments and CPxx markers for security-relevant code
- Changes to cryptographic code require extra care and justification
