## 2025-12-16 - Path Traversal in File Operations
**Vulnerability:** The application used unvalidated usernames to construct file paths for key storage (`username + ".pem"`), allowing path traversal (e.g., `../etc/passwd`).
**Learning:** File operations based on user input must always be validated or sanitized to prevent accessing unauthorized files.
**Prevention:** Implemented strict whitelist validation (`^[a-zA-Z0-9_]+$`) for usernames in `CryptoUtils.isValidUsername` and applied it before any file operations.
