## 2025-12-17 - Path Traversal in File Storage
**Vulnerability:** Path traversal vulnerability in key storage mechanism. Usernames were directly concatenated with file extensions (`username + ".pem"`), allowing attackers to potentially write or read files outside the intended directory using `../` patterns.
**Learning:** File system operations based on user input create tight coupling between input validation and security. Simple string concatenation for filenames is inherently dangerous without strict allowlisting.
**Prevention:** Enforce strict allowlists (e.g., `^[a-zA-Z0-9_]+$`) for any user input used in file paths. Centralize this validation to ensure consistency across all entry points (Login, Register).
