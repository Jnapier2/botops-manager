# Security Policy

## Supported version

Security reports are evaluated against the current `main` branch and the latest tagged release.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting if it is enabled for this repository. Otherwise, contact the maintainer through the GitHub profile and request a private reporting channel. Do not post credentials, private logs, proof-of-concept secrets, or exploit details in a public issue.

Include the affected version, operating system, reproduction steps, expected boundary, observed behavior, and a minimal sanitized fixture.

## Operational boundary

BotOps Manager does not need child-project credentials. Keep secrets outside this repository and outside support exports. Review every launcher before enabling control, and use monitor-only mode for processes BotOps did not start. Force termination is disabled in the public edition; use only reviewed, project-scoped stop scripts.
