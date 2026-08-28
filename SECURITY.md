# Security Policy

`paseto-zig` is a security-sensitive library, but it has not undergone a
formal third-party cryptographic audit.

## Supported Versions

Security fixes are prepared against the current `main` branch and the latest
tagged release. The package currently supports Zig `0.16.0` as its stable
baseline; compatibility with newer development snapshots is tested opportunely
and documented in the README.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately by opening a GitHub security
advisory for the repository, or by contacting the maintainer through the
private contact listed on the GitHub profile if advisories are unavailable.

Include:

- The affected version or commit.
- A minimal reproducer or malformed token/PASERK when possible.
- Whether the issue affects confidentiality, integrity, authentication,
  availability, or key handling.

Do not publish exploit details until a fix or mitigation is available.

## Disclosure Targets

The project aims to acknowledge reports within 7 days, provide an initial
impact assessment within 14 days, and publish a fix or mitigation as soon as a
safe release can be prepared.
