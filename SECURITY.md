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

## Known Security Posture

These are documented behaviors, not vulnerabilities:

- **PBKW unwrap work factor.** Password-based unwrap must run Argon2id (v4)
  or PBKDF2 (v3) before the authentication tag can be checked, so a malicious
  `k4.local-pw.`-style string forces one KDF invocation per unwrap attempt.
  Wire-controlled parameters are validated against the production policy
  (v4: 64–256 MiB / opslimit 2–3 / `para == 1`; v3: 1,000–10,000 iterations)
  before the KDF runs, bounding each attempt to policy maximum. Callers
  exposed to unauthenticated peers should rate-limit unwrap attempts.
- **Claims comparison timing.** Registered-claim checks (`iss`, `aud`,
  `sub`, `jti`) compare attacker-supplied claim values against expected
  values with constant-time equality (the `aud` list is scanned in full,
  with no early exit). Claim lengths and the outcome itself remain
  observable, which is inherent to returning a typed validation error.
- **Deterministic overrides.** The `nonce`, `salt`, and
  `ephemeral_override` options exist for vectors and fuzzing. Reusing a
  deterministic nonce with the same key breaks confidentiality; production
  callers must leave them unset.

A full checklist of the untrusted-input audit performed for this release,
mapped to spec sections and tests, is maintained in
[`docs/security-audit.md`](docs/security-audit.md); the attacker model and
trust boundaries it assumes are documented in
[`docs/threat-model.md`](docs/threat-model.md).
