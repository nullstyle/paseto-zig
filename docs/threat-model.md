# Threat model

Scope and attacker model for `paseto-zig`, maintained alongside
[`docs/security-audit.md`](security-audit.md) (which maps defenses to code
and tests). This document is the "what are we defending against" half.

## What this library is

A PASETO v3/v4 token and PASERK key-management library consumed three ways:

1. **Native verification path** — a server (the primary downstream consumer
   is qmsg) feeds token strings received from unauthenticated network peers
   into `token.parse` → `v4.Public.verify` / `v4.Local.decrypt` →
   `Validator.validate`, using PASERK IDs for key selection.
2. **Freestanding WASM module** — a JS host (Deno or browser packages)
   instantiates `paseto.wasm` and calls its packed ABI for v4.local
   seal/open and `k4.lid` derivation.
3. **Operator tooling** — PEM/DER private keys and passwords are imported
   or wrapped via `paseto.pem` and the PBKW surface.

## Assets

| Asset | Loss consequence |
| --- | --- |
| Symmetric keys / private key material (v4 seeds, v3 scalars) | Token forgery, plaintext recovery |
| Derived subkeys, PAE buffers, decrypted plaintexts | Plaintext recovery, key recovery via side channels |
| Token authenticity decisions | Authorization bypass (the qmsg HELLO credential path) |
| Availability of the verifying process | DoS of the auth path |

## Actors and trust boundaries

### 1. Network peer — fully untrusted

Supplies token and PASERK strings, byte for byte attacker-chosen.

**Must not achieve:** forgery, plaintext recovery, key recovery, key
selection confusion, crash, or unbounded resource consumption.

Defenses: header/purpose validated by full-string equality before any
crypto; PAE binds header, payload, footer, and implicit assertion;
authentication verified before plaintext release; all comparisons of
secret-derived data constant-time; every parser enforces size caps
(1 MiB token, 4096-byte PASERK, 64 KiB claims/PEM) before decoding or
allocating; decoded size never exceeds encoded size; PBKW wire parameters
validated against the production policy before the KDF runs, bounding each
attempt to one policy-maximum Argon2id/PBKDF2 evaluation. See the audit
checklist for per-entry-point dispositions and pinning tests.

Residual: PBKW unwrap inherently costs one KDF per attempt even on garbage
input — callers exposed to unauthenticated peers must rate-limit (documented
in `SECURITY.md`). Token replay is out of scope for the library; the
`Validator` provides `exp`/`nbf`/`iat` window checks, and replay caches are
the caller's responsibility.

### 2. WASM host — semi-trusted

Supplies every pointer, length, frame, and nonce to the module. The module
does not import randomness by design.

**Model:** the host is the *operator* of the module (it holds the keys it
passes in), so confidentiality against the host itself is not a goal. The
boundaries that do matter: pointer/length range validation (low-memory
pointers rejected, overflow-checked extents, exact frame consumption) so a
compromised *loader* or a buggy host cannot corrupt the module's arena; and
full-arena wiping between operations so key material does not persist in
linear memory after `resetAllocator`.

Residual: a host that repeats nonces with the same key breaks
confidentiality on its own — this is inherent to the host-supplied-nonce
contract and documented in `docs/wasm.md`.

### 3. Operator — trusted but fallible

Imports PEM/DER keys, chooses passwords and PBKW parameters.

Defenses: strict single-block PEM framing; DER walker rejects indefinite
and over-long length forms, truncated and trailing bytes; OID whitelists;
key material validated after decode (curve, point, seed consistency);
PBKW wrap refuses parameters outside the production policy. Deterministic
`nonce`/`salt`/`ephemeral_override` options exist for vectors and fuzzing
and are documented as confidentiality-breaking if misused in production.

### 4. Downstream builder — trusted

Consumes the published tarball with stable or dev Zig toolchains. Defenses:
dual-toolchain `build.zig`, the dev-snapshot CI canary, and the
release-hygiene check that the tag, zon version, and README pin agree.

## Explicitly out of scope

- Physical attacks, side channels beyond timing of public-data comparisons,
  and microarchitectural attacks against Zig std primitives.
- Protecting key material in the *caller's* memory after the library hands
  it over (raw `decrypt`/`verify` results are wiped only via the owning
  `deinit`/`secureFree` helpers; the README states this discipline).
- Caller-side concerns: key storage, rotation logistics, replay caching,
  rate limiting of PBKW attempts, transport security.
- `v2` purposes and the `code` purpose family — not implemented.

## Verification posture

Spec conformance: official PASETO/PASERK vector suite (17 files) in CI.
Cross-implementation: fresh ruby-paseto fixtures (tokens, PIE/PKE/PBKW)
verified in CI. Adversarial: 14 deterministic fuzz harnesses with
corpus/regression promotion, nightly mutation soaks on the parser,
envelope, and scenario groups, and a first-party audit checklist mapped to
spec sections. What has **not** happened: a formal third-party
cryptographic audit (see `SECURITY.md`).
