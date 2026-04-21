# Zig Built-In Fuzzing Suite Design

**Goal:** Design a complete, local/on-demand fuzz-testing suite for `paseto-zig` using Zig's built-in fuzzing facilities, with enough breadth and throughput to run a Mac Studio at full utilization for long sessions such as 48 hours.

**Status:** Approved design for planning handoff

## Scope

This design covers:
- local, developer-invoked fuzzing only
- Zig built-in fuzzing facilities only
- very deep coverage across parser, serializer, envelope, and scenario boundaries
- fuzz-only helper entrypoints where needed to directly exercise internal logic

This design does not cover:
- CI or nightly automation
- external fuzzing engines or harness generators
- distributed fuzzing orchestration

## Tooling Constraints

The local toolchain is Zig `0.16.0`, which provides:
- `std.testing.fuzz`
- `std.testing.Smith`
- `zig test -ffuzz`
- `zig build test --fuzz[=limit]`
- `zig build test --webui`

The suite should stay entirely within these built-in capabilities.

## Design Principles

1. Prefer many focused fuzz harnesses over one giant state machine.
2. Fuzz every important boundary twice when practical:
   - valid/structured acceptance paths
   - malformed/tampered rejection paths
3. Use seed corpora to start near real protocol shapes.
4. Use `std.testing.Smith` to generate structure-aware inputs, not just raw bytes.
5. Add fuzz-only helpers when internal boundaries are better crash surfaces than public APIs.
6. Optimize for long-run debuggability as much as raw coverage.

## High-Level Architecture

Create a dedicated fuzz subsystem under `tests/fuzz/` with:
- one harness file per semantic domain
- one shared support module for corpus loading, mutation helpers, deterministic repro plumbing, and size limits
- build graph support in `build.zig` for grouped fuzz runs

The suite should be organized into three groups:

1. **Parsers**
   - cheapest and highest-throughput targets
   - string/byte decoders, timestamp parsing, PEM/DER parsing, header parsing

2. **Envelopes**
   - protocol-aware token and PASERK consumers
   - wrap/unwrap, seal/unseal, sign/verify, encrypt/decrypt parsing and rejection behavior

3. **Scenarios**
   - multi-step cross-module invariants
   - lower throughput, higher semantic coverage

## Surface Map

### 1. Token Parsing Harness

**Target:** `src/token.zig`

**Purpose:** Exercise raw PASETO token framing.

**Coverage:**
- arbitrary segmented strings
- missing/extra dots
- unsupported versions and purposes
- malformed base64 payload/footer
- valid generated tokens followed by mutation

**Core invariants:**
- parse never panics
- successful `parse -> serialize -> parse` preserves header/payload/footer
- malformed inputs fail with declared errors only

### 2. Utility Codec Harness

**Target:** `src/util.zig`

**Purpose:** Hammer low-level encoding and framing primitives.

**Coverage:**
- base64url decoding
- hex decoding
- PAE construction
- concatenation boundaries

**Core invariants:**
- valid encode/decode round-trips
- malformed inputs reject cleanly
- large-but-bounded lengths do not cause undefined behavior

### 3. Claims Harness

**Target:** `src/claims.zig`

**Purpose:** Exercise JSON claim validation and timestamp parsing.

**Coverage:**
- arbitrary JSON objects and non-objects
- timestamp strings
- wrong claim types
- registered claim combinations
- mixed valid/invalid temporal relationships

**Core invariants:**
- validation never panics
- invalid JSON/time syntax rejects cleanly
- accepted timestamps parse consistently
- required claim handling stays type-safe

### 4. PEM/DER Harness

**Target:** `src/pem.zig`

**Purpose:** Exercise framed PEM parsing and tiny DER walker logic.

**Coverage:**
- garbage before/after PEM blocks
- malformed base64 bodies
- truncated DER
- bad tags, lengths, and OIDs
- concatenated PEM documents
- trailing bytes after valid structures

**Core invariants:**
- parser never panics
- only supported key shapes succeed
- reported formats and byte lengths always match contract

### 5. PASERK Keys Harness

**Target:** `src/paserk/keys.zig`

**Purpose:** Exercise key PASERK serialization/parsing and length gates.

**Coverage:**
- arbitrary PASERK strings
- wrong version/kind prefixes
- length mismatch cases
- valid generated raw key material

**Core invariants:**
- valid `serialize -> parse` is stable
- invalid lengths/prefixes never partially succeed

### 6. PASERK PIE Harness

**Target:** `src/paserk/pie.zig`

**Purpose:** Exercise symmetric wrapping envelopes.

**Coverage:**
- valid wrap/unwrap across v3/v4 and local/secret kinds
- tampered header/tag/nonce/body
- wrong wrapping keys
- mixed-version misuse

**Core invariants:**
- valid unwrap reproduces exact wrapped bytes
- tampering flips success to clean rejection
- no panic or allocator misuse on malformed bodies

### 7. PASERK PKE Harness

**Target:** `src/paserk/pke.zig`

**Purpose:** Exercise sealing envelopes and asymmetric decoding paths.

**Coverage:**
- valid seal/unseal
- wrong-version envelopes
- invalid key encodings
- malformed body sizes
- tag and ephemeral key mutations

**Core invariants:**
- valid unseal restores original 32-byte local key
- invalid inputs never produce out-of-contract output lengths
- wrong key material never succeeds silently

### 8. PASERK PBKW Harness

**Target:** `src/paserk/pbkw.zig`

**Purpose:** Exercise password-wrapping bodies and parameter parsing.

**Coverage:**
- valid wrap/unwrap with reduced fuzz-mode cost settings
- malformed headers and body lengths
- corrupted salt/nonce/tag/body
- weak or edge-case parameters

**Core invariants:**
- valid unwrap restores exact bytes
- malformed or weak parameter cases reject cleanly
- fuzz mode must keep parameters throughput-friendly

### 9. v4.local Harness

**Target:** `src/v4/local.zig`

**Purpose:** Exercise high-level authenticated encryption API.

**Coverage:**
- generated message/footer/assertion combinations
- wrong key decrypt attempts
- token mutation after valid generation
- deterministic nonce helper paths

**Core invariants:**
- valid encrypt/decrypt round-trips
- tampering or wrong-key use rejects cleanly
- decrypt never crashes on malformed token strings

### 10. v4.public Harness

**Target:** `src/v4/public.zig`

**Purpose:** Exercise signing/verification and key constructor surfaces.

**Coverage:**
- valid sign/verify
- wrong-key verification
- footer/assertion/signature mutations
- public/secret constructor misuse

**Core invariants:**
- valid sign/verify round-trips
- wrong key or tampering rejects
- malformed key material does not partially initialize unsafe state

### 11. v3.public Harness

**Target:** `src/v3/public.zig`

**Purpose:** Exercise P-384 signing/verification and key parsing.

**Coverage:**
- valid sign/verify
- wrong-key verification
- compressed/uncompressed public key constructors
- signature/footer/assertion mutation

**Core invariants:**
- valid sign/verify round-trips
- invalid point encodings reject cleanly
- tampering never verifies

### 12. v3.local Harness

**Target:** `src/v3/local.zig`

**Purpose:** Exercise high-level authenticated encryption for the v3 local API.

**Coverage:**
- generated message/footer/assertion combinations
- wrong key decrypt attempts
- token mutation after valid generation
- deterministic nonce helper paths

**Core invariants:**
- valid encrypt/decrypt round-trips
- tampering or wrong-key use rejects cleanly
- decrypt never crashes on malformed token strings

### 13. PASERK ID Harness

**Target:** `src/paserk/id.zig`

**Purpose:** Exercise deterministic PASERK identifier derivation and header construction.

**Coverage:**
- valid local/secret/public key material for v3/v4
- wrong-length key material
- repeated computation on identical inputs
- computation across all `lid` / `sid` / `pid` variants

**Core invariants:**
- identical inputs always produce identical IDs
- IDs always carry the correct `k3` / `k4` and `lid` / `sid` / `pid` prefix
- wrong-length inputs reject with declared key-length errors

### 14. Scenario Harness

**Targets:** cross-module workflows

**Purpose:** Cover cross-boundary invariants not visible to isolated fuzzers.

**Coverage:**
- key generation
- token issuance and consumption
- PASERK serialization and parsing
- wrap/unwrap, seal/unseal, sign/verify, encrypt/decrypt
- intentional mixed-version and mixed-purpose misuse

**Core invariants:**
- `serialize -> parse`
- `encrypt -> decrypt`
- `sign -> verify`
- `wrap -> unwrap`
- `seal -> unseal`
- misuse rejects cleanly

**Concrete scenario grammar:**
- The scenario harness should generate short bounded programs, not arbitrary open-ended workflows.
- The scenario harness should not invent arbitrary programs. It should randomly choose from a fixed menu of scenario families.
- Bound every scenario to exactly one of the following families:
  - `local_round_trip`
  - `public_round_trip`
  - `local_mutation_reject`
  - `public_mutation_reject`
  - `paserk_key_round_trip`
  - `pie_round_trip`
  - `pke_round_trip`
  - `pbkw_round_trip`
  - `mixed_version_misuse`
  - `mixed_purpose_misuse`
- Bound the operation count per scenario family to the exact sequence listed below. Do not generate extra operations.

**Exact scenario families:**

1. `local_round_trip`
   - variants: `v3.local`, `v4.local`
   - operations:
     - construct one local key
     - generate message, footer, implicit assertion
     - encrypt
     - decrypt with the same key and assertion
   - expected result:
     - decrypt succeeds and recovered plaintext matches message exactly

2. `public_round_trip`
   - variants: `v3.public`, `v4.public`
   - operations:
     - construct one signing keypair
     - generate message, footer, implicit assertion
     - sign
     - verify with matching public key and assertion
   - expected result:
     - verify succeeds and recovered payload matches message exactly

3. `local_mutation_reject`
   - variants: `v3.local`, `v4.local`
   - operations:
     - run `local_round_trip`
     - mutate exactly one field of the produced token:
       - header byte
       - payload byte
       - footer byte
       - authenticator byte
       - append extra separator segment
     - attempt decrypt with original key and assertion
   - expected result:
     - decrypt fails with an allowed local-token rejection error

4. `public_mutation_reject`
   - variants: `v3.public`, `v4.public`
   - operations:
     - run `public_round_trip`
     - mutate exactly one field of the produced token:
       - header byte
       - payload byte
       - footer byte
       - signature byte
       - append extra separator segment
     - attempt verify with original public key and assertion
   - expected result:
     - verify fails with an allowed public-token rejection error

5. `paserk_key_round_trip`
   - variants:
     - `k3.local`
     - `k3.public`
     - `k3.secret`
     - `k4.local`
     - `k4.public`
     - `k4.secret`
   - operations:
     - generate raw key material of the exact required length
     - serialize to PASERK
     - parse back
   - expected result:
     - parse succeeds and recovered bytes equal original bytes exactly

6. `pie_round_trip`
   - variants:
     - `v3 local-wrap`
     - `v3 secret-wrap`
     - `v4 local-wrap`
     - `v4 secret-wrap`
   - operations:
     - generate wrapping key and plaintext key bytes
     - wrap
     - unwrap with same wrapping key
   - expected result:
     - unwrap succeeds and recovered bytes equal original plaintext key bytes exactly

7. `pke_round_trip`
   - variants:
     - `v3 seal`
     - `v4 seal`
   - operations:
     - construct recipient key material
     - generate 32-byte local key
     - seal
     - unseal with matching recipient secret
   - expected result:
     - unseal succeeds and recovered local key equals original bytes exactly

8. `pbkw_round_trip`
   - variants:
     - `k3.local-pw`
     - `k3.secret-pw`
     - `k4.local-pw`
     - `k4.secret-pw`
   - operations:
     - generate password and plaintext key bytes
     - choose bounded fuzz-mode cost parameters
     - wrap
     - unwrap with same password
   - expected result:
     - unwrap succeeds and recovered bytes equal original plaintext key bytes exactly

9. `mixed_version_misuse`
   - operations:
     - produce one valid token or PASERK in one version
     - attempt to consume it through the opposite version's API
   - expected result:
     - operation fails with an allowed version or purpose mismatch error

10. `mixed_purpose_misuse`
   - operations:
     - produce one valid token in one purpose (`local` or `public`)
     - attempt to consume it through the other purpose's API in the same version
   - expected result:
     - operation fails with an allowed purpose mismatch error

**Scenario state model:**
- Hold a bounded state struct containing optional slots for:
  - one v3 local key
  - one v4 local key
  - one v3 public keypair/public-only key
  - one v4 public keypair/public-only key
  - one token string
  - one PASERK string
  - one footer
  - one implicit assertion
- The generator should not choose arbitrary state transitions. It should populate only the slots required by the selected scenario family.
- Scenario-family preconditions are:
  - `local_round_trip`, `local_mutation_reject`: require one local key slot, one token slot, one footer slot, one implicit assertion slot
  - `public_round_trip`, `public_mutation_reject`: require one public/private keypair slot, one token slot, one footer slot, one implicit assertion slot
  - `paserk_key_round_trip`: require one raw key slot and one PASERK slot
  - `pie_round_trip`: require one wrapping key slot, one plaintext-key slot, and one PASERK slot
  - `pke_round_trip`: require one recipient keypair slot, one plaintext local-key slot, and one PASERK slot
  - `pbkw_round_trip`: require one password slot, one plaintext-key slot, and one PASERK slot
  - `mixed_version_misuse`, `mixed_purpose_misuse`: require one produced artifact slot plus a consumer slot intentionally selected to mismatch
- When an operation is misuse-oriented, the harness must record the exact mismatch class:
  - wrong version
  - wrong purpose
  - wrong key
  - mutated payload
  - mutated authenticator/signature
  - malformed framing

## Input Strategy

Each harness should use both:

### A. Seed Corpus

Use:
- official vectors already present in `tests/vectors/*.json`
- manually curated malformed edge cases
- future minimized crash repros

Each harness gets its own corpus directory. Do not use one shared mega-corpus.

### B. Structured Generation

Use `std.testing.Smith` to generate:
- bounded lengths
- small enums and switches for mutation decisions
- structured strings/byte sequences
- operation sequences for scenario fuzzing

The generator should shape inputs close to valid protocol forms before mutation, rather than generating pure noise.

## Rejection Contract

Every harness should treat the following as success conditions:
- the operation succeeds and all stated invariants hold
- the operation fails with an expected, declared library error for that boundary

Every harness should treat the following as bugs:
- panic
- hang / non-terminating behavior within the harness bounds
- memory leak reported by the test runner
- out-of-bounds behavior, assertion failure, or allocator corruption
- success that violates a stated invariant
- failure with an undeclared or logically impossible error for that boundary

For planning purposes, define harness error contracts as follows.

If an error is not listed for the specific harness operation below, treat it as a bug or a spec drift that must be investigated.

The following errors are globally **not expected** from the currently targeted code paths and should be treated as bugs unless a future design revision explicitly allows them:
- `InvalidHeader`
- `InvalidFooter`
- `InvalidPayload`
- `InvalidImplicitAssertion`
- `InvalidKeyId`
- `InvalidWrappedPurpose`
- `WrongVersion`
- `WeakKey`
- `Io`
- `Overflow`

### Parser harnesses
- `src/token.zig`
  - `parse`
  - acceptable failures: `InvalidToken`, `UnsupportedVersion`, `UnsupportedPurpose`, `InvalidBase64`, `InvalidPadding`
- `src/util.zig`
  - `decodeBase64Alloc`, `hexDecodeAlloc`
  - acceptable failures: `InvalidBase64`, `InvalidPadding`, `InvalidEncoding`
- `src/claims.zig`
  - `Validator.validate`, `parseIsoTimestamp`
  - acceptable failures: `InvalidJson`, `InvalidClaim`, `InvalidTime`, `ExpiredToken`, `InactiveToken`, `ImmatureToken`, `InvalidIssuer`, `InvalidAudience`, `InvalidSubject`, `InvalidTokenIdentifier`
- `src/pem.zig`
  - `pemToDer`, `parse`
  - acceptable failures: `InvalidEncoding`, `InvalidBase64`, `InvalidKey`, `UnsupportedVersion`
- `src/paserk/keys.zig`
  - `parse`
  - acceptable failures: `InvalidEncoding`, `UnsupportedVersion`, `UnsupportedOperation`, `InvalidKey`, `InvalidBase64`, `InvalidPadding`

### Envelope harnesses
- `src/paserk/pie.zig`
  - `unwrap`
  - acceptable failures: `InvalidEncoding`, `UnsupportedVersion`, `UnsupportedOperation`, `InvalidKey`, `InvalidAuthenticator`, `MessageTooShort`, `InvalidBase64`, `InvalidPadding`
- `src/paserk/pke.zig`
  - `unsealV3`, `unsealV4`, `unsealV4FromSecretKey`
  - acceptable failures: `InvalidEncoding`, `InvalidKey`, `InvalidAuthenticator`, `MessageTooShort`, `InvalidBase64`, `InvalidPadding`
- `src/paserk/pbkw.zig`
  - `wrapV3`, `wrapV4`, `unwrap`
  - acceptable failures:
    - for `wrapV3`, `wrapV4`: `InvalidKey`, `WeakParameters`, `Canceled`, `OutOfMemory`
    - for `unwrap`: `InvalidEncoding`, `UnsupportedVersion`, `UnsupportedOperation`, `InvalidKey`, `InvalidAuthenticator`, `MessageTooShort`, `WeakParameters`, `Canceled`, `OutOfMemory`, `InvalidBase64`, `InvalidPadding`

### High-level API harnesses
- `src/v3/local.zig`, `src/v4/local.zig`
  - `decrypt`, `decryptToken`
  - acceptable failures: `InvalidToken`, `WrongPurpose`, `InvalidAuthenticator`, `MessageTooShort`, `InvalidKey`, `InvalidBase64`, `InvalidPadding`, `UnsupportedVersion`, `UnsupportedPurpose`
- `src/v3/public.zig`, `src/v4/public.zig`
  - `verify`, `verifyToken`
  - acceptable failures: `InvalidToken`, `WrongPurpose`, `InvalidSignature`, `InvalidKey`, `InvalidKeyPair`, `MessageTooShort`, `InvalidBase64`, `InvalidPadding`, `UnsupportedVersion`, `UnsupportedPurpose`
- `src/paserk/id.zig`
  - `compute`, `lid`, `sid`, `pid`
  - acceptable failures: `InvalidKey`

### Scenario-family contracts
- `local_round_trip`
  - success only; any error is a bug
- `public_round_trip`
  - success only; any error is a bug
- `paserk_key_round_trip`
  - success only; any error is a bug
- `pie_round_trip`
  - success only; any error is a bug
- `pke_round_trip`
  - success only; any error is a bug
- `pbkw_round_trip`
  - success only for bounded valid parameters; `WeakParameters`, `Canceled`, `OutOfMemory` are bugs in this family because the generator must choose valid, cheap fuzz-mode settings
- `local_mutation_reject`
  - acceptable failures: `InvalidToken`, `WrongPurpose`, `InvalidAuthenticator`, `MessageTooShort`, `InvalidBase64`, `InvalidPadding`, `UnsupportedVersion`, `UnsupportedPurpose`
- `public_mutation_reject`
  - acceptable failures: `InvalidToken`, `WrongPurpose`, `InvalidSignature`, `MessageTooShort`, `InvalidBase64`, `InvalidPadding`, `UnsupportedVersion`, `UnsupportedPurpose`
- `mixed_version_misuse`
  - acceptable failures: `WrongPurpose`, `InvalidEncoding`, `UnsupportedVersion`, `UnsupportedPurpose`, `UnsupportedOperation`, `InvalidToken`
- `mixed_purpose_misuse`
  - acceptable failures: `WrongPurpose`, `InvalidToken`

The implementation plan may refine these per harness, but it should not broaden them casually.

## Fuzz-Only Helper Entry Points

Add internal helper entrypoints where direct fuzzing is more valuable than going through public APIs.

Likely candidates:
- token parser helpers
- timestamp parsing helper
- PEM framing / DER structure helpers
- PASERK body decoders
- mutation helpers for flipping exactly one semantic field at a time

These helpers should:
- live in normal source modules or dedicated fuzz support modules
- be clearly documented as fuzz/test-only support
- not change public API behavior

## Performance Model For 48-Hour Local Runs

The suite should be designed for throughput on a Mac Studio by:
- separating cheap parser fuzzers from expensive scenario fuzzers
- keeping fuzz-mode PBKW parameters intentionally reduced
- bounding generated payload sizes unless a specific harness targets size scaling
- ensuring one slow domain does not bottleneck the entire fuzz run

Long-run execution should be meaningful rather than wasteful:
- parser harnesses maximize crash discovery rate
- envelope harnesses maximize protocol rejection coverage
- scenario harnesses maximize semantic invariant coverage

## Local Developer UX

Expose dedicated grouped steps in `build.zig`:
- `fuzz-parsers`
- `fuzz-envelopes`
- `fuzz-scenarios`
- `fuzz-all`

And support direct long runs with:
- `zig build fuzz-parsers --fuzz`
- `zig build fuzz-envelopes --fuzz`
- `zig build fuzz-all --fuzz`
- optional `--webui`

The suite should also make one-harness repro easy after a crash.

## Corpus And Regression Layout

Recommended layout:

- `tests/fuzz/`
  - harness source files
  - shared helper module(s)
- `tests/fuzz/corpus/`
  - one subdirectory per harness
- `tests/fuzz/regressions/`
  - minimized crashing inputs promoted to permanent seeds or fixed tests

Crash triage policy:
- every real crash found in a long run becomes either
  - a permanent corpus seed, or
  - a deterministic unit/fuzz regression test

## Non-Goals

- perfect formal coverage accounting
- CI execution policy
- distributed fuzz infrastructure
- external engine integration

## Success Criteria

The design is successful when:
- every major parser and envelope surface has a dedicated harness
- the suite can be run locally at high throughput for long sessions
- failures are attributable to narrow harnesses rather than one giant test blob
- crashes produce reproducible, minimizable inputs
- the local UX makes both quick focused fuzzing and deep overnight runs practical
