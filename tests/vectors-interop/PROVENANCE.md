# Interop Fixture Provenance

The JSON files in this directory are cross-implementation fixtures consumed
by `zig build interop` (see `tests/interop.zig`). They are **generated**
artifacts, not hand-written test data.

Local source of record:

- Generator: `tools/interop/generate.rb`
- Implementation: the vendored `ruby-paseto` reference at `vendor/ruby`
  (commit `e386ed47a5449b9ee9076d72e09959083eb64103`, gem version `0.2.0`)
- Runtime gem versions are pinned in `tools/interop/Gemfile` to match the
  vendored commit's own `Gemfile.lock`

Generated with Ruby 3.4 via mise and recorded on 2026-08-28:

```sh
cd tools/interop && bundle install
mise x ruby@3.4 -- bundle exec ruby generate.rb
```

CI never runs the generator; it only consumes the committed JSON, so no
Ruby toolchain is needed to test.

Conventions and caveats:

- Keys, nonces, and payloads are fixed, so v4 token fixtures (deterministic
  Ed25519, caller-supplied nonces for local encrypt and PIE wrap) are
  byte-stable across regenerations with the same vendored commit. Note that
  v4 PIE nonces are 32 bytes (per the official wrap vectors), unlike the
  24-byte v4 PBKW nonces.
- v3.public ECDSA signatures, PKE seals (random ephemeral keys), and PBKW
  wraps (random salt and nonce) are randomized per run: recorded values
  stay valid, but regenerating changes those bytes.
- PBKW fixture parameters (v4: 64 MiB / opslimit 2; v3: 10,000 iterations)
  sit inside paseto-zig's production policy envelope, so the Zig side
  unwraps them under the default policy in CI.
- PIE secret-wrap fixtures follow the official vector shape: v4 wraps the
  full 64-byte Ed25519 keypair, v3 wraps the 48-byte scalar.
- Payloads are ASCII-only: the reference's PAE concat cannot handle
  multibyte strings (its v3 path raises `Encoding::CompatibilityError`,
  and its v4.public signatures over UTF-8 messages are corrupted by the
  RbNaCl signing path, which slices the 64-byte signature by character
  count on a UTF-8-tagged buffer; the PAE itself is byte-correct, but the
  emitted tokens fail even the reference's own verification). ASCII payloads exercise the full cryptographic
  path, and byte-level handling of arbitrary plaintexts is covered by the
  official vector suite and this library's own tests.
- Each fixture case is additionally fed to every wrong version/purpose
  entry point by `tests/interop.zig` as a confusion negative.
