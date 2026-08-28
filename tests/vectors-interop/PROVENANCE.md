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

- Keys, nonces, and payloads are fixed, so v4 fixtures (deterministic
  Ed25519, caller-supplied nonce for local) are byte-stable across
  regenerations with the same vendored commit.
- v3.public ECDSA signatures are randomized by OpenSSL per run: recorded
  tokens stay valid, but regenerating changes those signature bytes.
- Payloads are ASCII-only: the reference's PAE concat cannot handle
  multibyte strings (its v3 path raises `Encoding::CompatibilityError`,
  and its v4.public signatures over UTF-8 messages do not verify against
  the spec-defined PAE). ASCII payloads exercise the full cryptographic
  path, and byte-level handling of arbitrary plaintexts is covered by the
  official vector suite and this library's own tests.
- Each fixture case is additionally fed to every wrong version/purpose
  entry point by `tests/interop.zig` as a confusion negative.
