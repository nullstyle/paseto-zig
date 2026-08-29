# Test Vector Provenance

The JSON files in this directory are the PASETO/PASERK vector corpus used by
the Zig test suite.

Local source of record:

- `vendor/ruby/spec/vectors/json/*.json`
- Vendored repository: `git@github.com:bannable/paseto.git`
- Vendored commit: `e386ed47a5449b9ee9076d72e09959083eb64103`

Upstream references:

- PASETO specification: https://github.com/paseto-standard/paseto-spec
- PASERK specification: https://github.com/paseto-standard/paserk
- Official test vectors: https://github.com/paseto-standard/test-vectors

Note: the vendored `v3.json` 3-S-1/3-S-3 signature bytes differ from the
current official repository's master branch. Upstream commit `32d7406`
("Fix v3.public", 2024-04-28) re-signed exactly those two cases because the
 originals carry high-S ECDSA signatures that strict low-S-enforcing
verifiers reject; the keys, messages, and PAE inputs are identical. The
vendored (high-S) signatures verify under lenient verifiers — including
this library, which enforces the raw ECDSA equation without a low-S
constraint — but fail under strict low-S implementations.

When refreshing vectors, update this file with the exact upstream source,
commit, import date, and any generator command used. Then run:

```sh
zig build vectors
zig build test
```
