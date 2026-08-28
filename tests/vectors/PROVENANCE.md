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

When refreshing vectors, update this file with the exact upstream source,
commit, import date, and any generator command used. Then run:

```sh
zig build vectors
zig build test
```
