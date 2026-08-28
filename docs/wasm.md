# PASETO v4.local WebAssembly ABI

`zig build wasm` writes a freestanding ReleaseSafe module to
`zig-out/wasm/paseto.wasm`, then post-processes it with mise-pinned Binaryen 130.
The optimizer uses `--enable-bulk-memory`, `-Oz`, `--low-memory-unused`,
`--optimize-instructions`, and `--converge`; ABI range checks make the low-memory
assumption explicit by rejecting every pointer below the fixed arena. ABI
integers and frame lengths are unsigned
32-bit little-endian values unless a signature says otherwise. ABI version 1
has no imports and exports its linear `memory`.

The module does not generate randomness. A host must generate a fresh 32-byte
nonce with a CSPRNG for every `seal` call. In Deno and browsers, use
`crypto.getRandomValues(new Uint8Array(32))` and never reuse a nonce with the
same local key.

## Exports

```text
version() -> u32                         // 1
allocate(len: u32) -> u32                // zero means allocation failure
free(ptr: u32, len: u32) -> void         // wipes; does not reclaim arena space
resetAllocator() -> void                 // wipes and reclaims the whole arena
seal(input_ptr: u32, input_len: u32, out_desc_ptr: u32) -> i32
open(input_ptr: u32, input_len: u32, out_desc_ptr: u32) -> i32
localKeyId(input_ptr: u32, input_len: u32, out_desc_ptr: u32) -> i32
localKeyIdLen() -> u32                    // 51
openResultHeaderLen() -> u32              // 8
```

On status `0`, the operation writes this descriptor at `out_desc_ptr`:

```text
offset  size  field
0       4     result_ptr
4       4     result_len
```

Copy the result bytes out of `memory` before calling `free` or
`resetAllocator`. The descriptor is unspecified on failure. Dynamic output
lengths are returned only through this descriptor; callers do not preallocate
or pass an output length.

## Status Codes

| Value | Name | Meaning |
| ---: | --- | --- |
| `0` | `ok` | The descriptor contains a result. |
| `1` | `crypto_error` | Authentication, token parsing, or another cryptographic operation failed. |
| `2` | `invalid_input` | A pointer, frame, length, or size limit is invalid. |
| `3` | `out_of_memory` | The fixed eight MiB arena cannot complete the call. |

Treat `crypto_error` from `open` as one generic authentication failure. Do not
expose token parsing details to callers.

## `seal` Input

The host supplies one exact frame; trailing bytes are rejected.

```text
offset  size          field
0       32            v4.local key
32      32            fresh host-generated nonce
64      4             message_len
68      4             footer_len
72      4             implicit_assertion_len
76      message_len   plaintext message
...     footer_len    raw authenticated footer
...     assertion_len implicit assertion
```

The result is the ASCII `v4.local...` token. Empty messages, footers, and
implicit assertions are valid. The serialized token is subject to the
library's one MiB token limit.

## `open` Input And Output

The input is exact and must contain a non-empty token:

```text
offset  size          field
0       32            v4.local key
32      4             token_len
36      4             implicit_assertion_len
40      token_len     ASCII PASETO token
...     assertion_len implicit assertion
```

The authenticated result has an unambiguous frame:

```text
offset  size            field
0       4               plaintext_len
4       4               footer_len
8       plaintext_len   plaintext
...     footer_len      raw authenticated footer
```

Both the plaintext and footer are available only after the token tag and
implicit assertion authenticate successfully.

## `localKeyId` Input And Output

The input is exactly one 32-byte v4.local key. The result is the canonical
51-byte ASCII `k4.lid.*` PASERK identifier. `localKeyIdLen()` returns that
fixed length for ABI introspection.

## Host Lifecycle

Use one module instance for one operation at a time:

1. Call `resetAllocator()` before starting an operation.
2. Allocate and fill the packed input and an eight-byte result descriptor.
3. Call the operation and check its status before reading the descriptor.
4. Copy the result into host-owned memory.
5. Call `free` for sensitive ranges when useful, then `resetAllocator()` in a
   `finally` block.

`resetAllocator()` wipes the arena's true allocation high-water mark, including
temporary buffers already released by the cryptographic implementation. After
a WebAssembly trap, discard the instance instead of returning it to a pool.
