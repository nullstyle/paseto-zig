const std = @import("std");
const errors = @import("errors.zig");

pub const Error = errors.Error;

const b64 = std.base64.url_safe_no_pad;

pub const max_token_string_bytes = 1024 * 1024;
pub const max_claims_json_bytes = 64 * 1024;
pub const max_pem_bytes = 64 * 1024;
pub const max_paserk_string_bytes = 4096;

pub fn encodedBase64Len(raw_len: usize) usize {
    return b64.Encoder.calcSize(raw_len);
}

/// Encode `raw` into `out`; `out.len` must equal `encodedBase64Len(raw.len)`.
pub fn encodeBase64(out: []u8, raw: []const u8) []const u8 {
    return b64.Encoder.encode(out, raw);
}

pub fn encodeBase64Alloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const n = encodedBase64Len(raw.len);
    const out = try allocator.alloc(u8, n);
    _ = encodeBase64(out, raw);
    return out;
}

pub fn decodeBase64Alloc(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    // PASETO test vectors require unpadded base64url input; reject any
    // trailing '=' characters the caller may have attached.
    if (std.mem.indexOfScalar(u8, encoded, '=')) |_| return Error.InvalidPadding;

    const size = b64.Decoder.calcSizeForSlice(encoded) catch |err| switch (err) {
        error.InvalidPadding => return Error.InvalidPadding,
        error.InvalidCharacter => return Error.InvalidBase64,
        error.NoSpaceLeft => return Error.InvalidBase64,
    };

    const out = try allocator.alloc(u8, size);
    errdefer secureFree(allocator, out);
    b64.Decoder.decode(out, encoded) catch |err| switch (err) {
        error.InvalidCharacter => return Error.InvalidBase64,
        error.InvalidPadding => return Error.InvalidPadding,
        error.NoSpaceLeft => unreachable,
    };
    return out;
}

/// Decode unpadded base64url into `out`; `out.len` must match the decoded
/// length exactly.
pub fn decodeBase64(out: []u8, encoded: []const u8) !void {
    // PASETO test vectors require unpadded base64url input; reject any
    // trailing '=' characters the caller may have attached.
    if (std.mem.indexOfScalar(u8, encoded, '=')) |_| return Error.InvalidPadding;

    const size = b64.Decoder.calcSizeForSlice(encoded) catch |err| switch (err) {
        error.InvalidPadding => return Error.InvalidPadding,
        error.InvalidCharacter => return Error.InvalidBase64,
        error.NoSpaceLeft => return Error.InvalidBase64,
    };
    if (size != out.len) return Error.InvalidEncoding;

    b64.Decoder.decode(out, encoded) catch |err| switch (err) {
        error.InvalidCharacter => return Error.InvalidBase64,
        error.InvalidPadding => return Error.InvalidPadding,
        error.NoSpaceLeft => unreachable,
    };
}

pub fn writeBE(comptime T: type, buf: []u8, value: T) void {
    std.mem.writeInt(T, buf[0..@sizeOf(T)], value, .big);
}

pub fn writeLE(comptime T: type, buf: []u8, value: T) void {
    std.mem.writeInt(T, buf[0..@sizeOf(T)], value, .little);
}

pub fn readBE(comptime T: type, buf: []const u8) T {
    return std.mem.readInt(T, buf[0..@sizeOf(T)], .big);
}

pub fn readLE(comptime T: type, buf: []const u8) T {
    return std.mem.readInt(T, buf[0..@sizeOf(T)], .little);
}

pub fn le64(value: u64) [8]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    return buf;
}

pub fn be64(value: u64) [8]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    return buf;
}

pub fn be32(value: u32) [4]u8 {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    return buf;
}

/// PAE (Pre-Authentication Encoding) per PASETO spec:
///   pae(parts) := LE64(n) || ( LE64(len(p_i)) || p_i for each p_i in parts )
/// High bit of each length is cleared (spec text) — we achieve this by
/// rejecting lengths >= 2^63, which no real input reaches.
pub fn preAuthEncodeAlloc(
    allocator: std.mem.Allocator,
    parts: []const []const u8,
) ![]u8 {
    // The spec clears the high bit of each LE64 length; reject oversized
    // inputs as a checked error so release builds cannot silently encode a
    // length that overflows into the sign bit.
    if (parts.len > std.math.maxInt(i64)) return Error.Overflow;
    var total: usize = 8;
    for (parts) |p| {
        if (p.len > std.math.maxInt(i64)) return Error.Overflow;
        total = std.math.add(usize, total, 8) catch return Error.Overflow;
        total = std.math.add(usize, total, p.len) catch return Error.Overflow;
    }

    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);

    var idx: usize = 0;
    std.mem.writeInt(u64, out[idx..][0..8], @as(u64, @intCast(parts.len)), .little);
    idx += 8;
    for (parts) |p| {
        std.mem.writeInt(u64, out[idx..][0..8], @as(u64, @intCast(p.len)), .little);
        idx += 8;
        @memcpy(out[idx..][0..p.len], p);
        idx += p.len;
    }
    return out;
}

pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var acc: u8 = 0;
    for (a, b) |x, y| acc |= x ^ y;
    // Mask acc down to a bool without a branch on the accumulator's value.
    const diff: u16 = @as(u16, acc);
    return @as(u1, @truncate((diff -% 1) >> 8)) == 1;
}

pub fn concatAlloc(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |p| total = std.math.add(usize, total, p.len) catch return Error.Overflow;
    const out = try allocator.alloc(u8, total);
    var idx: usize = 0;
    for (parts) |p| {
        @memcpy(out[idx..][0..p.len], p);
        idx += p.len;
    }
    return out;
}

/// Fill `buf` with random bytes from a process-local single-threaded Io
/// instance (sufficient for cryptographic keys/nonces via the host OS).
/// Callers that need explicit Io control can invoke `randomBytesWithIo`.
pub fn randomBytes(buf: []u8) void {
    const io = std.Io.Threaded.global_single_threaded.io();
    io.random(buf);
}

pub fn randomBytesWithIo(io: std.Io, buf: []u8) void {
    io.random(buf);
}

pub fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

pub fn secureFree(allocator: std.mem.Allocator, buf: []u8) void {
    secureZero(buf);
    allocator.free(buf);
}

/// Install a BLAKE2b key directly into a caller-owned state (RFC 7693 keyed
/// init: `h[0] ^= key_len << 8`, key block zero-padded, `buf_len` = block
/// size). Zig's keyed `init` returns a state containing the padded key block
/// by value, which can leave the temporary return frame on the stack (and in
/// exported WASM linear memory). Building the parameter block in place gives
/// the caller exactly one state to wipe with `secureZero`.
///
/// The equivalence test below pins this to `std.crypto`'s keyed init, which
/// is itself validated against the official BLAKE2 known-answer vectors.
pub fn setBlake2bKey(hasher: anytype, key: []const u8) void {
    std.debug.assert(key.len > 0 and key.len <= 64);
    hasher.h[0] ^= @as(u64, key.len << 8);
    @memset(&hasher.buf, 0);
    @memcpy(hasher.buf[0..key.len], key);
    hasher.buf_len = std.crypto.hash.blake2.Blake2b(8).block_length;
}

pub fn hexDecodeAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return Error.InvalidEncoding;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer secureFree(allocator, out);
    _ = std.fmt.hexToBytes(out, hex) catch return Error.InvalidEncoding;
    return out;
}

test "PAE matches spec examples" {
    const allocator = std.testing.allocator;

    // pae([]) == "\x00\x00\x00\x00\x00\x00\x00\x00"
    {
        const out = try preAuthEncodeAlloc(allocator, &.{});
        defer allocator.free(out);
        const expected: [8]u8 = @splat(0);
        try std.testing.expectEqualSlices(u8, &expected, out);
    }

    // pae([""]) ==
    // "\x01\x00\x00\x00\x00\x00\x00\x00" ++
    // "\x00\x00\x00\x00\x00\x00\x00\x00"
    {
        const out = try preAuthEncodeAlloc(allocator, &.{""});
        defer allocator.free(out);
        const expected = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        try std.testing.expectEqualSlices(u8, &expected, out);
    }

    // pae(["test"]) ==
    // "\x01\x00\x00\x00\x00\x00\x00\x00" ++
    // "\x04\x00\x00\x00\x00\x00\x00\x00" ++ "test"
    {
        const out = try preAuthEncodeAlloc(allocator, &.{"test"});
        defer allocator.free(out);
        const expected = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 't', 'e', 's', 't' };
        try std.testing.expectEqualSlices(u8, &expected, out);
    }
}

test "base64url round-trip rejects padding" {
    const allocator = std.testing.allocator;
    const raw = "hello, paseto";
    const encoded = try encodeBase64Alloc(allocator, raw);
    defer allocator.free(encoded);
    try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '=') == null);

    const decoded = try decodeBase64Alloc(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, raw, decoded);

    const padded = "aGVsbG8=";
    try std.testing.expectError(Error.InvalidPadding, decodeBase64Alloc(allocator, padded));
}

test "constantTimeEqual" {
    try std.testing.expect(constantTimeEqual("abc", "abc"));
    try std.testing.expect(!constantTimeEqual("abc", "abd"));
    try std.testing.expect(!constantTimeEqual("abc", "abcd"));
}

test "setBlake2bKey matches std keyed init across sizes" {
    const Blake2b = std.crypto.hash.blake2.Blake2b;

    // Sweep output sizes (the library uses 32- and 56-byte digests), key
    // lengths on both sides of the padding boundary, and message lengths
    // spanning empty, sub-block, block-aligned, and multi-block inputs.
    const out_bits = [_]usize{ 32 * 8, 56 * 8, 64 * 8 };
    const key_lens = [_]usize{ 1, 16, 32, 63, 64 };
    const msg_lens = [_]usize{ 0, 1, 127, 128, 129, 1000 };

    var key: [64]u8 = undefined;
    var msg: [1000]u8 = undefined;
    var seed: u64 = 0x9e3779b97f4a7c15;
    for (&key, 0..) |*b, i| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        b.* = @truncate(seed ^ i);
    }
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 31);

    inline for (out_bits) |bits| {
        inline for (key_lens) |klen| {
            inline for (msg_lens) |mlen| {
                var via_std: [64]u8 = undefined;
                Blake2b(bits).hash(msg[0..mlen], via_std[0 .. bits / 8], .{ .key = key[0..klen] });

                var h = Blake2b(bits).init(.{});
                setBlake2bKey(&h, key[0..klen]);
                h.update(msg[0..mlen]);
                var via_inplace: [64]u8 = undefined;
                h.final(via_inplace[0 .. bits / 8]);

                try std.testing.expectEqualSlices(u8, via_std[0 .. bits / 8], via_inplace[0 .. bits / 8]);
            }
        }
    }
}
