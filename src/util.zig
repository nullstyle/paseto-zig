const std = @import("std");
const errors = @import("errors.zig");

pub const Error = errors.Error;

const b64 = std.base64.url_safe_no_pad;

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
    errdefer allocator.free(out);
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
    var total: usize = 8;
    for (parts) |p| total += 8 + p.len;

    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);

    var idx: usize = 0;
    std.mem.writeInt(u64, out[idx..][0..8], @as(u64, @intCast(parts.len)), .little);
    idx += 8;
    for (parts) |p| {
        // PASETO spec masks the high bit; in practice the length is never that
        // large in this library. Enforce an assertion anyway.
        std.debug.assert(p.len <= std.math.maxInt(i64));
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
    for (parts) |p| total += p.len;
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

pub fn hexDecodeAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return Error.InvalidEncoding;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
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
