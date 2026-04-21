//! Fuzz harness for `src/util.zig`. Three sub-targets in one file:
//!   - base64url decode (strict: rejects `=` padding)
//!   - hex decode
//!   - PAE construction

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds_base64 = [_][]const u8{
    @embedFile("corpus/util/base64_valid.bin"),
    @embedFile("corpus/util/base64_padded.bin"),
    @embedFile("corpus/util/base64_std_chars.bin"),
    @embedFile("corpus/util/garbage.bin"),
};

const seeds_hex = [_][]const u8{
    @embedFile("corpus/util/hex_even.bin"),
    @embedFile("corpus/util/hex_odd.bin"),
    @embedFile("corpus/util/hex_uppercase.bin"),
    @embedFile("corpus/util/garbage.bin"),
};

const seeds_pae = [_][]const u8{
    @embedFile("corpus/util/base64_valid.bin"),
    @embedFile("corpus/util/hex_even.bin"),
    @embedFile("corpus/util/garbage.bin"),
};

const base64_errors = [_]paseto.Error{
    error.InvalidBase64,
    error.InvalidPadding,
    error.OutOfMemory,
};

const hex_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.OutOfMemory,
};

test "fuzz: util.decodeBase64Alloc" {
    try std.testing.fuzz({}, base64Fuzz, .{ .corpus = &seeds_base64 });
}

test "fuzz: util.hexDecodeAlloc" {
    try std.testing.fuzz({}, hexFuzz, .{ .corpus = &seeds_hex });
}

test "fuzz: util.preAuthEncodeAlloc" {
    try std.testing.fuzz({}, paeFuzz, .{ .corpus = &seeds_pae });
}

fn base64Fuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const allocator = std.testing.allocator;

    const decoded = paseto.util.decodeBase64Alloc(allocator, input) catch |err| {
        return support.expectAllowed(err, &base64_errors);
    };
    defer allocator.free(decoded);

    // Round-trip: re-encode and confirm the encoding matches the decoder's
    // accepted alphabet. Since decodeBase64Alloc rejects padding, a valid
    // input contains only base64url characters; re-encoding must reproduce
    // byte-for-byte (base64url has no case or character ambiguity).
    const reencoded = try paseto.util.encodeBase64Alloc(allocator, decoded);
    defer allocator.free(reencoded);
    try std.testing.expectEqualSlices(u8, input, reencoded);
}

fn hexFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const allocator = std.testing.allocator;

    const decoded = paseto.util.hexDecodeAlloc(allocator, input) catch |err| {
        return support.expectAllowed(err, &hex_errors);
    };
    defer allocator.free(decoded);
    try std.testing.expectEqual(input.len / 2, decoded.len);
}

fn paeFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    // Generate between 0 and 8 small parts. `preAuthEncodeAlloc` never
    // returns an error short of OutOfMemory and must always produce
    // `8 + sum(8 + len(p)) for p in parts` bytes.
    const part_count = s.valueRangeAtMost(u8, 0, 8);
    var parts: [8][]u8 = undefined;
    var part_bufs: [8][128]u8 = undefined;
    var part_slices: [8][]const u8 = undefined;
    var i: usize = 0;
    while (i < part_count) : (i += 1) {
        const n = s.slice(&part_bufs[i]);
        parts[i] = part_bufs[i][0..n];
        part_slices[i] = parts[i];
    }

    const out = try paseto.util.preAuthEncodeAlloc(allocator, part_slices[0..part_count]);
    defer allocator.free(out);

    var expected: usize = 8;
    for (part_slices[0..part_count]) |p| expected += 8 + p.len;
    try std.testing.expectEqual(expected, out.len);
}
