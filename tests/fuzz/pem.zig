//! Fuzz harness for `src/pem.zig`. Two sub-targets:
//!   - `pem.pemToDer` on arbitrary bytes
//!   - `pem.parse` on arbitrary bytes

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds = [_][]const u8{
    @embedFile("corpus/pem/v4_public.bin"),
    @embedFile("corpus/pem/v4_private.bin"),
    @embedFile("corpus/pem/v3_ec_private.bin"),
    @embedFile("corpus/pem/leading_garbage.bin"),
    @embedFile("corpus/pem/trailing_garbage.bin"),
    @embedFile("corpus/pem/concatenated.bin"),
    @embedFile("corpus/pem/truncated.bin"),
    @embedFile("corpus/pem/bad_base64.bin"),
};

const pem_to_der_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.InvalidBase64,
    error.OutOfMemory,
};

const parse_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.InvalidBase64,
    error.InvalidKey,
    error.UnsupportedVersion,
    error.OutOfMemory,
};

test "fuzz: pem.pemToDer" {
    try std.testing.fuzz({}, pemToDerFuzz, .{ .corpus = &seeds });
}

test "fuzz: pem.parse" {
    try std.testing.fuzz({}, parseFuzz, .{ .corpus = &seeds });
}

fn pemToDerFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const allocator = std.testing.allocator;

    const out = paseto.pem.pemToDer(allocator, input) catch |err| {
        return support.expectAllowed(err, &pem_to_der_errors);
    };
    defer allocator.free(out.der);
    // Invariant: the caller receives a non-empty DER buffer on success.
    try std.testing.expect(out.der.len > 0);
}

fn parseFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const allocator = std.testing.allocator;

    var parsed = paseto.pem.parse(allocator, input) catch |err| {
        return support.expectAllowed(err, &parse_errors);
    };
    defer parsed.deinit();

    // Contract: the reported format matches the byte length exactly.
    const expected: usize = switch (parsed.format) {
        .ed25519_seed => 32,
        .ed25519_public => 32,
        .p384_scalar => 48,
        .p384_public_compressed => 49,
    };
    try std.testing.expectEqual(expected, parsed.bytes.len);
}
