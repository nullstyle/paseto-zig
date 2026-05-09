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
    @embedFile("corpus/pem/v3_public.bin"),
    @embedFile("corpus/pem/leading_garbage.bin"),
    @embedFile("corpus/pem/trailing_garbage.bin"),
    @embedFile("corpus/pem/concatenated.bin"),
    @embedFile("corpus/pem/truncated.bin"),
    @embedFile("corpus/pem/bad_base64.bin"),
};

const pem_to_der_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.InvalidBase64,
};

const parse_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.InvalidBase64,
    error.InvalidKey,
    error.UnsupportedVersion,
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

    try std.testing.expect(out.der.len > 0);
    try std.testing.expect(isKnownPemLabel(@tagName(out.label)));
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

    const der = try paseto.pem.pemToDer(allocator, input);
    defer allocator.free(der.der);
    const label_name = @tagName(der.label);

    const expected: usize = switch (parsed.format) {
        .ed25519_seed => 32,
        .ed25519_public => 32,
        .p384_scalar => 48,
        .p384_public_compressed => 49,
    };
    try std.testing.expectEqual(expected, parsed.bytes.len);

    if (std.mem.eql(u8, label_name, "ec_private_key")) {
        try std.testing.expectEqual(paseto.pem.KeyFormat.p384_scalar, parsed.format);
    } else if (std.mem.eql(u8, label_name, "private_key")) {
        try std.testing.expect(parsed.format == .ed25519_seed or parsed.format == .p384_scalar);
    } else if (std.mem.eql(u8, label_name, "public_key")) {
        try std.testing.expect(parsed.format == .ed25519_public or parsed.format == .p384_public_compressed);
    } else {
        return error.UnexpectedPemParseSuccess;
    }
}

fn isKnownPemLabel(label_name: []const u8) bool {
    return std.mem.eql(u8, label_name, "private_key") or
        std.mem.eql(u8, label_name, "public_key") or
        std.mem.eql(u8, label_name, "ec_private_key");
}
