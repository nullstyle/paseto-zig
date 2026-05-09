//! Fuzz harness for `src/paserk/keys.zig`. Single sub-target: `parse` on
//! arbitrary bytes with a serialize-back round-trip on success.

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds = [_][]const u8{
    @embedFile("corpus/paserk_keys/k4_local_valid.bin"),
    @embedFile("corpus/paserk_keys/k3_local_valid.bin"),
    @embedFile("corpus/paserk_keys/wrong_length.bin"),
    @embedFile("corpus/paserk_keys/bad_prefix.bin"),
    @embedFile("corpus/paserk_keys/bad_kind.bin"),
    @embedFile("corpus/paserk_keys/too_many_dots.bin"),
};

const parse_errors = [_]paseto.Error{
    error.InvalidEncoding,
    error.UnsupportedVersion,
    error.UnsupportedOperation,
    error.InvalidKey,
    error.InvalidBase64,
    error.InvalidPadding,
};

test "fuzz: paserk.keys.parse round-trips" {
    try std.testing.fuzz({}, parseFuzz, .{ .corpus = &seeds });
}

fn parseFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const allocator = std.testing.allocator;

    var decoded = paseto.paserk.keys.parse(allocator, input) catch |err| {
        return support.expectAllowed(err, &parse_errors);
    };
    defer decoded.deinit();

    const reserialized = try paseto.paserk.keys.serialize(
        allocator,
        decoded.version,
        decoded.kind,
        decoded.bytes,
    );
    defer allocator.free(reserialized);

    var reparsed = try paseto.paserk.keys.parse(allocator, reserialized);
    defer reparsed.deinit();

    try std.testing.expectEqualSlices(u8, input, reserialized);
    try std.testing.expectEqual(decoded.version, reparsed.version);
    try std.testing.expectEqual(decoded.kind, reparsed.kind);
    try std.testing.expectEqualSlices(u8, decoded.bytes, reparsed.bytes);
}
