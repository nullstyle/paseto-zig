//! Fuzz harness for `src/paserk/id.zig`. Sub-targets:
//!   - `compute` on arbitrary bytes (tolerated: InvalidKey)
//!   - `parse` on arbitrary bytes (tolerated: parser/encoding errors)
//!   - Valid-length inputs: result carries the correct prefix and repeated
//!     calls are byte-for-byte deterministic

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds = [_][]const u8{
    @embedFile("corpus/paserk_id/local_32_zero.bin"),
    @embedFile("corpus/paserk_id/short.bin"),
};

const id_errors = [_]paseto.Error{
    error.InvalidKey,
};

const parse_errors = [_]paseto.Error{
    error.InvalidKeyId,
    error.UnsupportedVersion,
    error.UnsupportedOperation,
    error.InvalidBase64,
    error.InvalidPadding,
    error.InvalidEncoding,
};

test "fuzz: paserk.id.compute accepts or rejects cleanly" {
    try std.testing.fuzz({}, computeFuzz, .{ .corpus = &seeds });
}

test "fuzz: paserk.Id.parse accepts or rejects cleanly" {
    try std.testing.fuzz({}, parseFuzz, .{ .corpus = &seeds });
}

test "fuzz: paserk.id valid-length is deterministic and prefixed" {
    try std.testing.fuzz({}, validFuzz, .{});
}

fn computeFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [support.max_key_material_bytes]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const version = s.value(paseto.Version);
    const kind = s.value(paseto.paserk.IdKind);

    const id_handle = paseto.paserk.id.compute(version, kind, input) catch |err| {
        return support.expectAllowed(err, &id_errors);
    };

    // Prefix contract: "k{3,4}.{lid|sid|pid}."
    const expected_prefix = switch (version) {
        .v3 => switch (kind) {
            .lid => "k3.lid.",
            .sid => "k3.sid.",
            .pid => "k3.pid.",
        },
        .v4 => switch (kind) {
            .lid => "k4.lid.",
            .sid => "k4.sid.",
            .pid => "k4.pid.",
        },
    };

    const allocator = std.testing.allocator;
    const out = try id_handle.toString(allocator);
    defer allocator.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, expected_prefix));
    try std.testing.expectEqual(expected_prefix.len + paseto.util.encodedBase64Len(33), out.len);

    try std.testing.expect(id_handle.version == version);
    try std.testing.expect(id_handle.kind == kind);
    try std.testing.expect(id_handle.eqlString(out));

    const suffix = out[expected_prefix.len..];
    const decoded = try paseto.util.decodeBase64Alloc(allocator, suffix);
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 33), decoded.len);
}

fn parseFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const id_handle = paseto.paserk.Id.parse(input) catch |err| {
        return support.expectAllowed(err, &parse_errors);
    };

    const allocator = std.testing.allocator;
    const encoded = try id_handle.toString(allocator);
    defer allocator.free(encoded);

    const reparsed = try paseto.paserk.Id.parse(encoded);
    try std.testing.expect(id_handle.eql(reparsed));
}

fn validFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;

    const version = s.value(paseto.Version);
    const kind = s.value(paseto.paserk.IdKind);

    const len: usize = switch (version) {
        .v3 => switch (kind) {
            .lid => 32,
            .sid => 48,
            .pid => 49,
        },
        .v4 => switch (kind) {
            .lid => 32,
            .sid => 64,
            .pid => 32,
        },
    };

    var key_buf: [64]u8 = undefined;
    s.bytes(key_buf[0..len]);
    const key = key_buf[0..len];

    const id_handle = try paseto.paserk.id.compute(version, kind, key);
    try std.testing.expect(id_handle.version == version);
    try std.testing.expect(id_handle.kind == kind);

    const a = try id_handle.toString(allocator);
    defer allocator.free(a);
    const b = try paseto.paserk.id.compute(version, kind, key);
    try std.testing.expect(id_handle.eql(b));

    // And the dedicated wrappers must agree with `compute`.
    const via_wrapper = switch (kind) {
        .lid => try paseto.paserk.id.lid(version, key),
        .sid => try paseto.paserk.id.sid(version, key),
        .pid => try paseto.paserk.id.pid(version, key),
    };
    try std.testing.expect(id_handle.eql(via_wrapper));
    try std.testing.expect(id_handle.eql(try paseto.paserk.Id.parse(a)));

    const expected_prefix = switch (version) {
        .v3 => switch (kind) {
            .lid => "k3.lid.",
            .sid => "k3.sid.",
            .pid => "k3.pid.",
        },
        .v4 => switch (kind) {
            .lid => "k4.lid.",
            .sid => "k4.sid.",
            .pid => "k4.pid.",
        },
    };
    try std.testing.expect(std.mem.startsWith(u8, a, expected_prefix));
}
