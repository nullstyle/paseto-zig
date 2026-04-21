//! Fuzz harness for `src/paserk/id.zig`. Sub-targets:
//!   - `compute` on arbitrary bytes (tolerated: InvalidKey | OutOfMemory)
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
    error.OutOfMemory,
};

test "fuzz: paserk.id.compute accepts or rejects cleanly" {
    try std.testing.fuzz({}, computeFuzz, .{ .corpus = &seeds });
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

    const allocator = std.testing.allocator;
    const out = paseto.paserk.id.compute(allocator, version, kind, input) catch |err| {
        return support.expectAllowed(err, &id_errors);
    };
    defer allocator.free(out);

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
    try std.testing.expect(std.mem.startsWith(u8, out, expected_prefix));
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

    const a = try paseto.paserk.id.compute(allocator, version, kind, key);
    defer allocator.free(a);
    const b = try paseto.paserk.id.compute(allocator, version, kind, key);
    defer allocator.free(b);
    try std.testing.expectEqualSlices(u8, a, b);

    // And the dedicated wrappers must agree with `compute`.
    const via_wrapper = switch (kind) {
        .lid => try paseto.paserk.id.lid(allocator, version, key),
        .sid => try paseto.paserk.id.sid(allocator, version, key),
        .pid => try paseto.paserk.id.pid(allocator, version, key),
    };
    defer allocator.free(via_wrapper);
    try std.testing.expectEqualSlices(u8, a, via_wrapper);
}
