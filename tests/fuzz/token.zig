//! Fuzz harness for `src/token.zig`. Exercises raw PASETO framing.

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds = [_][]const u8{
    @embedFile("corpus/token/v4_local_valid.bin"),
    @embedFile("corpus/token/v3_local_valid.bin"),
    @embedFile("corpus/token/v4_public_valid.bin"),
    @embedFile("corpus/token/v3_public_valid.bin"),
    @embedFile("corpus/token/empty.bin"),
    @embedFile("corpus/token/header_only.bin"),
    @embedFile("corpus/token/too_many_dots.bin"),
    @embedFile("corpus/token/bad_base64.bin"),
    @embedFile("corpus/token/unsupported_version.bin"),
};

test "fuzz: token.parse never panics and round-trips" {
    try std.testing.fuzz({}, parseFuzz, .{ .corpus = &seeds });
}

fn parseFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&buf);
    const input = buf[0..n];

    const allocator = std.testing.allocator;

    var tok = paseto.token.parse(allocator, input) catch |err| {
        return support.expectAllowed(err, &support.token_parse_errors);
    };
    defer tok.deinit();

    // Round-trip invariant: re-serialize what we parsed, re-parse, confirm
    // payload/footer bytes survive.
    const reserialized = try paseto.token.serialize(
        allocator,
        tok.version,
        tok.purpose,
        tok.payload,
        tok.footer,
    );
    defer allocator.free(reserialized);

    var tok2 = try paseto.token.parse(allocator, reserialized);
    defer tok2.deinit();

    try std.testing.expectEqualSlices(u8, tok.payload, tok2.payload);
    try std.testing.expectEqualSlices(u8, tok.footer, tok2.footer);
    try std.testing.expectEqual(tok.version, tok2.version);
    try std.testing.expectEqual(tok.purpose, tok2.purpose);
}
