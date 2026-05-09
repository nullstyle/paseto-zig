//! Fuzz harness for `src/v3/public.zig`. Sub-targets:
//!   - `verify` on arbitrary bytes
//!   - sign/verify round-trip
//!   - mutation reject
//!   - constructor misuse:
//!       fromPublicBytesCompressed / fromPublicBytesUncompressed /
//!       fromPublicBytes / fromScalarBytes

const std = @import("std");
const paseto = @import("paseto");
const support = @import("support.zig");

const seeds_verify = [_][]const u8{
    @embedFile("corpus/v3_public/valid.bin"),
    @embedFile("corpus/v3_public/short.bin"),
    @embedFile("corpus/v3_public/wrong_purpose.bin"),
};

test "fuzz: v3.Public.verify" {
    try std.testing.fuzz({}, verifyFuzz, .{ .corpus = &seeds_verify });
}

test "fuzz: v3.Public sign/verify round-trip" {
    try std.testing.fuzz({}, roundTripFuzz, .{});
}

test "fuzz: v3.Public mutation reject" {
    try std.testing.fuzz({}, mutationFuzz, .{});
}

test "fuzz: v3.Public constructors" {
    try std.testing.fuzz({}, ctorFuzz, .{});
}

test "fuzz: v3.Public wrong-key reject" {
    try std.testing.fuzz({}, wrongKeyFuzz, .{});
}

fn verifyFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var tok_buf: [support.max_input_bytes]u8 = undefined;
    const n = s.slice(&tok_buf);
    const token_str = tok_buf[0..n];

    const pk = try paseto.v3.Public.generate();

    var assertion_buf: [64]u8 = undefined;
    const a_n = s.slice(&assertion_buf);

    const allocator = std.testing.allocator;
    const out = pk.verify(allocator, token_str, assertion_buf[0..a_n]) catch |err| {
        return support.expectAllowed(err, &support.public_verify_errors);
    };
    defer allocator.free(out);
}

fn roundTripFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    const pk = try paseto.v3.Public.generate();

    var msg_buf: [1024]u8 = undefined;
    const msg_n = s.slice(&msg_buf);
    const message = msg_buf[0..msg_n];
    var footer_buf: [256]u8 = undefined;
    const f_n = s.slice(&footer_buf);
    const footer = footer_buf[0..f_n];
    var assertion_buf: [256]u8 = undefined;
    const a_n = s.slice(&assertion_buf);
    const assertion = assertion_buf[0..a_n];

    const signed = try pk.sign(allocator, message, .{
        .footer = footer,
        .implicit_assertion = assertion,
    });
    defer allocator.free(signed);

    const recovered = try pk.verify(allocator, signed, assertion);
    defer allocator.free(recovered);
    try std.testing.expectEqualSlices(u8, message, recovered);
}

fn mutationFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    const pk = try paseto.v3.Public.generate();

    var msg_buf: [256]u8 = undefined;
    const msg_n = s.slice(&msg_buf);
    const message = msg_buf[0..msg_n];
    var footer_buf: [64]u8 = undefined;
    const f_n = s.slice(&footer_buf);
    const footer = footer_buf[0..f_n];
    var assertion_buf: [64]u8 = undefined;
    const a_n = s.slice(&assertion_buf);
    const assertion = assertion_buf[0..a_n];

    const signed = try pk.sign(allocator, message, .{
        .footer = footer,
        .implicit_assertion = assertion,
    });
    defer allocator.free(signed);

    for (support.token_mutation_classes) |mutation| {
        const tampered = try support.mutateToken(allocator, signed, mutation, s);
        defer allocator.free(tampered);

        if (std.mem.eql(u8, tampered, signed)) continue;

        if (pk.verify(allocator, tampered, assertion)) |ok| {
            allocator.free(ok);
            return error.MutatedTokenShouldNotVerify;
        } else |err| {
            try support.expectAllowed(err, &support.public_verify_errors);
        }
    }
}

fn wrongKeyFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    const allocator = std.testing.allocator;
    const signer = try paseto.v3.Public.generate();
    var verifier = try paseto.v3.Public.generate();
    const signer_public = signer.publicCompressed();
    while (std.mem.eql(u8, &signer_public, &verifier.publicCompressed())) {
        verifier = try paseto.v3.Public.generate();
    }

    var msg_buf: [256]u8 = undefined;
    const msg_n = s.slice(&msg_buf);
    const message = msg_buf[0..msg_n];
    var footer_buf: [64]u8 = undefined;
    const f_n = s.slice(&footer_buf);
    const footer = footer_buf[0..f_n];
    var assertion_buf: [64]u8 = undefined;
    const a_n = s.slice(&assertion_buf);
    const assertion = assertion_buf[0..a_n];

    const signed = try signer.sign(allocator, message, .{
        .footer = footer,
        .implicit_assertion = assertion,
    });
    defer allocator.free(signed);

    if (verifier.verify(allocator, signed, assertion)) |ok| {
        allocator.free(ok);
        return error.WrongKeyShouldNotVerify;
    } else |err| {
        try support.expectAllowed(err, &support.public_verify_errors);
    }
}

fn ctorFuzz(_: void, s: *std.testing.Smith) anyerror!void {
    var buf: [128]u8 = undefined;
    const n = s.slice(&buf);
    const bytes = buf[0..n];

    const choice = s.valueRangeAtMost(u8, 0, 3);
    switch (choice) {
        0 => {
            _ = paseto.v3.Public.fromScalarBytes(bytes) catch |err| {
                return support.expectAllowed(err, &support.public_ctor_errors);
            };
        },
        1 => {
            _ = paseto.v3.Public.fromPublicBytesCompressed(bytes) catch |err| {
                return support.expectAllowed(err, &support.public_ctor_errors);
            };
        },
        2 => {
            _ = paseto.v3.Public.fromPublicBytesUncompressed(bytes) catch |err| {
                return support.expectAllowed(err, &support.public_ctor_errors);
            };
        },
        3 => {
            _ = paseto.v3.Public.fromPublicBytes(bytes) catch |err| {
                return support.expectAllowed(err, &support.public_ctor_errors);
            };
        },
        else => unreachable,
    }
}
