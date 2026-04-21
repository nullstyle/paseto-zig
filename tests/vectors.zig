const std = @import("std");
const paseto = @import("paseto");

const VectorError = error{VectorFailed};

/// Common fields pulled from PASETO v3/v4 JSON vector files.
const PasetoVector = struct {
    name: []const u8,
    expect_fail: bool,
    token: []const u8,
    payload: ?[]const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
    nonce_hex: ?[]const u8,
    key_hex: ?[]const u8,
    public_key_hex: ?[]const u8,
    secret_key_hex: ?[]const u8,
    secret_key_seed_hex: ?[]const u8,
};

fn getOptionalString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        .null => null,
        else => null,
    };
}

fn readVectorFile(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(std.json.Value) {
    const io = std.testing.io;
    const buf = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
    defer allocator.free(buf);
    return try std.json.parseFromSlice(std.json.Value, allocator, buf, .{});
}

fn hexAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    return try paseto.util.hexDecodeAlloc(allocator, hex);
}

fn hexToArr(hex: []const u8, comptime N: usize) ![N]u8 {
    if (hex.len != N * 2) return error.VectorFailed;
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch return error.VectorFailed;
    return out;
}

test "PASETO v4 vectors" {
    const allocator = std.testing.allocator;
    var parsed = try readVectorFile(allocator, "tests/vectors/v4.json");
    defer parsed.deinit();
    const root = parsed.value.object;
    const tests = root.get("tests").?.array;
    try std.testing.expect(tests.items.len > 0);

    var seen_local: usize = 0;
    var seen_public: usize = 0;
    var seen_fail: usize = 0;
    for (tests.items) |test_val| {
        const t = test_val.object;
        const name = t.get("name").?.string;
        const expect_fail = t.get("expect-fail").?.bool;
        const token = t.get("token").?.string;
        const footer = t.get("footer").?.string;
        const implicit_assertion = t.get("implicit-assertion").?.string;

        if (std.mem.startsWith(u8, name, "4-E-")) {
            try runV4Local(allocator, name, t, token, footer, implicit_assertion, expect_fail);
            seen_local += 1;
        } else if (std.mem.startsWith(u8, name, "4-S-")) {
            try runV4Public(allocator, name, t, token, footer, implicit_assertion, expect_fail);
            seen_public += 1;
        } else if (std.mem.startsWith(u8, name, "4-F-")) {
            try runV4Fail(allocator, name, t, token, footer, implicit_assertion);
            seen_fail += 1;
        } else {
            std.debug.print("unrecognized v4 vector: {s}\n", .{name});
            return error.VectorFailed;
        }
    }
    try std.testing.expect(seen_local > 0);
    try std.testing.expect(seen_public > 0);
    try std.testing.expect(seen_fail > 0);
}

test "PASERK pbkw vectors" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        path: []const u8,
        version: paseto.paserk.Version,
        kind: paseto.paserk.pbkw.Kind,
    }{
        .{ .path = "tests/vectors/k4.local-pw.json", .version = .v4, .kind = .local },
        .{ .path = "tests/vectors/k4.secret-pw.json", .version = .v4, .kind = .secret },
        .{ .path = "tests/vectors/k3.local-pw.json", .version = .v3, .kind = .local },
        .{ .path = "tests/vectors/k3.secret-pw.json", .version = .v3, .kind = .secret },
    };

    var total_processed: usize = 0;
    for (cases) |c| {
        var parsed = try readVectorFile(allocator, c.path);
        defer parsed.deinit();
        const tests = parsed.value.object.get("tests").?.array;
        try std.testing.expect(tests.items.len > 0);
        var processed: usize = 0;
        for (tests.items) |tv| {
            const t = tv.object;
            const name = t.get("name").?.string;
            const expect_fail = t.get("expect-fail").?.bool;
            const password = t.get("password").?.string;
            const paserk_val = t.get("paserk").?;
            const unwrapped_val = t.get("unwrapped").?;
            // An expect-fail vector with a null paserk is expressing
            // "caller cannot even construct this input" — we treat the
            // absence of a paserk as a pass, but assert the shape is
            // consistent.
            if (paserk_val == .null) {
                try std.testing.expect(expect_fail);
                processed += 1;
                continue;
            }
            if (paserk_val != .string) {
                std.debug.print("{s}: paserk is not string-or-null\n", .{name});
                return error.VectorFailed;
            }

            const result = paseto.paserk.pbkw.unwrap(allocator, password, paserk_val.string);
            if (result) |r_val| {
                var r = r_val;
                defer r.deinit();
                // Reject wrong-version PASERKs by treating a mismatch as an
                // intentional "wrong version" negative case.
                const matches = r.version == c.version and r.kind == c.kind;
                if (expect_fail) {
                    if (!matches) {
                        processed += 1;
                        continue;
                    }
                    std.debug.print("{s}: unexpectedly unwrapped\n", .{name});
                    try std.testing.expect(false);
                }
                if (!matches) {
                    std.debug.print("{s}: version/kind mismatch\n", .{name});
                    try std.testing.expect(false);
                }
                if (unwrapped_val == .string) {
                    const expected = try hexAlloc(allocator, unwrapped_val.string);
                    defer allocator.free(expected);
                    try std.testing.expectEqualSlices(u8, expected, r.bytes);
                }
            } else |err| {
                if (!expect_fail) {
                    std.debug.print("{s}: unexpected error {s}\n", .{ name, @errorName(err) });
                    return err;
                }
            }
            processed += 1;
        }
        try std.testing.expectEqual(tests.items.len, processed);
        total_processed += processed;
    }
    try std.testing.expect(total_processed > 0);
}

test "PASERK seal vectors v4" {
    const allocator = std.testing.allocator;
    var parsed = try readVectorFile(allocator, "tests/vectors/k4.seal.json");
    defer parsed.deinit();
    const tests = parsed.value.object.get("tests").?.array;
    try std.testing.expect(tests.items.len > 0);

    var processed: usize = 0;
    for (tests.items) |tv| {
        const t = tv.object;
        const name = t.get("name").?.string;
        const expect_fail = t.get("expect-fail").?.bool;
        const paserk_val = t.get("paserk").?;
        const unsealed_val = t.get("unsealed").?;
        const sk_hex = t.get("sealing-secret-key").?.string;

        // v4 vectors always carry a 64-byte raw Ed25519 secret key (128 hex
        // chars). If we ever see a PEM-encoded variant here it's either a
        // spec change or a typo — fail loudly so we don't silently skip.
        if (sk_hex.len != 128) {
            std.debug.print("{s}: unexpected v4 sealing-secret-key shape len={d}\n", .{ name, sk_hex.len });
            return error.VectorFailed;
        }
        const sk_bytes = try hexToArr(sk_hex, 64);

        if (paserk_val != .string) {
            std.debug.print("{s}: paserk is not a string\n", .{name});
            return error.VectorFailed;
        }
        if (!std.mem.startsWith(u8, paserk_val.string, "k4.seal.")) {
            // Wrong-version vector (expect_fail must be true): unsealing
            // with a v4 key must refuse a k3 paserk.
            try std.testing.expect(expect_fail);
            const result = paseto.paserk.pke.unsealV4FromSecretKey(allocator, sk_bytes, paserk_val.string);
            if (result) |r| {
                allocator.free(r);
                std.debug.print("{s}: unexpectedly unsealed wrong-version\n", .{name});
                try std.testing.expect(false);
            } else |_| {}
            processed += 1;
            continue;
        }

        const result = paseto.paserk.pke.unsealV4FromSecretKey(allocator, sk_bytes, paserk_val.string);
        if (result) |bytes| {
            defer allocator.free(bytes);
            if (expect_fail) {
                std.debug.print("{s}: unexpectedly unsealed\n", .{name});
                try std.testing.expect(false);
            }
            if (unsealed_val == .string) {
                const expected = try hexAlloc(allocator, unsealed_val.string);
                defer allocator.free(expected);
                try std.testing.expectEqualSlices(u8, expected, bytes);
            }
        } else |err| {
            if (!expect_fail) {
                std.debug.print("{s}: unexpected error {s}\n", .{ name, @errorName(err) });
                return err;
            }
        }
        processed += 1;
    }
    try std.testing.expectEqual(tests.items.len, processed);
}

test "PASERK seal vectors v3" {
    const allocator = std.testing.allocator;
    var parsed = try readVectorFile(allocator, "tests/vectors/k3.seal.json");
    defer parsed.deinit();
    const tests = parsed.value.object.get("tests").?.array;
    try std.testing.expect(tests.items.len > 0);

    var processed: usize = 0;
    for (tests.items) |tv| {
        const t = tv.object;
        const name = t.get("name").?.string;
        const expect_fail = t.get("expect-fail").?.bool;
        const paserk_val = t.get("paserk").?;
        const unsealed_val = t.get("unsealed").?;
        const sk_text = t.get("sealing-secret-key").?.string;

        // v3 vectors provide one of three shapes for sealing-secret-key:
        //   * PEM (P-384 EC private key) — the canonical success input
        //   * 96-char hex (raw 48-byte P-384 scalar)
        //   * 128-char hex (raw Ed25519 secret key) — wrong-version vectors
        //     only; we must refuse to unseal their (k4.seal) paserk with a
        //     v3 API.
        var scalar: [48]u8 = undefined;
        if (std.mem.startsWith(u8, sk_text, "-----BEGIN")) {
            var pem_parsed = try paseto.pem.parse(allocator, sk_text);
            defer pem_parsed.deinit();
            if (pem_parsed.format != .p384_scalar or pem_parsed.bytes.len != 48) return error.VectorFailed;
            @memcpy(&scalar, pem_parsed.bytes);
        } else if (sk_text.len == 96) {
            scalar = try hexToArr(sk_text, 48);
        } else if (sk_text.len == 128) {
            // v4 secret key provided; the vector's paserk must be a k4
            // seal that the v3 API can't even open. We document that here
            // and skip the scalar-driven unseal path.
            try std.testing.expect(expect_fail);
            try std.testing.expect(paserk_val == .string);
            try std.testing.expect(!std.mem.startsWith(u8, paserk_val.string, "k3.seal."));
            processed += 1;
            continue;
        } else {
            std.debug.print("{s}: unrecognized sealing-secret-key shape\n", .{name});
            return error.VectorFailed;
        }

        if (paserk_val != .string) {
            std.debug.print("{s}: paserk is not a string\n", .{name});
            return error.VectorFailed;
        }
        if (!std.mem.startsWith(u8, paserk_val.string, "k3.seal.")) {
            try std.testing.expect(expect_fail);
            const result = paseto.paserk.pke.unsealV3(allocator, scalar, paserk_val.string);
            if (result) |r| {
                allocator.free(r);
                std.debug.print("{s}: unexpectedly unsealed wrong-version\n", .{name});
                try std.testing.expect(false);
            } else |_| {}
            processed += 1;
            continue;
        }

        const result = paseto.paserk.pke.unsealV3(allocator, scalar, paserk_val.string);
        if (result) |bytes| {
            defer allocator.free(bytes);
            if (expect_fail) {
                std.debug.print("{s}: unexpectedly unsealed\n", .{name});
                try std.testing.expect(false);
            }
            if (unsealed_val == .string) {
                const expected = try hexAlloc(allocator, unsealed_val.string);
                defer allocator.free(expected);
                try std.testing.expectEqualSlices(u8, expected, bytes);
            }
        } else |err| {
            if (!expect_fail) {
                std.debug.print("{s}: unexpected error {s}\n", .{ name, @errorName(err) });
                return err;
            }
        }
        processed += 1;
    }
    try std.testing.expectEqual(tests.items.len, processed);
}

test "PASERK pie wrap vectors" {
    const allocator = std.testing.allocator;
    const Version = paseto.paserk.Version;
    const Kind = paseto.paserk.pie.Kind;

    const cases = [_]struct {
        path: []const u8,
        version: Version,
        kind: Kind,
    }{
        .{ .path = "tests/vectors/k3.local-wrap.pie.json", .version = .v3, .kind = .local },
        .{ .path = "tests/vectors/k3.secret-wrap.pie.json", .version = .v3, .kind = .secret },
        .{ .path = "tests/vectors/k4.local-wrap.pie.json", .version = .v4, .kind = .local },
        .{ .path = "tests/vectors/k4.secret-wrap.pie.json", .version = .v4, .kind = .secret },
    };

    var total_processed: usize = 0;
    for (cases) |c| {
        var parsed = try readVectorFile(allocator, c.path);
        defer parsed.deinit();
        const tests = parsed.value.object.get("tests").?.array;
        try std.testing.expect(tests.items.len > 0);
        var processed: usize = 0;
        for (tests.items) |tv| {
            const t = tv.object;
            const name = t.get("name").?.string;
            const expect_fail = t.get("expect-fail").?.bool;
            const wrapping_hex = t.get("wrapping-key").?.string;
            const paserk_val = t.get("paserk").?;
            const unwrapped_val = t.get("unwrapped").?;

            const wrapping = try hexAlloc(allocator, wrapping_hex);
            defer allocator.free(wrapping);

            if (paserk_val == .null) {
                try std.testing.expect(expect_fail);
                processed += 1;
                continue;
            }
            if (paserk_val != .string) {
                std.debug.print("{s}: paserk is not string-or-null\n", .{name});
                return error.VectorFailed;
            }

            const result = paseto.paserk.pie.unwrap(allocator, wrapping, paserk_val.string);
            if (result) |r_val| {
                var r = r_val;
                defer r.deinit();
                // Vector files carry a specific version — treat mismatches
                // as the "PASERK of the wrong version" failure mode.
                const matches = r.version == c.version and r.kind == c.kind;
                if (expect_fail) {
                    if (!matches) {
                        processed += 1;
                        continue;
                    }
                    std.debug.print("{s}: unexpectedly unwrapped\n", .{name});
                    try std.testing.expect(false);
                }
                if (!matches) {
                    std.debug.print("{s}: version/kind mismatch\n", .{name});
                    try std.testing.expect(false);
                }
                if (unwrapped_val == .string) {
                    const expected = try hexAlloc(allocator, unwrapped_val.string);
                    defer allocator.free(expected);
                    try std.testing.expectEqualSlices(u8, expected, r.bytes);
                }
            } else |err| {
                if (!expect_fail) {
                    std.debug.print("{s}: unexpected error {s}\n", .{ name, @errorName(err) });
                    return err;
                }
            }
            processed += 1;
        }
        try std.testing.expectEqual(tests.items.len, processed);
        total_processed += processed;
    }
    try std.testing.expect(total_processed > 0);
}

test "PASERK id vectors" {
    const allocator = std.testing.allocator;
    const Version = paseto.paserk.Version;
    const IdKind = paseto.paserk.IdKind;

    const cases = [_]struct {
        path: []const u8,
        version: Version,
        kind: IdKind,
    }{
        .{ .path = "tests/vectors/k4.lid.json", .version = .v4, .kind = .lid },
        .{ .path = "tests/vectors/k4.sid.json", .version = .v4, .kind = .sid },
        .{ .path = "tests/vectors/k4.pid.json", .version = .v4, .kind = .pid },
        .{ .path = "tests/vectors/k3.lid.json", .version = .v3, .kind = .lid },
        .{ .path = "tests/vectors/k3.sid.json", .version = .v3, .kind = .sid },
        .{ .path = "tests/vectors/k3.pid.json", .version = .v3, .kind = .pid },
    };

    var total_processed: usize = 0;
    for (cases) |c| {
        var parsed = try readVectorFile(allocator, c.path);
        defer parsed.deinit();
        const tests = parsed.value.object.get("tests").?.array;
        try std.testing.expect(tests.items.len > 0);
        var processed: usize = 0;
        for (tests.items) |tv| {
            const t = tv.object;
            const name = t.get("name").?.string;
            const expect_fail = t.get("expect-fail").?.bool;
            const key_hex = t.get("key").?.string;
            const expected_paserk = getOptionalString(t, "paserk");

            const key_bytes = try hexAlloc(allocator, key_hex);
            defer allocator.free(key_bytes);

            const result = paseto.paserk.id.compute(allocator, c.version, c.kind, key_bytes);
            if (result) |produced| {
                defer allocator.free(produced);
                if (expect_fail) {
                    std.debug.print("vector {s}: unexpectedly produced {s}\n", .{ name, produced });
                    try std.testing.expect(false);
                }
                if (expected_paserk) |exp| {
                    if (!std.mem.eql(u8, produced, exp)) {
                        std.debug.print("{s}: produced {s}, expected {s}\n", .{ name, produced, exp });
                        try std.testing.expect(false);
                    }
                }
            } else |err| {
                if (!expect_fail) {
                    std.debug.print("vector {s}: unexpected error {s}\n", .{ name, @errorName(err) });
                    return err;
                }
            }
            processed += 1;
        }
        try std.testing.expectEqual(tests.items.len, processed);
        total_processed += processed;
    }
    try std.testing.expect(total_processed > 0);
}

test "PASETO v3 vectors" {
    const allocator = std.testing.allocator;
    var parsed = try readVectorFile(allocator, "tests/vectors/v3.json");
    defer parsed.deinit();
    const root = parsed.value.object;
    const tests = root.get("tests").?.array;
    try std.testing.expect(tests.items.len > 0);

    var seen_local: usize = 0;
    var seen_public: usize = 0;
    var seen_fail: usize = 0;
    for (tests.items) |test_val| {
        const t = test_val.object;
        const name = t.get("name").?.string;
        const expect_fail = t.get("expect-fail").?.bool;
        const token = t.get("token").?.string;
        const footer = t.get("footer").?.string;
        const implicit_assertion = t.get("implicit-assertion").?.string;

        if (std.mem.startsWith(u8, name, "3-E-")) {
            try runV3Local(allocator, name, t, token, footer, implicit_assertion, expect_fail);
            seen_local += 1;
        } else if (std.mem.startsWith(u8, name, "3-S-")) {
            try runV3Public(allocator, name, t, token, footer, implicit_assertion, expect_fail);
            seen_public += 1;
        } else if (std.mem.startsWith(u8, name, "3-F-")) {
            try runV3Fail(allocator, name, t, token, footer, implicit_assertion);
            seen_fail += 1;
        } else {
            std.debug.print("unrecognized v3 vector: {s}\n", .{name});
            return error.VectorFailed;
        }
    }
    try std.testing.expect(seen_local > 0);
    try std.testing.expect(seen_public > 0);
    try std.testing.expect(seen_fail > 0);
}

fn runV3Local(
    allocator: std.mem.Allocator,
    name: []const u8,
    t: std.json.ObjectMap,
    token: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
    expect_fail: bool,
) !void {
    const key_bytes = try hexToArr(t.get("key").?.string, 32);
    const nonce_bytes = try hexToArr(t.get("nonce").?.string, 32);
    const key = paseto.v3.Local{ .key = key_bytes };

    const payload_val = t.get("payload").?;
    if (payload_val == .string) {
        const produced = try key.encrypt(allocator, payload_val.string, .{
            .footer = footer,
            .implicit_assertion = implicit_assertion,
            .nonce = nonce_bytes,
        });
        defer allocator.free(produced);
        if (!std.mem.eql(u8, produced, token)) {
            std.debug.print("vector {s}: produced {s} != {s}\n", .{ name, produced, token });
            try std.testing.expect(false);
        }
    }

    if (key.decrypt(allocator, token, implicit_assertion)) |decrypted| {
        defer allocator.free(decrypted);
        try std.testing.expect(!expect_fail);
        if (payload_val == .string) {
            try std.testing.expectEqualStrings(payload_val.string, decrypted);
        }
    } else |err| {
        if (!expect_fail) {
            std.debug.print("vector {s}: unexpected error {s}\n", .{ name, @errorName(err) });
            return err;
        }
    }
}

fn runV3Public(
    allocator: std.mem.Allocator,
    name: []const u8,
    t: std.json.ObjectMap,
    token: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
    expect_fail: bool,
) !void {
    _ = name;
    const pk_hex = t.get("public-key").?.string;
    const sk_hex = t.get("secret-key").?.string;
    const pk_bytes = try hexAlloc(allocator, pk_hex);
    defer allocator.free(pk_bytes);
    const sk_bytes = try hexAlloc(allocator, sk_hex);
    defer allocator.free(sk_bytes);

    const signer = try paseto.v3.Public.fromScalarBytes(sk_bytes);
    const verifier = try paseto.v3.Public.fromPublicBytes(pk_bytes);

    const payload_val = t.get("payload").?;
    if (payload_val == .string and !expect_fail) {
        // ECDSA P-384 in Zig is randomized, so we can only verify round-trip
        // equality — signing twice won't produce the same bytes. Verify with
        // the expected token to confirm PAE/key machinery.
        const produced = try signer.sign(allocator, payload_val.string, .{
            .footer = footer,
            .implicit_assertion = implicit_assertion,
        });
        defer allocator.free(produced);
        const check = try verifier.verify(allocator, produced, implicit_assertion);
        defer allocator.free(check);
        try std.testing.expectEqualStrings(payload_val.string, check);
    }

    if (verifier.verify(allocator, token, implicit_assertion)) |verified| {
        defer allocator.free(verified);
        try std.testing.expect(!expect_fail);
        if (payload_val == .string) {
            try std.testing.expectEqualStrings(payload_val.string, verified);
        }
    } else |_| {
        try std.testing.expect(expect_fail);
    }
}

fn runV3Fail(
    allocator: std.mem.Allocator,
    name: []const u8,
    t: std.json.ObjectMap,
    token: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
) !void {
    _ = footer;
    var exercised: usize = 0;

    if (getOptionalString(t, "key")) |key_hex| {
        const key_bytes = try hexToArr(key_hex, 32);
        const key = paseto.v3.Local{ .key = key_bytes };
        if (key.decrypt(allocator, token, implicit_assertion)) |v| {
            allocator.free(v);
            std.debug.print("vector {s}: unexpectedly decrypted\n", .{name});
            try std.testing.expect(false);
        } else |_| {}
        exercised += 1;
    }

    if (getOptionalString(t, "public-key")) |pk_hex| {
        const pk_bytes = try hexAlloc(allocator, pk_hex);
        defer allocator.free(pk_bytes);
        if (paseto.v3.Public.fromPublicBytes(pk_bytes)) |verifier| {
            if (verifier.verify(allocator, token, implicit_assertion)) |v| {
                allocator.free(v);
                std.debug.print("vector {s}: unexpectedly verified\n", .{name});
                try std.testing.expect(false);
            } else |_| {}
        } else |_| {}
        exercised += 1;
    }

    if (exercised == 0) {
        std.debug.print("{s}: fail vector has no key or public-key\n", .{name});
        return error.VectorFailed;
    }
}

fn runV4Local(
    allocator: std.mem.Allocator,
    name: []const u8,
    t: std.json.ObjectMap,
    token: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
    expect_fail: bool,
) !void {
    const key_bytes = try hexToArr(t.get("key").?.string, 32);
    const nonce_bytes = try hexToArr(t.get("nonce").?.string, 32);

    const key = paseto.v4.Local{ .key = key_bytes };

    // Re-encrypt the plaintext to confirm we produce the exact token.
    const payload_val = t.get("payload").?;
    if (payload_val == .string) {
        const plaintext = payload_val.string;
        const produced = try key.encrypt(allocator, plaintext, .{
            .footer = footer,
            .implicit_assertion = implicit_assertion,
            .nonce = nonce_bytes,
        });
        defer allocator.free(produced);
        if (!std.mem.eql(u8, produced, token)) {
            std.debug.print("vector {s}: produced {s} != {s}\n", .{ name, produced, token });
            try std.testing.expect(false);
        }
    }

    // Decrypt the token; should return the original plaintext.
    if (key.decrypt(allocator, token, implicit_assertion)) |decrypted| {
        defer allocator.free(decrypted);
        try std.testing.expect(!expect_fail);
        if (payload_val == .string) {
            try std.testing.expectEqualStrings(payload_val.string, decrypted);
        }
    } else |err| {
        if (!expect_fail) {
            std.debug.print("vector {s}: unexpected error {s}\n", .{ name, @errorName(err) });
            return err;
        }
    }
}

fn runV4Public(
    allocator: std.mem.Allocator,
    name: []const u8,
    t: std.json.ObjectMap,
    token: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
    expect_fail: bool,
) !void {
    const pk_bytes = try hexToArr(t.get("public-key").?.string, 32);
    const sk_bytes = try hexToArr(t.get("secret-key").?.string, 64);

    const signer = try paseto.v4.Public.fromSecretKeyBytes(&sk_bytes);
    const verifier = try paseto.v4.Public.fromPublicKeyBytes(&pk_bytes);

    const payload_val = t.get("payload").?;
    if (payload_val == .string) {
        // Sign and compare byte-for-byte; Ed25519 is deterministic.
        const produced = try signer.sign(allocator, payload_val.string, .{
            .footer = footer,
            .implicit_assertion = implicit_assertion,
        });
        defer allocator.free(produced);
        if (!std.mem.eql(u8, produced, token)) {
            std.debug.print("vector {s}: produced {s} != {s}\n", .{ name, produced, token });
            try std.testing.expect(false);
        }
    }

    if (verifier.verify(allocator, token, implicit_assertion)) |verified| {
        defer allocator.free(verified);
        try std.testing.expect(!expect_fail);
        if (payload_val == .string) {
            try std.testing.expectEqualStrings(payload_val.string, verified);
        }
    } else |err| {
        if (!expect_fail) {
            std.debug.print("vector {s}: unexpected error {s}\n", .{ name, @errorName(err) });
            return err;
        }
    }
}

fn runV4Fail(
    allocator: std.mem.Allocator,
    name: []const u8,
    t: std.json.ObjectMap,
    token: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
) !void {
    _ = footer;
    // Fail-vectors may deliberately mix key types with tokens (e.g. a v4.local
    // token paired with a v4.public key to prove the library rejects purpose
    // mismatches). Try whichever key material the vector supplies; every
    // attempt must fail.
    var exercised: usize = 0;

    if (getOptionalString(t, "key")) |key_hex| {
        const key_bytes = try hexToArr(key_hex, 32);
        const key = paseto.v4.Local{ .key = key_bytes };
        if (key.decrypt(allocator, token, implicit_assertion)) |v| {
            allocator.free(v);
            std.debug.print("vector {s}: unexpectedly decrypted\n", .{name});
            try std.testing.expect(false);
        } else |_| {}
        exercised += 1;
    }

    if (getOptionalString(t, "public-key")) |pk_hex| {
        const pk_bytes = try hexToArr(pk_hex, 32);
        if (paseto.v4.Public.fromPublicKeyBytes(&pk_bytes)) |verifier| {
            if (verifier.verify(allocator, token, implicit_assertion)) |v| {
                allocator.free(v);
                std.debug.print("vector {s}: unexpectedly verified\n", .{name});
                try std.testing.expect(false);
            } else |_| {}
        } else |_| {}
        exercised += 1;
    }

    if (exercised == 0) {
        std.debug.print("{s}: fail vector has no key or public-key\n", .{name});
        return error.VectorFailed;
    }
}
