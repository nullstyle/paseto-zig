//! Password-based key wrapping (`local-pw`, `secret-pw`). Uses Argon2id for
//! v4 and PBKDF2-SHA384 for v3.

const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");
const keys = @import("keys.zig");

pub const Error = errors.Error;
pub const Version = token_mod.Version;

const Blake2b = std.crypto.hash.blake2.Blake2b;
const Sha384 = std.crypto.hash.sha2.Sha384;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const Aes256 = std.crypto.core.aes.Aes256;
const XChaCha20IETF = std.crypto.stream.chacha.XChaCha20IETF;
const pbkdf2 = std.crypto.pwhash.pbkdf2;
const argon2 = std.crypto.pwhash.argon2;

const DOMAIN_SEPARATOR_ENCRYPT: u8 = 0xFF;
const DOMAIN_SEPARATOR_AUTH: u8 = 0xFE;

/// Re-export of the shared `WrappedKind` so existing callers that address
/// PBKW-specific types directly keep working.
pub const Kind = keys.WrappedKind;

pub const V4Params = struct {
    memlimit_bytes: u64,
    opslimit: u32,
    /// Parallelism factor. PASERK fixes this at 1.
    para: u32 = 1,
};

pub const V3Params = struct {
    iterations: u32,
};

fn paserkHeader(version: Version, kind: Kind) []const u8 {
    return switch (version) {
        .v3 => switch (kind) {
            .local => "k3.local-pw",
            .secret => "k3.secret-pw",
        },
        .v4 => switch (kind) {
            .local => "k4.local-pw",
            .secret => "k4.secret-pw",
        },
    };
}

fn validatePtk(version: Version, kind: Kind, len: usize) !void {
    switch (version) {
        .v3 => switch (kind) {
            .local => if (len != 32) return Error.InvalidKey,
            .secret => if (len != 48) return Error.InvalidKey,
        },
        .v4 => switch (kind) {
            .local => if (len != 32) return Error.InvalidKey,
            .secret => if (len != 64) return Error.InvalidKey,
        },
    }
}

pub const WrapOptionsV4 = struct {
    params: V4Params,
    /// Deterministic salt & nonce for test reproducibility.
    salt: ?[16]u8 = null,
    nonce: ?[24]u8 = null,
};

pub const WrapOptionsV3 = struct {
    params: V3Params,
    salt: ?[32]u8 = null,
    nonce: ?[16]u8 = null,
};

pub fn wrapV4(
    allocator: std.mem.Allocator,
    kind: Kind,
    password: []const u8,
    ptk: []const u8,
    opts: WrapOptionsV4,
) ![]u8 {
    try validatePtk(.v4, kind, ptk.len);

    var salt: [16]u8 = undefined;
    var nonce: [24]u8 = undefined;
    if (opts.salt) |s| {
        @memcpy(&salt, &s);
    } else util.randomBytes(&salt);
    if (opts.nonce) |n| {
        @memcpy(&nonce, &n);
    } else util.randomBytes(&nonce);

    var pre_key: [32]u8 = undefined;
    try argon2id(allocator, &pre_key, password, &salt, opts.params);

    const edk = try allocator.alloc(u8, ptk.len);
    defer allocator.free(edk);
    try encryptV4(&pre_key, nonce, ptk, edk);

    const header = paserkHeader(.v4, kind);
    const body = try composeV4Body(allocator, header, &salt, opts.params, &nonce, edk, &pre_key);
    defer allocator.free(body);
    return try encodePaserk(allocator, header, body);
}

pub fn wrapV3(
    allocator: std.mem.Allocator,
    kind: Kind,
    password: []const u8,
    ptk: []const u8,
    opts: WrapOptionsV3,
) ![]u8 {
    try validatePtk(.v3, kind, ptk.len);
    try validateV3Params(opts.params);

    var salt: [32]u8 = undefined;
    var nonce: [16]u8 = undefined;
    if (opts.salt) |s| {
        @memcpy(&salt, &s);
    } else util.randomBytes(&salt);
    if (opts.nonce) |n| {
        @memcpy(&nonce, &n);
    } else util.randomBytes(&nonce);

    var pre_key: [32]u8 = undefined;
    pbkdf2(&pre_key, password, &salt, opts.params.iterations, HmacSha384) catch
        return Error.WeakParameters;

    const edk = try allocator.alloc(u8, ptk.len);
    defer allocator.free(edk);
    try encryptV3(&pre_key, nonce, ptk, edk);

    const header = paserkHeader(.v3, kind);
    const body = try composeV3Body(allocator, header, &salt, opts.params, &nonce, edk, &pre_key);
    defer allocator.free(body);
    return try encodePaserk(allocator, header, body);
}

/// Re-export of `paserk.keys.UnwrappedKey` so `paseto.paserk.pbkw.Unwrapped`
/// continues to resolve for existing callers.
pub const Unwrapped = keys.UnwrappedKey;

pub fn unwrap(
    allocator: std.mem.Allocator,
    password: []const u8,
    paserk: []const u8,
) !Unwrapped {
    // Parse header: version.kind.base64
    const first_dot = std.mem.indexOfScalar(u8, paserk, '.') orelse return Error.InvalidEncoding;
    const version_s = paserk[0..first_dot];
    const rest = paserk[first_dot + 1 ..];
    const second_dot = std.mem.indexOfScalar(u8, rest, '.') orelse return Error.InvalidEncoding;
    const kind_s = rest[0..second_dot];
    const data_s = rest[second_dot + 1 ..];

    const version = Version.fromPaserkPrefix(version_s) orelse return Error.UnsupportedVersion;
    const kind: Kind = if (std.mem.eql(u8, kind_s, "local-pw"))
        .local
    else if (std.mem.eql(u8, kind_s, "secret-pw"))
        .secret
    else
        return Error.UnsupportedOperation;

    const body = try util.decodeBase64Alloc(allocator, data_s);
    defer allocator.free(body);

    switch (version) {
        .v3 => return try unwrapV3(allocator, password, kind, body),
        .v4 => return try unwrapV4(allocator, password, kind, body),
    }
}

fn unwrapV4(
    allocator: std.mem.Allocator,
    password: []const u8,
    kind: Kind,
    body: []const u8,
) !Unwrapped {
    const min_len = 16 + 8 + 4 + 4 + 24 + 32;
    if (body.len < min_len) return Error.MessageTooShort;

    const salt = body[0..16];
    const memlimit = util.readBE(u64, body[16..24]);
    const opslimit = util.readBE(u32, body[24..28]);
    const para = util.readBE(u32, body[28..32]);
    const nonce = body[32..56];
    const edk = body[56 .. body.len - 32];
    const tag = body[body.len - 32 ..];

    try validatePtk(.v4, kind, edk.len);

    const params: V4Params = .{
        .memlimit_bytes = memlimit,
        .opslimit = opslimit,
        .para = para,
    };

    var pre_key: [32]u8 = undefined;
    try argon2id(allocator, &pre_key, password, salt, params);

    const header = paserkHeader(.v4, kind);

    var expected_tag: [32]u8 = undefined;
    macV4(&pre_key, header, salt, params, nonce, edk, &expected_tag);
    if (!util.constantTimeEqual(tag, &expected_tag)) return Error.InvalidAuthenticator;

    const out = try allocator.alloc(u8, edk.len);
    errdefer allocator.free(out);
    var nonce_arr: [24]u8 = undefined;
    @memcpy(&nonce_arr, nonce);
    try encryptV4(&pre_key, nonce_arr, edk, out);
    return .{ .version = .v4, .kind = kind, .bytes = out, .allocator = allocator };
}

fn unwrapV3(
    allocator: std.mem.Allocator,
    password: []const u8,
    kind: Kind,
    body: []const u8,
) !Unwrapped {
    const min_len = 32 + 4 + 16 + 48;
    if (body.len < min_len) return Error.MessageTooShort;

    const salt = body[0..32];
    const iterations = util.readBE(u32, body[32..36]);
    const nonce = body[36..52];
    const edk = body[52 .. body.len - 48];
    const tag = body[body.len - 48 ..];

    try validatePtk(.v3, kind, edk.len);

    const params: V3Params = .{ .iterations = iterations };
    try validateV3Params(params);

    var pre_key: [32]u8 = undefined;
    pbkdf2(&pre_key, password, salt, iterations, HmacSha384) catch
        return Error.WeakParameters;

    const header = paserkHeader(.v3, kind);
    var expected_tag: [48]u8 = undefined;
    macV3(&pre_key, header, salt, params, nonce, edk, &expected_tag);
    if (!util.constantTimeEqual(tag, &expected_tag)) return Error.InvalidAuthenticator;

    const out = try allocator.alloc(u8, edk.len);
    errdefer allocator.free(out);
    var nonce_arr: [16]u8 = undefined;
    @memcpy(&nonce_arr, nonce);
    try encryptV3(&pre_key, nonce_arr, edk, out);
    return .{ .version = .v3, .kind = kind, .bytes = out, .allocator = allocator };
}

fn validateV4Params(params: V4Params) !void {
    // PASERK fixes the Argon2 parallelism factor at 1; any other value is
    // a caller error.
    if (params.para != 1) return Error.WeakParameters;
    if (params.opslimit == 0) return Error.WeakParameters;
    // Argon2 measures memory in KiB, and the PASERK wire format records the
    // memlimit as bytes. Round-trip requires the caller's bytes value to be
    // an exact multiple of 1024; otherwise the wrapped + unwrapped inputs
    // would disagree after truncation.
    if (params.memlimit_bytes < 1024) return Error.WeakParameters;
    if (params.memlimit_bytes % 1024 != 0) return Error.WeakParameters;
    if (params.memlimit_bytes / 1024 > std.math.maxInt(u32)) return Error.WeakParameters;
}

fn validateV3Params(params: V3Params) !void {
    if (params.iterations == 0) return Error.WeakParameters;
}

fn argon2id(
    allocator: std.mem.Allocator,
    out: []u8,
    password: []const u8,
    salt: []const u8,
    params: V4Params,
) !void {
    try validateV4Params(params);
    const memory_kib: u32 = @intCast(params.memlimit_bytes / 1024);
    const argon_params: argon2.Params = .{
        .t = params.opslimit,
        .m = memory_kib,
        .p = @intCast(params.para),
    };
    const io = std.Io.Threaded.global_single_threaded.io();
    argon2.kdf(allocator, out, password, salt, argon_params, .argon2id, io) catch |err| switch (err) {
        // Caller-parameter mistakes that slip past our pre-checks stay as
        // WeakParameters.
        error.WeakParameters => return Error.WeakParameters,
        error.OutputTooLong => return Error.WeakParameters,
        error.Canceled => return Error.Canceled,
        // Any other Argon2 runtime failure (e.g. out-of-memory for large
        // memlimits) is collapsed into Error.OutOfMemory: the public error
        // set does not currently distinguish them, and widening it is out
        // of scope for this hardening pass.
        else => return Error.OutOfMemory,
    };
}

fn encryptV4(pre_key: []const u8, nonce: [24]u8, src: []const u8, dst: []u8) !void {
    std.debug.assert(src.len == dst.len);
    var ek: [32]u8 = undefined;
    var h = Blake2b(32 * 8).init(.{});
    var sep = [_]u8{DOMAIN_SEPARATOR_ENCRYPT};
    h.update(&sep);
    h.update(pre_key);
    h.final(&ek);
    XChaCha20IETF.xor(dst, src, 0, ek, nonce);
}

fn encryptV3(pre_key: []const u8, nonce: [16]u8, src: []const u8, dst: []u8) !void {
    std.debug.assert(src.len == dst.len);
    var ek_full: [48]u8 = undefined;
    var h = Sha384.init(.{});
    var sep = [_]u8{DOMAIN_SEPARATOR_ENCRYPT};
    h.update(&sep);
    h.update(pre_key);
    h.final(&ek_full);
    var ek: [32]u8 = undefined;
    @memcpy(&ek, ek_full[0..32]);
    const enc = Aes256.initEnc(ek);
    std.crypto.core.modes.ctr(@TypeOf(enc), enc, dst, src, nonce, .big);
}

fn macV4(
    pre_key: []const u8,
    header: []const u8,
    salt: []const u8,
    params: V4Params,
    nonce: []const u8,
    edk: []const u8,
    out: []u8,
) void {
    std.debug.assert(out.len == 32);
    var ak: [32]u8 = undefined;
    var ak_hash = Blake2b(32 * 8).init(.{});
    var sep_a = [_]u8{DOMAIN_SEPARATOR_AUTH};
    ak_hash.update(&sep_a);
    ak_hash.update(pre_key);
    ak_hash.final(&ak);

    var tag_hash = Blake2b(32 * 8).init(.{ .key = &ak });
    tag_hash.update(header);
    tag_hash.update(".");
    tag_hash.update(salt);
    const memlimit_be = util.be64(params.memlimit_bytes);
    tag_hash.update(&memlimit_be);
    const opslimit_be = util.be32(params.opslimit);
    tag_hash.update(&opslimit_be);
    const para_be = util.be32(params.para);
    tag_hash.update(&para_be);
    tag_hash.update(nonce);
    tag_hash.update(edk);
    tag_hash.final(out[0..32]);
}

fn macV3(
    pre_key: []const u8,
    header: []const u8,
    salt: []const u8,
    params: V3Params,
    nonce: []const u8,
    edk: []const u8,
    out: []u8,
) void {
    std.debug.assert(out.len == 48);
    var ak: [48]u8 = undefined;
    var ak_hash = Sha384.init(.{});
    var sep_a = [_]u8{DOMAIN_SEPARATOR_AUTH};
    ak_hash.update(&sep_a);
    ak_hash.update(pre_key);
    ak_hash.final(&ak);

    var tag = HmacSha384.init(&ak);
    tag.update(header);
    tag.update(".");
    tag.update(salt);
    const iter_be = util.be32(params.iterations);
    tag.update(&iter_be);
    tag.update(nonce);
    tag.update(edk);
    var full: [48]u8 = undefined;
    tag.final(&full);
    @memcpy(out[0..48], &full);
}

fn composeV4Body(
    allocator: std.mem.Allocator,
    header: []const u8,
    salt: []const u8,
    params: V4Params,
    nonce: []const u8,
    edk: []const u8,
    pre_key: []const u8,
) ![]u8 {
    const len = 16 + 8 + 4 + 4 + 24 + edk.len + 32;
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    var idx: usize = 0;
    @memcpy(out[idx..][0..16], salt);
    idx += 16;
    const memlimit_be = util.be64(params.memlimit_bytes);
    @memcpy(out[idx..][0..8], &memlimit_be);
    idx += 8;
    const opslimit_be = util.be32(params.opslimit);
    @memcpy(out[idx..][0..4], &opslimit_be);
    idx += 4;
    const para_be = util.be32(params.para);
    @memcpy(out[idx..][0..4], &para_be);
    idx += 4;
    @memcpy(out[idx..][0..24], nonce);
    idx += 24;
    @memcpy(out[idx..][0..edk.len], edk);
    idx += edk.len;
    var tag: [32]u8 = undefined;
    macV4(pre_key, header, salt, params, nonce, edk, &tag);
    @memcpy(out[idx..][0..32], &tag);
    return out;
}

fn composeV3Body(
    allocator: std.mem.Allocator,
    header: []const u8,
    salt: []const u8,
    params: V3Params,
    nonce: []const u8,
    edk: []const u8,
    pre_key: []const u8,
) ![]u8 {
    const len = 32 + 4 + 16 + edk.len + 48;
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    var idx: usize = 0;
    @memcpy(out[idx..][0..32], salt);
    idx += 32;
    const iter_be = util.be32(params.iterations);
    @memcpy(out[idx..][0..4], &iter_be);
    idx += 4;
    @memcpy(out[idx..][0..16], nonce);
    idx += 16;
    @memcpy(out[idx..][0..edk.len], edk);
    idx += edk.len;
    var tag: [48]u8 = undefined;
    macV3(pre_key, header, salt, params, nonce, edk, &tag);
    @memcpy(out[idx..][0..48], &tag);
    return out;
}

fn encodePaserk(allocator: std.mem.Allocator, header: []const u8, body: []const u8) ![]u8 {
    const encoded_len = util.encodedBase64Len(body.len);
    const out = try allocator.alloc(u8, header.len + 1 + encoded_len);
    errdefer allocator.free(out);
    @memcpy(out[0..header.len], header);
    out[header.len] = '.';
    _ = util.encodeBase64(out[header.len + 1 ..][0..encoded_len], body);
    return out;
}

test "wrapV4 rejects non-KiB-aligned memlimit_bytes" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x11);
    try std.testing.expectError(Error.WeakParameters, wrapV4(allocator, .local, "pw", &key, .{
        .params = .{ .memlimit_bytes = 1500, .opslimit = 2 },
        .salt = @as([16]u8, @splat(0x22)),
        .nonce = @as([24]u8, @splat(0x33)),
    }));
}

test "wrapV4 rejects memlimit_bytes below 1 KiB" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x11);
    try std.testing.expectError(Error.WeakParameters, wrapV4(allocator, .local, "pw", &key, .{
        .params = .{ .memlimit_bytes = 512, .opslimit = 2 },
        .salt = @as([16]u8, @splat(0x22)),
        .nonce = @as([24]u8, @splat(0x33)),
    }));
}

test "wrapV4 rejects zero opslimit" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x11);
    try std.testing.expectError(Error.WeakParameters, wrapV4(allocator, .local, "pw", &key, .{
        .params = .{ .memlimit_bytes = 64 * 1024 * 1024, .opslimit = 0 },
        .salt = @as([16]u8, @splat(0x22)),
        .nonce = @as([24]u8, @splat(0x33)),
    }));
}

test "wrapV4 rejects parallelism != 1" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x11);
    try std.testing.expectError(Error.WeakParameters, wrapV4(allocator, .local, "pw", &key, .{
        .params = .{ .memlimit_bytes = 64 * 1024 * 1024, .opslimit = 2, .para = 2 },
        .salt = @as([16]u8, @splat(0x22)),
        .nonce = @as([24]u8, @splat(0x33)),
    }));
}

test "wrapV3 rejects zero iterations" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x11);
    try std.testing.expectError(Error.WeakParameters, wrapV3(allocator, .local, "pw", &key, .{
        .params = .{ .iterations = 0 },
        .salt = @as([32]u8, @splat(0x22)),
        .nonce = @as([16]u8, @splat(0x33)),
    }));
}

test "unwrap rejects non-KiB-aligned memlimit from malicious paserk" {
    const allocator = std.testing.allocator;
    // Hand-craft a body with memlimit_bytes = 1500 so decoding must bail
    // before running Argon2.
    var body: [16 + 8 + 4 + 4 + 24 + 32 + 32]u8 = undefined;
    @memset(&body, 0);
    const memlimit_be = util.be64(1500);
    @memcpy(body[16..24], &memlimit_be);
    const opslimit_be = util.be32(2);
    @memcpy(body[24..28], &opslimit_be);
    const para_be = util.be32(1);
    @memcpy(body[28..32], &para_be);

    const encoded_len = util.encodedBase64Len(body.len);
    const paserk = try allocator.alloc(u8, "k4.local-pw.".len + encoded_len);
    defer allocator.free(paserk);
    @memcpy(paserk[0.."k4.local-pw.".len], "k4.local-pw.");
    _ = util.encodeBase64(paserk["k4.local-pw.".len..][0..encoded_len], &body);

    try std.testing.expectError(Error.WeakParameters, unwrap(allocator, "pw", paserk));
}
