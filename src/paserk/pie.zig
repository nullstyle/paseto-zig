//! PASERK PIE wrapping: symmetric-key wrapping for local or secret keys.

const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const keys = @import("keys.zig");
const token_mod = @import("../token.zig");

pub const Error = errors.Error;
pub const Version = token_mod.Version;

const Blake2b = std.crypto.hash.blake2.Blake2b;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const Aes256 = std.crypto.core.aes.Aes256;
const XChaCha20IETF = std.crypto.stream.chacha.XChaCha20IETF;

const DOMAIN_SEPARATOR_AUTH: u8 = 0x81;
const DOMAIN_SEPARATOR_ENCRYPT: u8 = 0x80;

const nonce_bytes = 32;

/// Re-export of the shared `WrappedKind` for backward compatibility with
/// callers that address PIE-specific types directly.
pub const Kind = keys.WrappedKind;

pub const WrapOptions = struct {
    /// Deterministic nonce for test vectors. Production code should leave
    /// this null.
    nonce: ?[nonce_bytes]u8 = null,
};

/// Wrap `ptk` (plaintext key) with the symmetric wrapping key using the PIE
/// construction. The resulting PASERK string is allocator-owned.
pub fn wrap(
    allocator: std.mem.Allocator,
    version: Version,
    kind: Kind,
    wrapping_key: []const u8,
    ptk: []const u8,
    opts: WrapOptions,
) ![]u8 {
    try validateWrappingKey(wrapping_key.len);
    try validatePtkMaterial(version, kind, ptk);

    var nonce: [nonce_bytes]u8 = undefined;
    if (opts.nonce) |n| {
        @memcpy(&nonce, &n);
    } else {
        util.randomBytes(&nonce);
    }

    const mac_len = switch (version) {
        .v3 => @as(usize, 48),
        .v4 => @as(usize, 32),
    };

    const header = paserkHeader(version, kind);

    // Encrypt in place into a ciphertext buffer.
    const ciphertext = try allocator.alloc(u8, ptk.len);
    defer util.secureFree(allocator, ciphertext);
    try encryptPayload(version, wrapping_key, nonce, ptk, ciphertext);

    // tag = MAC(header || nonce || ciphertext, key = ak)
    var mac_buf: [48]u8 = undefined;
    try macBody(version, wrapping_key, nonce, header, ciphertext, mac_buf[0..mac_len]);

    // Encoded body: tag || nonce || ciphertext
    const body_len = mac_len + nonce_bytes + ciphertext.len;
    const body = try allocator.alloc(u8, body_len);
    defer util.secureFree(allocator, body);
    @memcpy(body[0..mac_len], mac_buf[0..mac_len]);
    @memcpy(body[mac_len .. mac_len + nonce_bytes], &nonce);
    @memcpy(body[mac_len + nonce_bytes ..], ciphertext);

    const encoded_len = util.encodedBase64Len(body_len);
    const out = try allocator.alloc(u8, header.len + encoded_len);
    errdefer allocator.free(out);
    @memcpy(out[0..header.len], header);
    _ = util.encodeBase64(out[header.len..][0..encoded_len], body);
    return out;
}

/// Re-export of `paserk.keys.UnwrappedKey` so `paseto.paserk.pie.Unwrapped`
/// continues to resolve for existing callers.
pub const Unwrapped = keys.UnwrappedKey;

pub fn unwrap(
    allocator: std.mem.Allocator,
    wrapping_key: []const u8,
    paserk: []const u8,
) !Unwrapped {
    try validateWrappingKey(wrapping_key.len);
    if (paserk.len > util.max_paserk_string_bytes) return Error.InvalidEncoding;

    var it = std.mem.splitScalar(u8, paserk, '.');
    const version_s = it.next() orelse return Error.InvalidEncoding;
    const kind_s = it.next() orelse return Error.InvalidEncoding;
    const alg_s = it.next() orelse return Error.InvalidEncoding;
    const data_s = it.next() orelse return Error.InvalidEncoding;
    if (it.next() != null) return Error.InvalidEncoding;

    if (!std.mem.eql(u8, alg_s, "pie")) return Error.UnsupportedOperation;

    const version = Version.fromPaserkPrefix(version_s) orelse return Error.UnsupportedVersion;
    const kind: Kind = if (std.mem.eql(u8, kind_s, "local-wrap"))
        .local
    else if (std.mem.eql(u8, kind_s, "secret-wrap"))
        .secret
    else
        return Error.UnsupportedOperation;

    const expected_len = bodyLen(version, kind);
    if (data_s.len != util.encodedBase64Len(expected_len)) return Error.InvalidEncoding;

    const body = try util.decodeBase64Alloc(allocator, data_s);
    defer util.secureFree(allocator, body);

    const mac_len: usize = switch (version) {
        .v3 => 48,
        .v4 => 32,
    };
    if (body.len != expected_len) return Error.InvalidEncoding;

    const tag = body[0..mac_len];
    const nonce_slice = body[mac_len .. mac_len + nonce_bytes];
    const ciphertext = body[mac_len + nonce_bytes ..];

    try validatePtk(version, kind, ciphertext.len);

    const header = paserkHeader(version, kind);
    var expected_tag: [48]u8 = undefined;
    var nonce_arr: [nonce_bytes]u8 = undefined;
    @memcpy(&nonce_arr, nonce_slice);
    try macBody(version, wrapping_key, nonce_arr, header, ciphertext, expected_tag[0..mac_len]);
    if (!util.constantTimeEqual(tag, expected_tag[0..mac_len])) return Error.InvalidAuthenticator;

    const out = try allocator.alloc(u8, ciphertext.len);
    errdefer util.secureFree(allocator, out);
    try encryptPayload(version, wrapping_key, nonce_arr, ciphertext, out);
    try validatePtkMaterial(version, kind, out);
    return .{
        .version = version,
        .kind = kind,
        .bytes = out,
        .allocator = allocator,
    };
}

fn bodyLen(version: Version, kind: Kind) usize {
    const mac_len: usize = switch (version) {
        .v3 => 48,
        .v4 => 32,
    };
    return mac_len + nonce_bytes + ptkLen(version, kind);
}

fn ptkLen(version: Version, kind: Kind) usize {
    return switch (version) {
        .v3 => switch (kind) {
            .local => 32,
            .secret => 48,
        },
        .v4 => switch (kind) {
            .local => 32,
            .secret => 64,
        },
    };
}

fn validateWrappingKey(len: usize) !void {
    if (len != 32) return Error.InvalidKey;
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

fn validatePtkMaterial(version: Version, kind: Kind, ptk: []const u8) !void {
    try validatePtk(version, kind, ptk.len);
    try keys.validateKeyMaterial(version, kind.toKeyType(), ptk);
}

fn paserkHeader(version: Version, kind: Kind) []const u8 {
    return switch (version) {
        .v3 => switch (kind) {
            .local => "k3.local-wrap.pie.",
            .secret => "k3.secret-wrap.pie.",
        },
        .v4 => switch (kind) {
            .local => "k4.local-wrap.pie.",
            .secret => "k4.secret-wrap.pie.",
        },
    };
}

/// Derive the encryption key + nonce and encrypt (or decrypt, since CTR/XOR
/// streams are symmetric) `src` into `dst`.
fn encryptPayload(
    version: Version,
    wrapping_key: []const u8,
    nonce: [nonce_bytes]u8,
    src: []const u8,
    dst: []u8,
) !void {
    std.debug.assert(src.len == dst.len);
    switch (version) {
        .v3 => {
            // x = HMAC-SHA384(wrapping_key, 0x80 || nonce)
            var input: [1 + nonce_bytes]u8 = undefined;
            input[0] = DOMAIN_SEPARATOR_ENCRYPT;
            @memcpy(input[1..], &nonce);
            var x: [48]u8 = undefined;
            defer util.secureZero(&x);
            HmacSha384.create(&x, &input, wrapping_key);
            var ek: [32]u8 = undefined;
            defer util.secureZero(&ek);
            @memcpy(&ek, x[0..32]);
            var iv: [16]u8 = undefined;
            defer util.secureZero(&iv);
            @memcpy(&iv, x[32..48]);
            const enc = Aes256.initEnc(ek);
            std.crypto.core.modes.ctr(@TypeOf(enc), enc, dst, src, iv, .big);
        },
        .v4 => {
            // x = BLAKE2b-56(wrapping_key, 0x80 || nonce)
            var x: [56]u8 = undefined;
            defer util.secureZero(&x);
            var h = Blake2b(56 * 8).init(.{});
            defer util.secureZero(std.mem.asBytes(&h));
            util.setBlake2bKey(&h, wrapping_key);
            var sep = [_]u8{DOMAIN_SEPARATOR_ENCRYPT};
            h.update(&sep);
            h.update(&nonce);
            h.final(&x);
            var ek: [32]u8 = undefined;
            defer util.secureZero(&ek);
            @memcpy(&ek, x[0..32]);
            var n2: [24]u8 = undefined;
            defer util.secureZero(&n2);
            @memcpy(&n2, x[32..56]);
            XChaCha20IETF.xor(dst, src, 0, ek, n2);
        },
    }
}

fn macBody(
    version: Version,
    wrapping_key: []const u8,
    nonce: [nonce_bytes]u8,
    header: []const u8,
    ciphertext: []const u8,
    out: []u8,
) !void {
    switch (version) {
        .v3 => {
            // ak = HMAC-SHA384(wrapping_key, 0x81 || nonce)[:32]
            var input: [1 + nonce_bytes]u8 = undefined;
            input[0] = DOMAIN_SEPARATOR_AUTH;
            @memcpy(input[1..], &nonce);
            var ak_full: [48]u8 = undefined;
            defer util.secureZero(&ak_full);
            HmacSha384.create(&ak_full, &input, wrapping_key);
            var ak: [32]u8 = undefined;
            defer util.secureZero(&ak);
            @memcpy(&ak, ak_full[0..32]);

            var mac = HmacSha384.init(&ak);
            defer util.secureZero(std.mem.asBytes(&mac));
            mac.update(header);
            mac.update(&nonce);
            mac.update(ciphertext);
            var full: [48]u8 = undefined;
            defer util.secureZero(&full);
            mac.final(&full);
            @memcpy(out[0..48], &full);
        },
        .v4 => {
            // ak = BLAKE2b-32(wrapping_key, 0x81 || nonce)
            var ak: [32]u8 = undefined;
            defer util.secureZero(&ak);
            var h_ak = Blake2b(32 * 8).init(.{});
            defer util.secureZero(std.mem.asBytes(&h_ak));
            util.setBlake2bKey(&h_ak, wrapping_key);
            var sep = [_]u8{DOMAIN_SEPARATOR_AUTH};
            h_ak.update(&sep);
            h_ak.update(&nonce);
            h_ak.final(&ak);

            var h_tag = Blake2b(32 * 8).init(.{});
            defer util.secureZero(std.mem.asBytes(&h_tag));
            util.setBlake2bKey(&h_tag, &ak);
            h_tag.update(header);
            h_tag.update(&nonce);
            h_tag.update(ciphertext);
            var tag: [32]u8 = undefined;
            defer util.secureZero(&tag);
            h_tag.final(&tag);
            @memcpy(out[0..32], &tag);
        },
    }
}

test "PIE v4.local round trip" {
    const allocator = std.testing.allocator;
    const wrapping: [32]u8 = @splat(0xaa);
    const ptk: [32]u8 = @splat(0x55);
    const wrapped = try wrap(allocator, .v4, .local, &wrapping, &ptk, .{});
    defer allocator.free(wrapped);
    var result = try unwrap(allocator, &wrapping, wrapped);
    defer result.deinit();
    try std.testing.expectEqualSlices(u8, &ptk, result.bytes);
}
