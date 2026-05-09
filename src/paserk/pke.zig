//! PASERK PKE: sealing a symmetric key with an asymmetric public key.

const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");

pub const Error = errors.Error;
pub const Version = token_mod.Version;

const Blake2b = std.crypto.hash.blake2.Blake2b;
const Sha384 = std.crypto.hash.sha2.Sha384;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const Aes256 = std.crypto.core.aes.Aes256;
const XChaCha20IETF = std.crypto.stream.chacha.XChaCha20IETF;
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;
const P384 = std.crypto.ecc.P384;

const DOMAIN_SEPARATOR_ENCRYPT: u8 = 0x01;
const DOMAIN_SEPARATOR_AUTH: u8 = 0x02;

const k4_header = "k4.seal.";
const k3_header = "k3.seal.";

/// Seal the v4 local key `ptk` (32 bytes) to an Ed25519 public key.
pub fn sealV4(
    allocator: std.mem.Allocator,
    recipient_ed_public: [32]u8,
    ptk: []const u8,
    /// Optional deterministic ephemeral X25519 secret for reproducible tests.
    ephemeral_override: ?[32]u8,
) ![]u8 {
    if (ptk.len != 32) return Error.InvalidKey;

    // Ed25519 → X25519 public key for the recipient.
    const recipient_pk_ed = Ed25519.PublicKey.fromBytes(recipient_ed_public) catch
        return Error.InvalidKey;
    const recipient_pk_x = X25519.publicKeyFromEd25519(recipient_pk_ed) catch
        return Error.InvalidKey;

    // Ephemeral X25519 key pair.
    var esk: [32]u8 = undefined;
    if (ephemeral_override) |e| {
        @memcpy(&esk, &e);
    } else {
        util.randomBytes(&esk);
    }
    const epk = X25519.recoverPublicKey(esk) catch return Error.InvalidKey;

    // Shared secret.
    const xk = X25519.scalarmult(esk, recipient_pk_x) catch return Error.InvalidKey;

    var ek: [32]u8 = undefined;
    var n: [24]u8 = undefined;
    deriveEkNV4(ek[0..], n[0..], &xk, &epk, &recipient_pk_x);

    var ak: [32]u8 = undefined;
    deriveAkV4(&ak, &xk, &epk, &recipient_pk_x);

    // edk = XChaCha20(ptk, ek, n)
    var edk_buf: [64]u8 = undefined;
    const edk = edk_buf[0..ptk.len];
    XChaCha20IETF.xor(edk, ptk, 0, ek, n);

    // tag = BLAKE2b(header || epk || edk, key=ak, 32)
    var tag: [32]u8 = undefined;
    var h = Blake2b(32 * 8).init(.{ .key = &ak });
    h.update(k4_header);
    h.update(&epk);
    h.update(edk);
    h.final(&tag);

    const body_len = 32 + 32 + edk.len;
    const body = try allocator.alloc(u8, body_len);
    defer allocator.free(body);
    @memcpy(body[0..32], &tag);
    @memcpy(body[32..64], &epk);
    @memcpy(body[64..], edk);

    return try concatPaserk(allocator, k4_header, body);
}

pub fn unsealV4(
    allocator: std.mem.Allocator,
    recipient_ed_seed: [32]u8,
    paserk: []const u8,
) ![]u8 {
    // Recipient: Ed25519 seed → Ed25519 keypair → X25519 keypair.
    const ed_kp = Ed25519.KeyPair.generateDeterministic(recipient_ed_seed) catch
        return Error.InvalidKey;
    const x_kp = X25519.KeyPair.fromEd25519(ed_kp) catch return Error.InvalidKey;
    return try unsealV4Raw(allocator, x_kp.secret_key, x_kp.public_key, paserk);
}

pub fn unsealV4FromSecretKey(
    allocator: std.mem.Allocator,
    recipient_ed_secret: [64]u8,
    paserk: []const u8,
) ![]u8 {
    const sk = Ed25519.SecretKey.fromBytes(recipient_ed_secret) catch return Error.InvalidKey;
    const seed: [32]u8 = sk.seed();
    return try unsealV4(allocator, seed, paserk);
}

fn unsealV4Raw(
    allocator: std.mem.Allocator,
    recipient_secret: [32]u8,
    recipient_public: [32]u8,
    paserk: []const u8,
) ![]u8 {
    if (!std.mem.startsWith(u8, paserk, k4_header)) return Error.InvalidEncoding;
    const data = paserk[k4_header.len..];
    const body = try util.decodeBase64Alloc(allocator, data);
    defer allocator.free(body);

    if (body.len < 32 + 32 + 1) return Error.MessageTooShort;
    const tag = body[0..32];
    const epk_slice = body[32..64];
    const edk = body[64..];
    if (edk.len != 32) return Error.InvalidKey;

    var epk: [32]u8 = undefined;
    @memcpy(&epk, epk_slice);

    const xk = X25519.scalarmult(recipient_secret, epk) catch return Error.InvalidKey;

    var ak: [32]u8 = undefined;
    deriveAkV4(&ak, &xk, &epk, &recipient_public);

    var expected_tag: [32]u8 = undefined;
    var h = Blake2b(32 * 8).init(.{ .key = &ak });
    h.update(k4_header);
    h.update(&epk);
    h.update(edk);
    h.final(&expected_tag);
    if (!util.constantTimeEqual(tag, &expected_tag)) return Error.InvalidAuthenticator;

    var ek: [32]u8 = undefined;
    var n: [24]u8 = undefined;
    deriveEkNV4(&ek, &n, &xk, &epk, &recipient_public);

    const out = try allocator.alloc(u8, 32);
    errdefer allocator.free(out);
    XChaCha20IETF.xor(out, edk, 0, ek, n);
    return out;
}

fn deriveEkNV4(
    ek_out: []u8,
    n_out: []u8,
    xk: []const u8,
    epk: []const u8,
    pk: []const u8,
) void {
    std.debug.assert(ek_out.len == 32 and n_out.len == 24);
    var h = Blake2b(32 * 8).init(.{});
    const sep_e = [_]u8{DOMAIN_SEPARATOR_ENCRYPT};
    h.update(&sep_e);
    h.update(k4_header);
    h.update(xk);
    h.update(epk);
    h.update(pk);
    h.final(ek_out[0..32]);

    var n_hash = Blake2b(24 * 8).init(.{});
    n_hash.update(epk);
    n_hash.update(pk);
    n_hash.final(n_out[0..24]);
}

fn deriveAkV4(out: []u8, xk: []const u8, epk: []const u8, pk: []const u8) void {
    std.debug.assert(out.len == 32);
    var h = Blake2b(32 * 8).init(.{});
    const sep = [_]u8{DOMAIN_SEPARATOR_AUTH};
    h.update(&sep);
    h.update(k4_header);
    h.update(xk);
    h.update(epk);
    h.update(pk);
    h.final(out[0..32]);
}

// ----- v3 ------------------------------------------------------------

pub fn sealV3(
    allocator: std.mem.Allocator,
    recipient_public_compressed: []const u8,
    ptk: []const u8,
    ephemeral_override: ?[48]u8,
) ![]u8 {
    if (ptk.len != 32) return Error.InvalidKey;
    if (recipient_public_compressed.len != 49) return Error.InvalidKey;

    const recipient_point = P384.fromSec1(recipient_public_compressed) catch return Error.InvalidKey;

    // Generate ephemeral key pair.
    var esk: [48]u8 = undefined;
    if (ephemeral_override) |e| {
        @memcpy(&esk, &e);
    } else {
        while (true) {
            util.randomBytes(&esk);
            _ = P384.basePoint.mul(esk, .big) catch continue;
            break;
        }
    }
    const epk_point = P384.basePoint.mul(esk, .big) catch return Error.InvalidKey;
    const epk = epk_point.toCompressedSec1();

    // Shared secret = X coordinate of recipient * esk.
    const shared_point = recipient_point.mul(esk, .big) catch return Error.InvalidKey;
    const xk = shared_point.affineCoordinates().x.toBytes(.big);

    var ek: [32]u8 = undefined;
    var n: [16]u8 = undefined;
    deriveEkNV3(&ek, &n, &xk, &epk, recipient_public_compressed);

    var ak: [48]u8 = undefined;
    deriveAkV3(&ak, &xk, &epk, recipient_public_compressed);

    var edk: [32]u8 = undefined;
    const enc = Aes256.initEnc(ek);
    std.crypto.core.modes.ctr(@TypeOf(enc), enc, &edk, ptk, n, .big);

    var tag: [48]u8 = undefined;
    var mac = HmacSha384.init(&ak);
    mac.update(k3_header);
    mac.update(&epk);
    mac.update(&edk);
    mac.final(&tag);

    const body_len = 48 + 49 + edk.len;
    const body = try allocator.alloc(u8, body_len);
    defer allocator.free(body);
    @memcpy(body[0..48], &tag);
    @memcpy(body[48..97], &epk);
    @memcpy(body[97..], &edk);

    return try concatPaserk(allocator, k3_header, body);
}

pub fn unsealV3(
    allocator: std.mem.Allocator,
    recipient_scalar: [48]u8,
    paserk: []const u8,
) ![]u8 {
    if (!std.mem.startsWith(u8, paserk, k3_header)) return Error.InvalidEncoding;
    const data = paserk[k3_header.len..];
    const body = try util.decodeBase64Alloc(allocator, data);
    defer allocator.free(body);
    if (body.len < 48 + 49 + 1) return Error.MessageTooShort;

    const tag = body[0..48];
    const epk_slice = body[48..97];
    const edk = body[97..];
    if (edk.len != 32) return Error.InvalidKey;

    const epk_point = P384.fromSec1(epk_slice) catch return Error.InvalidKey;

    // Derive recipient public point for derive_ek_n / derive_ak inputs.
    const recipient_point = P384.basePoint.mul(recipient_scalar, .big) catch return Error.InvalidKey;
    const recipient_public = recipient_point.toCompressedSec1();

    // Shared secret.
    const shared_point = epk_point.mul(recipient_scalar, .big) catch return Error.InvalidKey;
    const xk = shared_point.affineCoordinates().x.toBytes(.big);

    var ak: [48]u8 = undefined;
    deriveAkV3(&ak, &xk, epk_slice, &recipient_public);

    var expected_tag: [48]u8 = undefined;
    var mac = HmacSha384.init(&ak);
    mac.update(k3_header);
    mac.update(epk_slice);
    mac.update(edk);
    mac.final(&expected_tag);
    if (!util.constantTimeEqual(tag, &expected_tag)) return Error.InvalidAuthenticator;

    var ek: [32]u8 = undefined;
    var n: [16]u8 = undefined;
    deriveEkNV3(&ek, &n, &xk, epk_slice, &recipient_public);

    const out = try allocator.alloc(u8, 32);
    errdefer allocator.free(out);
    const enc = Aes256.initEnc(ek);
    std.crypto.core.modes.ctr(@TypeOf(enc), enc, out, edk, n, .big);
    return out;
}

fn deriveEkNV3(
    ek_out: []u8,
    n_out: []u8,
    xk: []const u8,
    epk: []const u8,
    pk: []const u8,
) void {
    std.debug.assert(ek_out.len == 32 and n_out.len == 16);
    var h = Sha384.init(.{});
    const sep = [_]u8{DOMAIN_SEPARATOR_ENCRYPT};
    h.update(&sep);
    h.update(k3_header);
    h.update(xk);
    h.update(epk);
    h.update(pk);
    var full: [48]u8 = undefined;
    h.final(&full);
    @memcpy(ek_out[0..32], full[0..32]);
    @memcpy(n_out[0..16], full[32..48]);
}

fn deriveAkV3(out: []u8, xk: []const u8, epk: []const u8, pk: []const u8) void {
    std.debug.assert(out.len == 48);
    var h = Sha384.init(.{});
    const sep = [_]u8{DOMAIN_SEPARATOR_AUTH};
    h.update(&sep);
    h.update(k3_header);
    h.update(xk);
    h.update(epk);
    h.update(pk);
    h.final(out[0..48]);
}

fn concatPaserk(allocator: std.mem.Allocator, header: []const u8, body: []const u8) ![]u8 {
    const encoded_len = util.encodedBase64Len(body.len);
    const out = try allocator.alloc(u8, header.len + encoded_len);
    errdefer allocator.free(out);
    @memcpy(out[0..header.len], header);
    _ = util.encodeBase64(out[header.len..][0..encoded_len], body);
    return out;
}

test "PKE v4 round trip" {
    const allocator = std.testing.allocator;
    var seed: [32]u8 = undefined;
    util.randomBytes(&seed);
    const ed_kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pk = ed_kp.public_key.toBytes();

    const ptk: [32]u8 = @splat(0x42);
    const sealed = try sealV4(allocator, pk, &ptk, null);
    defer allocator.free(sealed);

    const unsealed = try unsealV4(allocator, seed, sealed);
    defer allocator.free(unsealed);
    try std.testing.expectEqualSlices(u8, &ptk, unsealed);
}

test "PKE v3 round trip" {
    const allocator = std.testing.allocator;
    var scalar: [48]u8 = undefined;
    while (true) {
        util.randomBytes(&scalar);
        _ = P384.basePoint.mul(scalar, .big) catch continue;
        break;
    }
    const pubkey_point = try P384.basePoint.mul(scalar, .big);
    const pubkey = pubkey_point.toCompressedSec1();

    const ptk: [32]u8 = @splat(0x99);
    const sealed = try sealV3(allocator, &pubkey, &ptk, null);
    defer allocator.free(sealed);

    const unsealed = try unsealV3(allocator, scalar, sealed);
    defer allocator.free(unsealed);
    try std.testing.expectEqualSlices(u8, &ptk, unsealed);
}
