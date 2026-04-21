const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");
const keys_mod = @import("../paserk/keys.zig");
const id_mod = @import("../paserk/id.zig");
const pie_mod = @import("../paserk/pie.zig");
const pbkw_mod = @import("../paserk/pbkw.zig");

pub const Error = errors.Error;

const Sha384 = std.crypto.hash.sha2.Sha384;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const Hkdf = std.crypto.kdf.hkdf.Hkdf(HmacSha384);
const Aes256 = std.crypto.core.aes.Aes256;

pub const key_bytes = 32;
pub const nonce_bytes = 32;
pub const iv_bytes = 16;
pub const mac_bytes = 48;

const pae_header = "v3.local.";

pub const Local = struct {
    key: [key_bytes]u8,

    pub fn fromBytes(bytes: []const u8) !Local {
        if (bytes.len != key_bytes) return Error.InvalidKey;
        var k: Local = .{ .key = undefined };
        @memcpy(&k.key, bytes);
        return k;
    }

    pub fn generate() Local {
        var k: Local = .{ .key = undefined };
        util.randomBytes(&k.key);
        return k;
    }

    pub fn eql(self: Local, other: Local) bool {
        return util.constantTimeEqual(&self.key, &other.key);
    }

    pub const Options = struct {
        footer: []const u8 = "",
        implicit_assertion: []const u8 = "",
        nonce: ?[nonce_bytes]u8 = null,
    };

    pub fn encrypt(
        self: Local,
        allocator: std.mem.Allocator,
        message: []const u8,
        opts: Options,
    ) ![]u8 {
        var nonce: [nonce_bytes]u8 = undefined;
        if (opts.nonce) |n| {
            @memcpy(&nonce, &n);
        } else {
            util.randomBytes(&nonce);
        }

        const keys = deriveKeys(self.key, nonce);

        const ciphertext = try allocator.alloc(u8, message.len);
        defer allocator.free(ciphertext);
        aes256Ctr(ciphertext, message, keys.ek, keys.iv);

        var pae_parts: [5][]const u8 = .{
            pae_header,
            &nonce,
            ciphertext,
            opts.footer,
            opts.implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer allocator.free(pae);

        var tag: [mac_bytes]u8 = undefined;
        HmacSha384.create(&tag, pae, &keys.ak);

        const raw_payload = try allocator.alloc(u8, nonce_bytes + ciphertext.len + mac_bytes);
        defer allocator.free(raw_payload);
        @memcpy(raw_payload[0..nonce_bytes], &nonce);
        @memcpy(raw_payload[nonce_bytes .. nonce_bytes + ciphertext.len], ciphertext);
        @memcpy(raw_payload[nonce_bytes + ciphertext.len ..], &tag);

        return try token_mod.serialize(allocator, .v3, .local, raw_payload, opts.footer);
    }

    pub fn decrypt(
        self: Local,
        allocator: std.mem.Allocator,
        token_str: []const u8,
        implicit_assertion: []const u8,
    ) ![]u8 {
        var tok = try token_mod.parse(allocator, token_str);
        defer tok.deinit();
        return try self.decryptToken(allocator, tok, implicit_assertion);
    }

    pub fn decryptToken(
        self: Local,
        allocator: std.mem.Allocator,
        tok: token_mod.Token,
        implicit_assertion: []const u8,
    ) ![]u8 {
        if (tok.version != .v3 or tok.purpose != .local) return Error.WrongPurpose;
        const payload = tok.payload;
        if (payload.len < nonce_bytes + mac_bytes) return Error.MessageTooShort;

        const nonce = payload[0..nonce_bytes];
        const ciphertext = payload[nonce_bytes .. payload.len - mac_bytes];
        const tag = payload[payload.len - mac_bytes ..];

        const keys = deriveKeys(self.key, nonce.*);

        var pae_parts: [5][]const u8 = .{
            pae_header,
            nonce,
            ciphertext,
            tok.footer,
            implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer allocator.free(pae);

        var expected_tag: [mac_bytes]u8 = undefined;
        HmacSha384.create(&expected_tag, pae, &keys.ak);
        if (!util.constantTimeEqual(tag, &expected_tag)) return Error.InvalidAuthenticator;

        const plaintext = try allocator.alloc(u8, ciphertext.len);
        errdefer allocator.free(plaintext);
        aes256Ctr(plaintext, ciphertext, keys.ek, keys.iv);
        return plaintext;
    }

    pub fn paserkLocal(self: Local, allocator: std.mem.Allocator) ![]u8 {
        return try keys_mod.serialize(allocator, .v3, .local, &self.key);
    }

    pub fn lid(self: Local, allocator: std.mem.Allocator) ![]u8 {
        return try id_mod.lid(allocator, .v3, &self.key);
    }

    pub fn wrapLocal(
        self: Local,
        allocator: std.mem.Allocator,
        other: Local,
        opts: pie_mod.WrapOptions,
    ) ![]u8 {
        return try pie_mod.wrap(allocator, .v3, .local, &self.key, &other.key, opts);
    }

    pub fn wrapSecret(
        self: Local,
        allocator: std.mem.Allocator,
        secret_scalar_48: []const u8,
        opts: pie_mod.WrapOptions,
    ) ![]u8 {
        return try pie_mod.wrap(allocator, .v3, .secret, &self.key, secret_scalar_48, opts);
    }

    pub fn unwrap(
        self: Local,
        allocator: std.mem.Allocator,
        paserk: []const u8,
    ) !pie_mod.Unwrapped {
        return try pie_mod.unwrap(allocator, &self.key, paserk);
    }

    pub fn wrapWithPassword(
        self: Local,
        allocator: std.mem.Allocator,
        password: []const u8,
        opts: pbkw_mod.WrapOptionsV3,
    ) ![]u8 {
        return try pbkw_mod.wrapV3(allocator, .local, password, &self.key, opts);
    }
};

const DerivedKeys = struct {
    ek: [32]u8,
    iv: [iv_bytes]u8,
    ak: [48]u8,
};

fn deriveKeys(key: [key_bytes]u8, nonce: [nonce_bytes]u8) DerivedKeys {
    // HKDF-SHA384 with empty (all-zero) salt; v3 uses null salt per Ruby impl.
    // OpenSSL::KDF.hkdf passes a salt parameter of 0x00 * 48. In HKDF, a zero
    // salt and a null salt produce the same PRK, so we can pass an empty salt.
    var encrypt_info: [64]u8 = undefined;
    @memcpy(encrypt_info[0.."paseto-encryption-key".len], "paseto-encryption-key");
    @memcpy(encrypt_info["paseto-encryption-key".len..][0..nonce_bytes], &nonce);
    const encrypt_info_slice = encrypt_info[0 .. "paseto-encryption-key".len + nonce_bytes];

    var auth_info: [64]u8 = undefined;
    @memcpy(auth_info[0.."paseto-auth-key-for-aead".len], "paseto-auth-key-for-aead");
    @memcpy(auth_info["paseto-auth-key-for-aead".len..][0..nonce_bytes], &nonce);
    const auth_info_slice = auth_info[0 .. "paseto-auth-key-for-aead".len + nonce_bytes];

    const prk = Hkdf.extract(&[_]u8{}, &key);

    var out: DerivedKeys = undefined;
    var tmp: [48]u8 = undefined;
    Hkdf.expand(&tmp, encrypt_info_slice, prk);
    @memcpy(&out.ek, tmp[0..32]);
    @memcpy(&out.iv, tmp[32..48]);

    Hkdf.expand(&out.ak, auth_info_slice, prk);
    return out;
}

fn aes256Ctr(dst: []u8, src: []const u8, key: [32]u8, iv: [iv_bytes]u8) void {
    const enc_ctx = Aes256.initEnc(key);
    std.crypto.core.modes.ctr(@TypeOf(enc_ctx), enc_ctx, dst, src, iv, .big);
}

test "v3.local round trip" {
    const allocator = std.testing.allocator;
    const key = Local.generate();
    const tok = try key.encrypt(allocator, "hello v3", .{ .footer = "foot" });
    defer allocator.free(tok);
    const out = try key.decrypt(allocator, tok, "");
    defer allocator.free(out);
    try std.testing.expectEqualSlices(u8, "hello v3", out);
}
