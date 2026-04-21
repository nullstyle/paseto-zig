const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");
const keys_mod = @import("../paserk/keys.zig");
const id_mod = @import("../paserk/id.zig");
const pke_mod = @import("../paserk/pke.zig");
const pbkw_mod = @import("../paserk/pbkw.zig");

pub const Error = errors.Error;

const Ed25519 = std.crypto.sign.Ed25519;

pub const seed_bytes = 32;
pub const public_bytes = 32;
pub const secret_bytes = 64; // seed || public
pub const signature_bytes = Ed25519.Signature.encoded_length; // 64

const pae_header = "v4.public.";

/// A PASETO v4.public Ed25519 key. When `keypair` is non-null this key may
/// be used to sign as well as verify.
pub const Public = struct {
    public_key: [public_bytes]u8,
    keypair: ?Ed25519.KeyPair,

    pub fn fromPublicKeyBytes(bytes: []const u8) !Public {
        if (bytes.len != public_bytes) return Error.InvalidKey;
        var pk: [public_bytes]u8 = undefined;
        @memcpy(&pk, bytes);
        _ = Ed25519.PublicKey.fromBytes(pk) catch return Error.InvalidKey;
        return .{ .public_key = pk, .keypair = null };
    }

    pub fn fromSeed(seed: []const u8) !Public {
        if (seed.len != seed_bytes) return Error.InvalidKey;
        var s: [seed_bytes]u8 = undefined;
        @memcpy(&s, seed);
        const kp = Ed25519.KeyPair.generateDeterministic(s) catch return Error.InvalidKey;
        return .{ .public_key = kp.public_key.toBytes(), .keypair = kp };
    }

    pub fn fromSecretKeyBytes(bytes: []const u8) !Public {
        if (bytes.len != secret_bytes) return Error.InvalidKey;
        var sk_bytes: [secret_bytes]u8 = undefined;
        @memcpy(&sk_bytes, bytes);
        const sk = Ed25519.SecretKey.fromBytes(sk_bytes) catch return Error.InvalidKey;
        const kp = Ed25519.KeyPair.fromSecretKey(sk) catch return Error.InvalidKey;
        // PASERK requires that the public key in the secret-key be consistent
        // with the seed. Recompute from seed and compare.
        const derived = Ed25519.KeyPair.generateDeterministic(sk.seed()) catch return Error.InvalidKey;
        if (!std.mem.eql(u8, &derived.public_key.toBytes(), &kp.public_key.toBytes())) {
            return Error.InvalidKeyPair;
        }
        return .{ .public_key = kp.public_key.toBytes(), .keypair = kp };
    }

    pub fn generate() Public {
        var seed: [seed_bytes]u8 = undefined;
        util.randomBytes(&seed);
        return fromSeed(&seed) catch unreachable;
    }

    pub fn isPrivate(self: Public) bool {
        return self.keypair != null;
    }

    pub fn publicKeyBytes(self: Public) [public_bytes]u8 {
        return self.public_key;
    }

    pub fn secretKeyBytes(self: Public) ?[secret_bytes]u8 {
        const kp = self.keypair orelse return null;
        return kp.secret_key.toBytes();
    }

    pub const SignOptions = struct {
        footer: []const u8 = "",
        implicit_assertion: []const u8 = "",
    };

    /// Sign `message` and return a PASETO token string.
    pub fn sign(
        self: Public,
        allocator: std.mem.Allocator,
        message: []const u8,
        opts: SignOptions,
    ) ![]u8 {
        const kp = self.keypair orelse return Error.InvalidKeyPair;

        var pae_parts: [4][]const u8 = .{
            pae_header,
            message,
            opts.footer,
            opts.implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer allocator.free(pae);

        const sig = kp.sign(pae, null) catch return Error.InvalidSignature;
        const sig_bytes = sig.toBytes();

        const raw_payload = try allocator.alloc(u8, message.len + signature_bytes);
        defer allocator.free(raw_payload);
        @memcpy(raw_payload[0..message.len], message);
        @memcpy(raw_payload[message.len..], &sig_bytes);

        return try token_mod.serialize(allocator, .v4, .public, raw_payload, opts.footer);
    }

    pub fn verify(
        self: Public,
        allocator: std.mem.Allocator,
        token_str: []const u8,
        implicit_assertion: []const u8,
    ) ![]u8 {
        var tok = try token_mod.parse(allocator, token_str);
        defer tok.deinit();
        return try self.verifyToken(allocator, tok, implicit_assertion);
    }

    pub fn verifyToken(
        self: Public,
        allocator: std.mem.Allocator,
        tok: token_mod.Token,
        implicit_assertion: []const u8,
    ) ![]u8 {
        if (tok.version != .v4 or tok.purpose != .public) return Error.WrongPurpose;
        const payload = tok.payload;
        if (payload.len < signature_bytes) return Error.MessageTooShort;

        const message = payload[0 .. payload.len - signature_bytes];
        const sig_slice = payload[payload.len - signature_bytes ..];

        var sig_bytes: [signature_bytes]u8 = undefined;
        @memcpy(&sig_bytes, sig_slice);
        const sig = Ed25519.Signature.fromBytes(sig_bytes);

        var pae_parts: [4][]const u8 = .{
            pae_header,
            message,
            tok.footer,
            implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer allocator.free(pae);

        const pk = Ed25519.PublicKey.fromBytes(self.public_key) catch return Error.InvalidKey;
        sig.verify(pae, pk) catch return Error.InvalidSignature;

        const out = try allocator.alloc(u8, message.len);
        @memcpy(out, message);
        return out;
    }

    pub fn paserkPublic(self: Public, allocator: std.mem.Allocator) ![]u8 {
        return try keys_mod.serialize(allocator, .v4, .public, &self.public_key);
    }

    pub fn paserkSecret(self: Public, allocator: std.mem.Allocator) ![]u8 {
        const secret = self.secretKeyBytes() orelse return Error.InvalidKeyPair;
        return try keys_mod.serialize(allocator, .v4, .secret, &secret);
    }

    pub fn pid(self: Public, allocator: std.mem.Allocator) ![]u8 {
        return try id_mod.pid(allocator, .v4, &self.public_key);
    }

    pub fn sid(self: Public, allocator: std.mem.Allocator) ![]u8 {
        const secret = self.secretKeyBytes() orelse return Error.InvalidKeyPair;
        return try id_mod.sid(allocator, .v4, &secret);
    }

    /// Seal a v4 local key to this public key, returning a `k4.seal.` PASERK.
    pub fn seal(
        self: Public,
        allocator: std.mem.Allocator,
        local_key_bytes: []const u8,
        ephemeral_override: ?[32]u8,
    ) ![]u8 {
        return try pke_mod.sealV4(allocator, self.public_key, local_key_bytes, ephemeral_override);
    }

    /// Unseal a `k4.seal.` PASERK using the stored private key.
    pub fn unseal(
        self: Public,
        allocator: std.mem.Allocator,
        paserk: []const u8,
    ) ![]u8 {
        const kp = self.keypair orelse return Error.InvalidKeyPair;
        const seed = kp.secret_key.seed();
        return try pke_mod.unsealV4(allocator, seed, paserk);
    }

    /// Encrypt the secret key with a password. Returns a `k4.secret-pw.`
    /// PASERK. Requires `keypair` to be populated.
    pub fn wrapWithPassword(
        self: Public,
        allocator: std.mem.Allocator,
        password: []const u8,
        opts: pbkw_mod.WrapOptionsV4,
    ) ![]u8 {
        const secret = self.secretKeyBytes() orelse return Error.InvalidKeyPair;
        return try pbkw_mod.wrapV4(allocator, .secret, password, &secret, opts);
    }
};

test "v4.public sign verify round trip" {
    const allocator = std.testing.allocator;
    const key = Public.generate();
    const token_str = try key.sign(allocator, "some message", .{});
    defer allocator.free(token_str);
    const out = try key.verify(allocator, token_str, "");
    defer allocator.free(out);
    try std.testing.expectEqualSlices(u8, "some message", out);
}
