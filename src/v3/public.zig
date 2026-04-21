const std = @import("std");
const util = @import("../util.zig");
const errors = @import("../errors.zig");
const token_mod = @import("../token.zig");
const keys_mod = @import("../paserk/keys.zig");
const id_mod = @import("../paserk/id.zig");
const pke_mod = @import("../paserk/pke.zig");
const pbkw_mod = @import("../paserk/pbkw.zig");

pub const Error = errors.Error;

const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha384 = std.crypto.hash.sha2.Sha384;
const P384 = std.crypto.ecc.P384;

pub const scalar_bytes = 48;
pub const compressed_public_bytes = 49; // 0x02/0x03 || 48 byte X coord
pub const uncompressed_public_bytes = 97; // 0x04 || 48 byte X || 48 byte Y
pub const signature_bytes = 96; // r (48) || s (48)

const pae_header = "v3.public.";

/// A PASETO v3.public ECDSA P-384 key.
pub const Public = struct {
    public_point: P384,
    secret_scalar: ?[scalar_bytes]u8,

    pub fn fromPublicBytesCompressed(bytes: []const u8) !Public {
        if (bytes.len != compressed_public_bytes) return Error.InvalidKey;
        const point = P384.fromSec1(bytes) catch return Error.InvalidKey;
        return .{ .public_point = point, .secret_scalar = null };
    }

    pub fn fromPublicBytesUncompressed(bytes: []const u8) !Public {
        if (bytes.len != uncompressed_public_bytes) return Error.InvalidKey;
        const point = P384.fromSec1(bytes) catch return Error.InvalidKey;
        return .{ .public_point = point, .secret_scalar = null };
    }

    pub fn fromPublicBytes(bytes: []const u8) !Public {
        return switch (bytes.len) {
            compressed_public_bytes => fromPublicBytesCompressed(bytes),
            uncompressed_public_bytes => fromPublicBytesUncompressed(bytes),
            else => Error.InvalidKey,
        };
    }

    pub fn fromScalarBytes(bytes: []const u8) !Public {
        if (bytes.len != scalar_bytes) return Error.InvalidKey;
        var scalar: [scalar_bytes]u8 = undefined;
        @memcpy(&scalar, bytes);
        const kp = EcdsaP384Sha384.KeyPair.fromSecretKey(.{ .bytes = scalar }) catch
            return Error.InvalidKey;
        return .{ .public_point = kp.public_key.p, .secret_scalar = scalar };
    }

    pub fn generate() !Public {
        // Pick a random 48-byte scalar in [1, n-1] by rejection.
        while (true) {
            var scalar: [scalar_bytes]u8 = undefined;
            util.randomBytes(&scalar);
            return fromScalarBytes(&scalar) catch continue;
        }
    }

    pub fn isPrivate(self: Public) bool {
        return self.secret_scalar != null;
    }

    pub fn publicCompressed(self: Public) [compressed_public_bytes]u8 {
        return self.public_point.toCompressedSec1();
    }

    pub fn publicUncompressed(self: Public) [uncompressed_public_bytes]u8 {
        return self.public_point.toUncompressedSec1();
    }

    pub fn secretBytes(self: Public) ?[scalar_bytes]u8 {
        return self.secret_scalar;
    }

    pub const SignOptions = struct {
        footer: []const u8 = "",
        implicit_assertion: []const u8 = "",
    };

    pub fn sign(
        self: Public,
        allocator: std.mem.Allocator,
        message: []const u8,
        opts: SignOptions,
    ) ![]u8 {
        const scalar = self.secret_scalar orelse return Error.InvalidKeyPair;
        const kp = EcdsaP384Sha384.KeyPair.fromSecretKey(.{ .bytes = scalar }) catch
            return Error.InvalidKeyPair;
        const public_bytes = self.publicCompressed();

        var pae_parts: [5][]const u8 = .{
            &public_bytes,
            pae_header,
            message,
            opts.footer,
            opts.implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer allocator.free(pae);

        // Zig's EcdsaP384Sha384.sign requires a noise value for side-channel
        // protection. We derive it from OS randomness.
        var noise: [EcdsaP384Sha384.noise_length]u8 = undefined;
        util.randomBytes(&noise);
        const sig = kp.sign(pae, noise) catch return Error.InvalidSignature;
        const sig_bytes = sig.toBytes();

        const raw_payload = try allocator.alloc(u8, message.len + signature_bytes);
        defer allocator.free(raw_payload);
        @memcpy(raw_payload[0..message.len], message);
        @memcpy(raw_payload[message.len..], &sig_bytes);

        return try token_mod.serialize(allocator, .v3, .public, raw_payload, opts.footer);
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
        if (tok.version != .v3 or tok.purpose != .public) return Error.WrongPurpose;
        const payload = tok.payload;
        if (payload.len < signature_bytes) return Error.MessageTooShort;

        const message = payload[0 .. payload.len - signature_bytes];
        const sig_slice = payload[payload.len - signature_bytes ..];

        var sig_bytes: [signature_bytes]u8 = undefined;
        @memcpy(&sig_bytes, sig_slice);
        const sig = EcdsaP384Sha384.Signature.fromBytes(sig_bytes);

        const public_bytes = self.publicCompressed();
        var pae_parts: [5][]const u8 = .{
            &public_bytes,
            pae_header,
            message,
            tok.footer,
            implicit_assertion,
        };
        const pae = try util.preAuthEncodeAlloc(allocator, &pae_parts);
        defer allocator.free(pae);

        const pubkey = EcdsaP384Sha384.PublicKey{ .p = self.public_point };
        sig.verify(pae, pubkey) catch return Error.InvalidSignature;

        const out = try allocator.alloc(u8, message.len);
        @memcpy(out, message);
        return out;
    }

    pub fn paserkPublic(self: Public, allocator: std.mem.Allocator) ![]u8 {
        const compressed = self.publicCompressed();
        return try keys_mod.serialize(allocator, .v3, .public, &compressed);
    }

    pub fn paserkSecret(self: Public, allocator: std.mem.Allocator) ![]u8 {
        const scalar = self.secret_scalar orelse return Error.InvalidKeyPair;
        return try keys_mod.serialize(allocator, .v3, .secret, &scalar);
    }

    pub fn pid(self: Public, allocator: std.mem.Allocator) ![]u8 {
        const compressed = self.publicCompressed();
        return try id_mod.pid(allocator, .v3, &compressed);
    }

    pub fn sid(self: Public, allocator: std.mem.Allocator) ![]u8 {
        const scalar = self.secret_scalar orelse return Error.InvalidKeyPair;
        return try id_mod.sid(allocator, .v3, &scalar);
    }

    /// Seal a v3 local key to this public key.
    pub fn seal(
        self: Public,
        allocator: std.mem.Allocator,
        local_key_bytes: []const u8,
        ephemeral_override: ?[48]u8,
    ) ![]u8 {
        const compressed = self.publicCompressed();
        return try pke_mod.sealV3(allocator, &compressed, local_key_bytes, ephemeral_override);
    }

    pub fn unseal(
        self: Public,
        allocator: std.mem.Allocator,
        paserk: []const u8,
    ) ![]u8 {
        const scalar = self.secret_scalar orelse return Error.InvalidKeyPair;
        return try pke_mod.unsealV3(allocator, scalar, paserk);
    }

    pub fn wrapWithPassword(
        self: Public,
        allocator: std.mem.Allocator,
        password: []const u8,
        opts: pbkw_mod.WrapOptionsV3,
    ) ![]u8 {
        const scalar = self.secret_scalar orelse return Error.InvalidKeyPair;
        return try pbkw_mod.wrapV3(allocator, .secret, password, &scalar, opts);
    }
};

test "v3.public round trip" {
    const allocator = std.testing.allocator;
    const key = try Public.generate();
    const tok = try key.sign(allocator, "some message", .{});
    defer allocator.free(tok);
    const out = try key.verify(allocator, tok, "");
    defer allocator.free(out);
    try std.testing.expectEqualSlices(u8, "some message", out);
}
