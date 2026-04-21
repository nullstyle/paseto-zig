//! Minimal PEM decoding for PASETO/PASERK needs. Supports:
//! * SEC1 `EC PRIVATE KEY` for P-384 (returns 48-byte scalar).
//! * PKCS#8 `PRIVATE KEY` for Ed25519 (returns 32-byte seed).
//! * SPKI `PUBLIC KEY` for both P-384 (returns compressed SEC1) and Ed25519.

const std = @import("std");
const util = @import("util.zig");
const errors = @import("errors.zig");

pub const Error = errors.Error;

pub const KeyFormat = enum {
    /// Ed25519 32-byte seed.
    ed25519_seed,
    /// Ed25519 32-byte public key (raw, not DER-encoded).
    ed25519_public,
    /// P-384 48-byte scalar.
    p384_scalar,
    /// P-384 compressed SEC1 (0x02/0x03 || X, 49 bytes).
    p384_public_compressed,
};

pub const Parsed = struct {
    format: KeyFormat,
    bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Parsed) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

const Label = enum {
    private_key, // PKCS#8 PRIVATE KEY
    public_key, // SPKI PUBLIC KEY
    ec_private_key, // SEC1 EC PRIVATE KEY

    fn detect(content: []const u8) ?struct { label: Label, end_tag: []const u8 } {
        const candidates = [_]struct { begin: []const u8, end: []const u8, label: Label }{
            .{ .begin = "-----BEGIN PRIVATE KEY-----", .end = "-----END PRIVATE KEY-----", .label = .private_key },
            .{ .begin = "-----BEGIN PUBLIC KEY-----", .end = "-----END PUBLIC KEY-----", .label = .public_key },
            .{ .begin = "-----BEGIN EC PRIVATE KEY-----", .end = "-----END EC PRIVATE KEY-----", .label = .ec_private_key },
        };
        for (candidates) |c| {
            if (std.mem.indexOf(u8, content, c.begin) != null) {
                return .{ .label = c.label, .end_tag = c.end };
            }
        }
        return null;
    }
};

/// Decode a PEM document into its DER bytes.
pub fn pemToDer(allocator: std.mem.Allocator, pem_text: []const u8) !struct {
    label: Label,
    der: []u8,
} {
    const detection = Label.detect(pem_text) orelse return Error.InvalidEncoding;
    const begin_tag = switch (detection.label) {
        .private_key => "-----BEGIN PRIVATE KEY-----",
        .public_key => "-----BEGIN PUBLIC KEY-----",
        .ec_private_key => "-----BEGIN EC PRIVATE KEY-----",
    };
    const begin_idx = std.mem.indexOf(u8, pem_text, begin_tag).? + begin_tag.len;
    const end_idx = std.mem.indexOf(u8, pem_text, detection.end_tag) orelse return Error.InvalidEncoding;
    if (end_idx <= begin_idx) return Error.InvalidEncoding;

    const body = pem_text[begin_idx..end_idx];
    // Strip whitespace.
    var stripped = try std.ArrayList(u8).initCapacity(allocator, body.len);
    defer stripped.deinit(allocator);
    for (body) |c| switch (c) {
        ' ', '\t', '\r', '\n' => {},
        else => try stripped.append(allocator, c),
    };

    // The standard base64 alphabet (with padding) is used by PEM. PEM is
    // permissive about trailing '=' padding, so we must use the padded codec.
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(stripped.items) catch return Error.InvalidBase64;
    const der = try allocator.alloc(u8, size);
    errdefer allocator.free(der);
    decoder.decode(der, stripped.items) catch return Error.InvalidBase64;
    return .{ .label = detection.label, .der = der };
}

/// Parse a PEM-encoded key into its raw primitive bytes.
pub fn parse(allocator: std.mem.Allocator, pem_text: []const u8) !Parsed {
    const dec = try pemToDer(allocator, pem_text);
    defer allocator.free(dec.der);

    switch (dec.label) {
        .ec_private_key => {
            const scalar = try parseSec1EcPrivateKey(dec.der);
            const bytes = try allocator.alloc(u8, scalar.len);
            @memcpy(bytes, scalar);
            return .{ .format = .p384_scalar, .bytes = bytes, .allocator = allocator };
        },
        .private_key => {
            const inner = try parsePkcs8PrivateKey(dec.der);
            switch (inner.algorithm) {
                .ed25519 => {
                    // Ed25519 PKCS#8 inner key is OCTET STRING wrapping a
                    // 32-byte seed OCTET STRING.
                    const seed_oct = try readTag(inner.private_key_bytes, 0x04);
                    if (seed_oct.value.len != 32) return Error.InvalidKey;
                    const bytes = try allocator.alloc(u8, 32);
                    @memcpy(bytes, seed_oct.value);
                    return .{ .format = .ed25519_seed, .bytes = bytes, .allocator = allocator };
                },
                .ec_p384 => {
                    // PKCS#8 wraps an SEC1 ECPrivateKey.
                    const scalar = try parseSec1EcPrivateKey(inner.private_key_bytes);
                    const bytes = try allocator.alloc(u8, scalar.len);
                    @memcpy(bytes, scalar);
                    return .{ .format = .p384_scalar, .bytes = bytes, .allocator = allocator };
                },
            }
        },
        .public_key => {
            const spki = try parseSpki(dec.der);
            switch (spki.algorithm) {
                .ed25519 => {
                    if (spki.bit_string.len != 32) return Error.InvalidKey;
                    const bytes = try allocator.alloc(u8, 32);
                    @memcpy(bytes, spki.bit_string);
                    return .{ .format = .ed25519_public, .bytes = bytes, .allocator = allocator };
                },
                .ec_p384 => {
                    // Returns the raw EC point encoding (compressed or uncompressed).
                    const in = spki.bit_string;
                    if (in.len == 0) return Error.InvalidKey;
                    const bytes = switch (in[0]) {
                        0x02, 0x03 => blk: {
                            const out = try allocator.alloc(u8, in.len);
                            @memcpy(out, in);
                            break :blk out;
                        },
                        0x04 => blk: {
                            // Convert uncompressed -> compressed.
                            if (in.len != 97) return Error.InvalidKey;
                            const out = try allocator.alloc(u8, 49);
                            const parity: u8 = if ((in[96] & 1) == 1) 0x03 else 0x02;
                            out[0] = parity;
                            @memcpy(out[1..49], in[1..49]);
                            break :blk out;
                        },
                        else => return Error.InvalidKey,
                    };
                    return .{ .format = .p384_public_compressed, .bytes = bytes, .allocator = allocator };
                },
            }
        },
    }
}

// ----- Tiny DER walker -------------------------------------------------

const TagValue = struct { tag: u8, value: []const u8, rest: []const u8 };

fn readAnyTag(input: []const u8) !TagValue {
    if (input.len < 2) return Error.InvalidEncoding;
    const tag = input[0];
    var idx: usize = 1;
    var len: usize = input[idx];
    idx += 1;
    if (len & 0x80 != 0) {
        const n = len & 0x7f;
        if (n == 0 or n > 4) return Error.InvalidEncoding;
        if (idx + n > input.len) return Error.InvalidEncoding;
        len = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            len = (len << 8) | input[idx + i];
        }
        idx += n;
    }
    if (idx + len > input.len) return Error.InvalidEncoding;
    return .{ .tag = tag, .value = input[idx .. idx + len], .rest = input[idx + len ..] };
}

fn readTag(input: []const u8, expected: u8) !TagValue {
    const tv = try readAnyTag(input);
    if (tv.tag != expected) return Error.InvalidEncoding;
    return tv;
}

// OIDs we recognize.
const ed25519_oid: []const u8 = &[_]u8{ 0x06, 0x03, 0x2b, 0x65, 0x70 }; // id-Ed25519 1.3.101.112
const ec_public_key_oid: []const u8 = &[_]u8{ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }; // 1.2.840.10045.2.1
const secp384r1_oid: []const u8 = &[_]u8{ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }; // 1.3.132.0.34

const Algorithm = enum { ed25519, ec_p384 };

fn parseAlgorithmIdentifier(input: []const u8) !Algorithm {
    const seq = try readTag(input, 0x30);
    const oid_tv = try readAnyTag(seq.value);
    if (oid_tv.tag != 0x06) return Error.InvalidEncoding;

    // Rebuild OID bytes including the DER header to compare with our
    // pre-encoded constants.
    if (startsWith(input, ed25519_oid)) return Error.InvalidEncoding; // unreachable via SEQUENCE
    const oid_encoded = buildOidEncoded(input, seq.value, oid_tv.value);

    if (std.mem.eql(u8, oid_encoded, ed25519_oid)) return .ed25519;
    if (std.mem.eql(u8, oid_encoded, ec_public_key_oid)) {
        // Then parameters should carry secp384r1.
        const rest = oid_tv.rest;
        const params_tv = try readAnyTag(rest);
        if (params_tv.tag != 0x06) return Error.InvalidEncoding;
        const params_encoded = buildOidEncoded(input, rest, params_tv.value);
        if (!std.mem.eql(u8, params_encoded, secp384r1_oid)) return Error.UnsupportedVersion;
        return .ec_p384;
    }
    return Error.UnsupportedVersion;
}

fn startsWith(haystack: []const u8, needle: []const u8) bool {
    return haystack.len >= needle.len and std.mem.eql(u8, haystack[0..needle.len], needle);
}

// Construct the raw encoded OID bytes for comparison. `full_tag_bytes` is the
// slice starting at the tag byte (0x06); len is implicit from the header.
fn buildOidEncoded(outer: []const u8, wrapper_bytes: []const u8, value: []const u8) []const u8 {
    _ = outer;
    // value.ptr starts at beginning of OID contents.
    // value.ptr - 2 points at the tag byte if the length is short-form (< 128),
    // which is always the case for the OIDs we care about.
    const tag_ptr_len: usize = 2 + value.len;
    const wrapper_start: [*]const u8 = wrapper_bytes.ptr;
    const value_offset: usize = (@intFromPtr(value.ptr) - @intFromPtr(wrapper_start));
    const tag_start: [*]const u8 = wrapper_start + (value_offset - 2);
    return tag_start[0..tag_ptr_len];
}

fn parseSec1EcPrivateKey(der: []const u8) ![]const u8 {
    // ECPrivateKey ::= SEQUENCE {
    //   version INTEGER, privateKey OCTET STRING, ...
    // }
    const outer = try readTag(der, 0x30);
    const version_tv = try readTag(outer.value, 0x02);
    if (version_tv.value.len != 1 or version_tv.value[0] != 0x01) return Error.InvalidEncoding;
    const priv_tv = try readTag(version_tv.rest, 0x04);
    return priv_tv.value;
}

const Pkcs8Parsed = struct {
    algorithm: Algorithm,
    private_key_bytes: []const u8,
};

fn parsePkcs8PrivateKey(der: []const u8) !Pkcs8Parsed {
    // PrivateKeyInfo ::= SEQUENCE {
    //   version INTEGER (0),
    //   privateKeyAlgorithm AlgorithmIdentifier,
    //   privateKey OCTET STRING,
    //   ...
    // }
    const outer = try readTag(der, 0x30);
    const version_tv = try readTag(outer.value, 0x02);
    if (version_tv.value.len != 1 or version_tv.value[0] != 0x00) return Error.InvalidEncoding;
    const algo = try parseAlgorithmIdentifier(version_tv.rest);
    // The AlgorithmIdentifier sequence is followed by OCTET STRING for priv key.
    const algo_tv = try readTag(version_tv.rest, 0x30);
    const key_tv = try readTag(algo_tv.rest, 0x04);
    return .{ .algorithm = algo, .private_key_bytes = key_tv.value };
}

const SpkiParsed = struct {
    algorithm: Algorithm,
    bit_string: []const u8,
};

fn parseSpki(der: []const u8) !SpkiParsed {
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }
    const outer = try readTag(der, 0x30);
    const algo = try parseAlgorithmIdentifier(outer.value);
    const algo_tv = try readTag(outer.value, 0x30);
    const bit_tv = try readTag(algo_tv.rest, 0x03);
    // BIT STRING starts with one byte: number of unused bits. Typically 0.
    if (bit_tv.value.len == 0) return Error.InvalidEncoding;
    if (bit_tv.value[0] != 0) return Error.InvalidEncoding;
    return .{ .algorithm = algo, .bit_string = bit_tv.value[1..] };
}

test "parse v4 test vector public key PEM" {
    const allocator = std.testing.allocator;
    const pem =
        \\-----BEGIN PUBLIC KEY-----
        \\MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
        \\-----END PUBLIC KEY-----
    ;
    var parsed = try parse(allocator, pem);
    defer parsed.deinit();
    try std.testing.expect(parsed.format == .ed25519_public);
    try std.testing.expectEqual(@as(usize, 32), parsed.bytes.len);
    const expected_hex = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, parsed.bytes);
}

test "parse v3 test vector EC private key PEM" {
    const allocator = std.testing.allocator;
    const pem =
        \\-----BEGIN EC PRIVATE KEY-----
        \\MIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7t
        \\WsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8
        \\AUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnj
        \\SUd/gcAm08EjSIz06iWjrNy4NakxR3I=
        \\-----END EC PRIVATE KEY-----
    ;
    var parsed = try parse(allocator, pem);
    defer parsed.deinit();
    try std.testing.expect(parsed.format == .p384_scalar);
    try std.testing.expectEqual(@as(usize, 48), parsed.bytes.len);
    const expected_hex = "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96";
    var expected: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, parsed.bytes);
}

test "parse v3 test vector public key PEM" {
    const allocator = std.testing.allocator;
    const pem =
        \\-----BEGIN PUBLIC KEY-----
        \\MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2
        \\PAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5
        \\40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdy
        \\-----END PUBLIC KEY-----
    ;
    var parsed = try parse(allocator, pem);
    defer parsed.deinit();
    try std.testing.expect(parsed.format == .p384_public_compressed);
    try std.testing.expectEqual(@as(usize, 49), parsed.bytes.len);
    const expected_hex = "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb";
    var expected: [49]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, parsed.bytes);
}
