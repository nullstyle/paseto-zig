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

/// Raw primitive bytes extracted from a PEM document.
///
/// Ownership model:
/// * Call `deinit` exactly once when done.
/// * Do not copy the struct by value and keep both copies alive across
///   `deinit`; the two copies would share a heap allocation.
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

    fn beginTag(self: Label) []const u8 {
        return switch (self) {
            .private_key => "-----BEGIN PRIVATE KEY-----",
            .public_key => "-----BEGIN PUBLIC KEY-----",
            .ec_private_key => "-----BEGIN EC PRIVATE KEY-----",
        };
    }

    fn endTag(self: Label) []const u8 {
        return switch (self) {
            .private_key => "-----END PRIVATE KEY-----",
            .public_key => "-----END PUBLIC KEY-----",
            .ec_private_key => "-----END EC PRIVATE KEY-----",
        };
    }
};

fn isPemWhitespace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

/// Decode a PEM document into its DER bytes. Enforces strict framing:
/// only ASCII whitespace is allowed before the begin tag or after the end
/// tag, and the document must contain exactly one PEM block.
pub fn pemToDer(allocator: std.mem.Allocator, pem_text: []const u8) !struct {
    label: Label,
    der: []u8,
} {
    // Skip leading whitespace; the first non-whitespace byte must begin a
    // recognized header.
    var start: usize = 0;
    while (start < pem_text.len and isPemWhitespace(pem_text[start])) : (start += 1) {}
    if (start == pem_text.len) return Error.InvalidEncoding;

    const label = blk: {
        inline for (@typeInfo(Label).@"enum".fields) |f| {
            const l: Label = @enumFromInt(f.value);
            const tag = l.beginTag();
            if (pem_text.len - start >= tag.len and
                std.mem.eql(u8, pem_text[start .. start + tag.len], tag))
            {
                break :blk l;
            }
        }
        return Error.InvalidEncoding;
    };

    const begin_tag = label.beginTag();
    const end_tag = label.endTag();
    const body_start = start + begin_tag.len;

    const end_idx = std.mem.indexOfPos(u8, pem_text, body_start, end_tag) orelse
        return Error.InvalidEncoding;

    // Only whitespace may appear after the end tag.
    var tail = end_idx + end_tag.len;
    while (tail < pem_text.len) : (tail += 1) {
        if (!isPemWhitespace(pem_text[tail])) return Error.InvalidEncoding;
    }

    const body = pem_text[body_start..end_idx];

    // Strip whitespace from the body only. Any remaining byte must belong
    // to the standard base64 alphabet — the decoder will enforce that.
    var stripped = try std.ArrayList(u8).initCapacity(allocator, body.len);
    defer stripped.deinit(allocator);
    for (body) |c| {
        if (isPemWhitespace(c)) continue;
        // Reject any embedded header fragment (e.g. a second BEGIN block).
        if (c == '-') return Error.InvalidEncoding;
        try stripped.append(allocator, c);
    }

    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(stripped.items) catch return Error.InvalidBase64;
    const der = try allocator.alloc(u8, size);
    errdefer allocator.free(der);
    decoder.decode(der, stripped.items) catch return Error.InvalidBase64;
    return .{ .label = label, .der = der };
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

/// Like `readTag`, but also asserts that the tag fills the entire `input`
/// (i.e. there are no trailing bytes after the structure).
fn readTagExhaustive(input: []const u8, expected: u8) !TagValue {
    const tv = try readTag(input, expected);
    if (tv.rest.len != 0) return Error.InvalidEncoding;
    return tv;
}

/// Read an OID value and return its raw contents (the bytes inside the OID
/// TLV, not including the `0x06` tag or length).
fn readOid(input: []const u8) !TagValue {
    const tv = try readAnyTag(input);
    if (tv.tag != 0x06) return Error.InvalidEncoding;
    return tv;
}

fn oidEquals(value: []const u8, expected: []const u8) bool {
    return std.mem.eql(u8, value, expected);
}

// Encoded OID *contents* (not including tag+length).
const oid_ed25519: []const u8 = &.{ 0x2b, 0x65, 0x70 }; // 1.3.101.112
const oid_ec_public_key: []const u8 = &.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }; // 1.2.840.10045.2.1
const oid_secp384r1: []const u8 = &.{ 0x2b, 0x81, 0x04, 0x00, 0x22 }; // 1.3.132.0.34

const Algorithm = enum { ed25519, ec_p384 };

/// Read an `AlgorithmIdentifier` SEQUENCE from the head of `input` and
/// classify it. Returns the algorithm plus the bytes following the SEQUENCE
/// in the caller's buffer.
fn consumeAlgorithmIdentifier(input: []const u8) !struct { algorithm: Algorithm, rest: []const u8 } {
    const seq = try readTag(input, 0x30);
    const oid_tv = try readOid(seq.value);

    if (oidEquals(oid_tv.value, oid_ed25519)) {
        // RFC 8410: Ed25519 AlgorithmIdentifier MUST be the OID only,
        // with no parameters.
        if (oid_tv.rest.len != 0) return Error.InvalidEncoding;
        return .{ .algorithm = .ed25519, .rest = seq.rest };
    }

    if (oidEquals(oid_tv.value, oid_ec_public_key)) {
        // RFC 5480: parameters for ecPublicKey MUST carry a NamedCurve OID.
        const params_tv = try readOid(oid_tv.rest);
        if (!oidEquals(params_tv.value, oid_secp384r1)) return Error.UnsupportedVersion;
        if (params_tv.rest.len != 0) return Error.InvalidEncoding;
        return .{ .algorithm = .ec_p384, .rest = seq.rest };
    }

    return Error.UnsupportedVersion;
}

fn parseSec1EcPrivateKey(der: []const u8) ![]const u8 {
    // ECPrivateKey ::= SEQUENCE {
    //   version INTEGER (1),
    //   privateKey OCTET STRING,
    //   parameters [0] EXPLICIT ECParameters OPTIONAL,
    //   publicKey [1] EXPLICIT BIT STRING OPTIONAL
    // }
    // RFC 5915: the structure's outer SEQUENCE must consume the whole DER.
    const outer = try readTagExhaustive(der, 0x30);
    const version_tv = try readTag(outer.value, 0x02);
    if (version_tv.value.len != 1 or version_tv.value[0] != 0x01) return Error.InvalidEncoding;
    const priv_tv = try readTag(version_tv.rest, 0x04);
    // The remaining fields are optional context-specific tags [0] and [1].
    // We don't use them, but we must walk them to confirm well-formedness
    // instead of silently accepting garbage.
    var remaining = priv_tv.rest;
    while (remaining.len > 0) {
        const tv = try readAnyTag(remaining);
        // Accept either [0] (0xA0) or [1] (0xA1) explicit tags, in order.
        if (tv.tag != 0xA0 and tv.tag != 0xA1) return Error.InvalidEncoding;
        remaining = tv.rest;
    }
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
    //   attributes [0] OPTIONAL
    // }
    const outer = try readTagExhaustive(der, 0x30);
    const version_tv = try readTag(outer.value, 0x02);
    if (version_tv.value.len != 1 or version_tv.value[0] != 0x00) return Error.InvalidEncoding;

    const algo = try consumeAlgorithmIdentifier(version_tv.rest);
    const key_tv = try readTag(algo.rest, 0x04);
    // Optional attributes [0] may follow; accept only that tag if present.
    if (key_tv.rest.len > 0) {
        const attrs = try readAnyTag(key_tv.rest);
        if (attrs.tag != 0xA0) return Error.InvalidEncoding;
        if (attrs.rest.len != 0) return Error.InvalidEncoding;
    }
    return .{ .algorithm = algo.algorithm, .private_key_bytes = key_tv.value };
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
    const outer = try readTagExhaustive(der, 0x30);
    const algo = try consumeAlgorithmIdentifier(outer.value);
    const bit_tv = try readTag(algo.rest, 0x03);
    if (bit_tv.rest.len != 0) return Error.InvalidEncoding;
    // BIT STRING starts with one byte: number of unused bits (must be 0).
    if (bit_tv.value.len == 0) return Error.InvalidEncoding;
    if (bit_tv.value[0] != 0) return Error.InvalidEncoding;
    return .{ .algorithm = algo.algorithm, .bit_string = bit_tv.value[1..] };
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

test "pemToDer rejects leading garbage" {
    const allocator = std.testing.allocator;
    const pem =
        \\junk
        \\-----BEGIN PUBLIC KEY-----
        \\MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
        \\-----END PUBLIC KEY-----
    ;
    try std.testing.expectError(Error.InvalidEncoding, parse(allocator, pem));
}

test "pemToDer rejects trailing garbage" {
    const allocator = std.testing.allocator;
    const pem =
        \\-----BEGIN PUBLIC KEY-----
        \\MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
        \\-----END PUBLIC KEY-----
        \\junk after
    ;
    try std.testing.expectError(Error.InvalidEncoding, parse(allocator, pem));
}

test "pemToDer rejects concatenated PEM blocks" {
    const allocator = std.testing.allocator;
    const pem =
        \\-----BEGIN PUBLIC KEY-----
        \\MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
        \\-----END PUBLIC KEY-----
        \\-----BEGIN PUBLIC KEY-----
        \\MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
        \\-----END PUBLIC KEY-----
    ;
    try std.testing.expectError(Error.InvalidEncoding, parse(allocator, pem));
}

test "pemToDer allows leading/trailing whitespace" {
    const allocator = std.testing.allocator;
    const pem =
        \\
        \\
        \\-----BEGIN PUBLIC KEY-----
        \\MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=
        \\-----END PUBLIC KEY-----
        \\
        \\
    ;
    var parsed = try parse(allocator, pem);
    defer parsed.deinit();
    try std.testing.expect(parsed.format == .ed25519_public);
}

test "parse rejects trailing bytes after valid DER" {
    const allocator = std.testing.allocator;
    // Take a valid Ed25519 public key DER and append a byte. Re-encode to PEM
    // so we hit the DER walker after a successful base64 decode.
    const base_der_b64 = "MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=";
    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(base_der_b64);
    const der = try allocator.alloc(u8, size);
    defer allocator.free(der);
    try decoder.decode(der, base_der_b64);

    const padded = try allocator.alloc(u8, der.len + 1);
    defer allocator.free(padded);
    @memcpy(padded[0..der.len], der);
    padded[der.len] = 0x00;

    const encoder = std.base64.standard.Encoder;
    const enc_len = encoder.calcSize(padded.len);
    const enc = try allocator.alloc(u8, enc_len);
    defer allocator.free(enc);
    _ = encoder.encode(enc, padded);

    const pem = try std.mem.concat(allocator, u8, &.{
        "-----BEGIN PUBLIC KEY-----\n",
        enc,
        "\n-----END PUBLIC KEY-----\n",
    });
    defer allocator.free(pem);

    try std.testing.expectError(Error.InvalidEncoding, parse(allocator, pem));
}

test "parse rejects Ed25519 AlgorithmIdentifier with trailing parameters" {
    const allocator = std.testing.allocator;
    // SEQUENCE { OID 1.3.101.112, NULL } wrapped as SPKI — strict parsers
    // must reject this because the Ed25519 AlgorithmIdentifier MUST be the
    // OID only, with no parameters.
    //
    // Handcraft DER:
    //   SPKI ::= SEQUENCE {
    //     algorithm ::= SEQUENCE { OID 1.3.101.112, NULL },
    //     subjectPublicKey ::= BIT STRING (0 unused bits, 32 zero bytes)
    //   }
    //
    // Sizes:
    //   algorithm = 30 07 06 03 2B 65 70 05 00           (9 bytes total)
    //   bit_string = 03 21 00 || 32 zero bytes           (35 bytes total)
    //   outer = 30 2E || algorithm || bit_string         (48 bytes total)
    // outer body: algo_sequence(9) + bit_string(2 header + 33 body) = 44
    const der = [_]u8{
        0x30, 0x2C, // SEQUENCE, len 44
        0x30, 0x07, // SEQUENCE, len 7
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
        0x05, 0x00, // NULL parameters (disallowed)
        0x03, 0x21, 0x00, // BIT STRING, len 33, 0 unused bits
    } ++ @as([32]u8, @splat(0x00));

    const encoder = std.base64.standard.Encoder;
    const enc_len = encoder.calcSize(der.len);
    const enc = try allocator.alloc(u8, enc_len);
    defer allocator.free(enc);
    _ = encoder.encode(enc, &der);

    const pem = try std.mem.concat(allocator, u8, &.{
        "-----BEGIN PUBLIC KEY-----\n",
        enc,
        "\n-----END PUBLIC KEY-----\n",
    });
    defer allocator.free(pem);

    try std.testing.expectError(Error.InvalidEncoding, parse(allocator, pem));
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
