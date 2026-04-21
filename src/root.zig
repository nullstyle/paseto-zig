//! PASETO (Platform-Agnostic Security Tokens) for Zig.
//!
//! Implements PASETO v3 (NIST Modern) and v4 (Sodium Modern), covering both
//! `local` (symmetric) and `public` (asymmetric) purposes. A comprehensive
//! PASERK layer provides serialized key formats (local/secret/public), key
//! IDs (lid/sid/pid), symmetric wrapping (PIE), public-key sealing, and
//! password-based wrapping.

const std = @import("std");

pub const util = @import("util.zig");
pub const errors = @import("errors.zig");
pub const token = @import("token.zig");
pub const claims = @import("claims.zig");
pub const paserk = @import("paserk/root.zig");
pub const pem = @import("pem.zig");

pub const Error = errors.Error;
pub const Token = token.Token;
pub const Version = token.Version;
pub const Purpose = token.Purpose;
pub const Claims = claims.Claims;
pub const Validator = claims.Validator;
pub const Result = claims.Result;

pub const v3 = struct {
    pub const Local = @import("v3/local.zig").Local;
    pub const Public = @import("v3/public.zig").Public;
};

pub const v4 = struct {
    pub const Local = @import("v4/local.zig").Local;
    pub const Public = @import("v4/public.zig").Public;
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("v4/local.zig");
    _ = @import("v4/public.zig");
    _ = @import("v3/local.zig");
    _ = @import("v3/public.zig");
    _ = @import("paserk/root.zig");
    _ = @import("paserk/id.zig");
    _ = @import("paserk/pie.zig");
    _ = @import("paserk/pke.zig");
    _ = @import("paserk/pbkw.zig");
}
