//! The Edge Fleet — a guided tour of the paseto v4 feature set.
//!
//! One runnable story that uses each capability where it actually earns its
//! keep, with the negative paths demonstrated alongside the happy ones:
//!
//!   1. Node identity        v4.public signing keys, `k4.pid` pinning
//!   2. Footer key-hints     authenticated cleartext routing + rotation
//!   3. Implicit assertion   channel-bound challenges that cannot replay
//!   4. PIE key wrapping     config delivery + rotation by `k4.lid`
//!   5. Sealed telemetry     anonymous `k4.seal` submission to a collector
//!   6. PBKW escrow          break-glass key behind a passphrase
//!
//! Everything is deterministic (fixed seeds, fixed nonces/ephemerals), so
//! two runs print identical tokens. Run with:
//!
//!   zig build examples
//!
//! Keys here are demo constants; never ship them.

const std = @import("std");
const paseto = @import("paseto");

fn seed32(comptime label: []const u8) [32]u8 {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @truncate(label[i % label.len] + i);
    return s;
}

fn trunc(s: []const u8) []const u8 {
    return if (s.len > 40) s[0..40] else s;
}

/// One pinned verification key, selected by its PASERK id.
const KeyringEntry = struct { kid: []const u8, verifier: paseto.v4.Public };

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // ----- cast ------------------------------------------------------------
    const node_seed = seed32("fleet-demo-node-seed");
    const collector_seed = seed32("fleet-demo-collector");
    const master1_bytes = seed32("fleet-demo-master-01");
    const master2_bytes = seed32("fleet-demo-master-02");
    const data_key_bytes = seed32("fleet-demo-data-key");
    const fleet_key_bytes = seed32("fleet-demo-fleet-local");
    const challenge_nonce = seed32("fleet-demo-challenge-nonce");
    const seal_ephemeral = seed32("fleet-demo-seal-ephemeral");
    const report_key_bytes = seed32("fleet-demo-report-key");
    const report_nonce = seed32("fleet-demo-report-nonce");
    const pie_nonce = seed32("fleet-demo-pie-nonce");
    const pbkw_salt: [16]u8 = seed32("fleet-demo-pbkw-salt")[0..16].*;
    const pbkw_nonce: [24]u8 = seed32("fleet-demo-pbkw-nonce")[0..24].*;

    // ------------------------------------------------------------------ [1]
    std.debug.print("\n== The Edge Fleet: a tour of paseto v4 ==\n", .{});
    std.debug.print("\n[1] Node identity (v4.public + k4.pid)\n", .{});

    const node = try paseto.v4.Public.fromSeed(&node_seed);
    const node_pid = try node.pid();
    const node_pid_str = try node_pid.toString(allocator);
    defer allocator.free(node_pid_str);
    std.debug.print("    node pid:      {s}\n", .{node_pid_str});
    std.debug.print("    gateway pins the pid as this node's identity\n", .{});

    // ------------------------------------------------------------------ [2]
    std.debug.print("\n[2] HELLO with footer key-hint routing (rotation-ready)\n", .{});

    // The gateway keeps a small keyring: last epoch's key plus the current
    // one. The token's footer says which to use — in cleartext, so the
    // gateway routes before any crypto, but authenticated, so it cannot be
    // rewritten to downgrade the node to a retired key.
    const rotated_node = try paseto.v4.Public.fromSeed(&collector_seed);
    const rotated_pid_str = try (try rotated_node.pid()).toString(allocator);
    defer allocator.free(rotated_pid_str);

    const footer = try std.fmt.allocPrint(allocator, "{{\"kid\":\"{s}\"}}", .{node_pid_str});
    defer allocator.free(footer);

    const hello = try node.sign(allocator, "{\"node\":\"edge-17\",\"epoch\":4}", .{ .footer = footer });
    defer allocator.free(hello);
    std.debug.print("    hello token:   {s}...\n", .{trunc(hello)});
    std.debug.print("    footer (clear, but MAC-bound): {s}\n", .{footer});

    const keyring = [_]KeyringEntry{
        .{ .kid = node_pid_str, .verifier = node },
        .{ .kid = rotated_pid_str, .verifier = rotated_node },
    };

    {
        var result = try (try routeByKid(&keyring, allocator, hello)).verifyWithFooter(allocator, hello, "");
        defer result.deinit();
        std.debug.print("    routed by kid -> verified, claims: {s}, footer: {s}\n", .{ trunc(result.claims_bytes), result.footer });

        // A rewritten footer is caught by the signature, not by parsing.
        const forged_footer = try std.fmt.allocPrint(allocator, "{{\"kid\":\"{s}\"}}", .{rotated_pid_str});
        defer allocator.free(forged_footer);
        var parsed = try paseto.token.parse(allocator, hello);
        defer parsed.deinit();
        const forged = try paseto.token.serialize(allocator, parsed.version, parsed.purpose, parsed.payload, forged_footer);
        defer allocator.free(forged);
        if ((try routeByKid(&keyring, allocator, forged)).verify(allocator, forged, "")) |_| {
            return error.UnexpectedVerificationSuccess;
        } else |err| {
            std.debug.print("    footer rewritten to another kid -> rejected ({s})\n", .{@errorName(err)});
        }
    }

    // ------------------------------------------------------------------ [3]
    std.debug.print("\n[3] Channel-bound challenge (v4.local + implicit assertion)\n", .{});

    // The gateway mints a one-shot challenge for connection #1041. The
    // binding lives in the implicit assertion: it is NOT on the wire, so a
    // captured challenge carries no hint of where it is valid.
    const fleet_key = try paseto.v4.Local.fromBytes(&fleet_key_bytes);
    const challenge = try fleet_key.encrypt(allocator, "prove-you-are-edge-17", .{
        .implicit_assertion = "conn:1041",
        .nonce = challenge_nonce,
    });
    defer allocator.free(challenge);
    std.debug.print("    challenge:     {s}...\n", .{trunc(challenge)});
    std.debug.print("    (wire shows no binding; verifier supplies \"conn:1041\")\n", .{});

    {
        const answer = try fleet_key.decrypt(allocator, challenge, "conn:1041");
        defer paseto.util.secureFree(allocator, answer);
        std.debug.print("    answered on conn #1041 -> verified: {s}\n", .{answer});

        if (fleet_key.decrypt(allocator, challenge, "conn:1042")) |_| {
            return error.UnexpectedVerificationSuccess;
        } else |err| {
            std.debug.print("    replayed on conn #1042 -> rejected ({s})\n", .{@errorName(err)});
        }
    }

    // ------------------------------------------------------------------ [4]
    std.debug.print("\n[4] Config key delivery (PIE wrap + rotation by k4.lid)\n", .{});

    var master1 = try paseto.v4.Local.fromBytes(&master1_bytes);
    const data_key = try paseto.v4.Local.fromBytes(&data_key_bytes);
    const data_lid_str = try (try data_key.lid()).toString(allocator);
    defer allocator.free(data_lid_str);

    const wrapped1 = try master1.wrapLocal(allocator, data_key, .{ .nonce = pie_nonce });
    defer allocator.free(wrapped1);
    std.debug.print("    wrapped cfg:   {s}...\n", .{trunc(wrapped1)});
    std.debug.print("    data key lid:  {s}\n", .{data_lid_str});

    {
        var unwrapped = try master1.unwrap(allocator, wrapped1);
        defer unwrapped.deinit();
        std.debug.print("    node unwrapped under master-01 -> {s} key, {} bytes\n", .{ @tagName(unwrapped.kind), unwrapped.bytes.len });
    }

    // Rotation: master-02 takes over. Ops looks the data key up by lid and
    // re-wraps; nodes never see the masters change.
    var master2 = try paseto.v4.Local.fromBytes(&master2_bytes);
    const wrapped2 = try master2.wrapLocal(allocator, data_key, .{ .nonce = pie_nonce });
    defer allocator.free(wrapped2);
    {
        var unwrapped = try master2.unwrap(allocator, wrapped2);
        defer unwrapped.deinit();
        std.debug.print("    rotated to master-02 (same lid) -> unwrapped OK\n", .{});
    }

    // The retired master is wiped as soon as it is no longer needed.
    master1.wipe();
    std.debug.print("    retired master-01 wiped (wipe())\n", .{});

    // ------------------------------------------------------------------ [5]
    std.debug.print("\n[5] Anonymous telemetry (k4.seal + v4.local)\n", .{});

    // k4.seal encapsulates *keys*, not messages — so anonymous submission
    // composes two moves: seal a fresh report key to the collector's public
    // key (no shared secret, no sender identity, no account), then encrypt
    // the payload with it. Anyone can submit; only the collector can read.
    const collector = try paseto.v4.Public.fromSeed(&collector_seed);
    const collector_public = try paseto.v4.Public.fromPublicKeyBytes(&collector.publicKeyBytes());
    const report_key = try paseto.v4.Local.fromBytes(&report_key_bytes);

    const sealed_key = try collector_public.seal(allocator, &report_key_bytes, seal_ephemeral);
    defer allocator.free(sealed_key);
    const report_body = try report_key.encrypt(allocator, "{\"temp_c\":41,\"node\":\"edge-17\"}", .{ .nonce = report_nonce });
    defer allocator.free(report_body);
    std.debug.print("    sealed key:    {s}...\n", .{trunc(sealed_key)});
    std.debug.print("    report body:   {s}...\n", .{trunc(report_body)});

    {
        const key_bytes = try collector.unseal(allocator, sealed_key);
        defer paseto.util.secureFree(allocator, key_bytes);
        const report = try (try paseto.v4.Local.fromBytes(key_bytes[0..32])).decrypt(allocator, report_body, "");
        defer paseto.util.secureFree(allocator, report);
        std.debug.print("    collector unsealed the key, decrypted -> {s}\n", .{report});

        // A different collector cannot even recover the key.
        const rival = try paseto.v4.Public.fromSeed(&node_seed);
        if (rival.unseal(allocator, sealed_key)) |_| {
            return error.UnexpectedVerificationSuccess;
        } else |err| {
            std.debug.print("    a rival key tried -> rejected ({s})\n", .{@errorName(err)});
        }
    }

    // ------------------------------------------------------------------ [6]
    std.debug.print("\n[6] Break-glass escrow (PBKW)\n", .{});

    // The fleet master is wrapped with a passphrase and stored in a safe.
    // Argon2id at production policy; the passphrase never protects
    // anything weaker.
    const escrow = try master2.wrapWithPassword(allocator, "correct horse - fleet safe 01", .{
        .params = .{ .memlimit_bytes = 64 * 1024 * 1024, .opslimit = 2 },
        .salt = pbkw_salt,
        .nonce = pbkw_nonce,
    });
    defer allocator.free(escrow);
    std.debug.print("    escrow:        {s}...\n", .{trunc(escrow)});

    {
        var recovered = try paseto.paserk.pbkw.unwrap(allocator, "correct horse - fleet safe 01", escrow);
        defer recovered.deinit();
        std.debug.print("    passphrase from the safe -> master recovered, {} bytes, then wiped\n", .{recovered.bytes.len});
    }
    if (paseto.paserk.pbkw.unwrap(allocator, "wrong horse", escrow)) |_| {
        return error.UnexpectedVerificationSuccess;
    } else |err| {
        std.debug.print("    wrong passphrase -> rejected ({s})\n", .{@errorName(err)});
    }
    master2.wipe();

    std.debug.print("\nevery artifact above was produced and verified by this run.\n", .{});
}

/// Pick the verifier whose `kid` matches the token's footer — routing that
/// happens before any crypto, on authenticated data.
fn routeByKid(keyring: []const KeyringEntry, allocator: std.mem.Allocator, token_str: []const u8) !paseto.v4.Public {
    var parsed = try paseto.token.parse(allocator, token_str);
    defer parsed.deinit();
    for (keyring) |entry| {
        const want = try std.fmt.allocPrint(allocator, "{{\"kid\":\"{s}\"}}", .{entry.kid});
        defer allocator.free(want);
        if (std.mem.eql(u8, parsed.footer, want)) return entry.verifier;
    }
    return paseto.Error.InvalidKeyId;
}
