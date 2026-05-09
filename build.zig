const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const paseto_mod = b.addModule("paseto", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "paseto",
        .root_module = paseto_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // Build all three test binaries once so each step reuses the same
    // compiled test artifact.
    const unit_tests = b.addTest(.{ .root_module = paseto_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const vectors_mod = b.createModule(.{
        .root_source_file = b.path("tests/vectors.zig"),
        .target = target,
        .optimize = optimize,
    });
    vectors_mod.addImport("paseto", paseto_mod);
    const vectors_tests = b.addTest(.{ .root_module = vectors_mod });
    const run_vectors_tests = b.addRunArtifact(vectors_tests);

    const e2e_mod = b.createModule(.{
        .root_source_file = b.path("tests/e2e.zig"),
        .target = target,
        .optimize = optimize,
    });
    e2e_mod.addImport("paseto", paseto_mod);
    const e2e_tests = b.addTest(.{ .root_module = e2e_mod });
    const run_e2e_tests = b.addRunArtifact(e2e_tests);

    // `zig build unit` — source-embedded unit tests only (fast).
    const unit_step = b.step("unit", "Run source-embedded unit tests (fast)");
    unit_step.dependOn(&run_unit_tests.step);

    // `zig build vectors` — official PASETO/PASERK test vectors.
    const vectors_step = b.step("vectors", "Run official PASETO/PASERK test vectors");
    vectors_step.dependOn(&run_vectors_tests.step);

    // `zig build e2e` — end-to-end smoke tests using the public API.
    const e2e_step = b.step("e2e", "Run end-to-end smoke tests");
    e2e_step.dependOn(&run_e2e_tests.step);

    // `zig build test` — the full suite (unit + vectors + e2e).
    const test_step = b.step("test", "Run unit + vectors + e2e tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_vectors_tests.step);
    test_step.dependOn(&run_e2e_tests.step);

    // -- Fuzz suite ------------------------------------------------------
    //
    // Every harness is registered via `addFuzzHarness`, which attaches the
    // harness to its group step, the aggregate `fuzz-all` step, and a
    // dedicated `fuzz-<name>` step so developers can target one harness at
    // a time. Plain `zig build fuzz-...` runs each harness's test artifact
    // once against its embedded corpus seeds. Add `--fuzz[=limit]` to enable
    // Zig's builtin mutation engine, and `--webui` when interactive triage
    // helps.
    const fuzz_all_step = b.step("fuzz-all", "Run all fuzz harnesses (seed-only by default; add --fuzz for mutation)");
    const fuzz_parsers_step = b.step("fuzz-parsers", "Run parser fuzz harnesses (seed-only by default; add --fuzz for mutation)");
    const fuzz_envelopes_step = b.step("fuzz-envelopes", "Run envelope fuzz harnesses (seed-only by default; add --fuzz for mutation)");
    const fuzz_scenarios_step = b.step("fuzz-scenarios", "Run scenario fuzz harnesses (seed-only by default; add --fuzz for mutation)");

    const fuzz_ctx: FuzzCtx = .{
        .b = b,
        .paseto_mod = paseto_mod,
        .target = target,
        .optimize = optimize,
        .all_step = fuzz_all_step,
    };
    addFuzzHarness(fuzz_ctx, "token", "tests/fuzz/token.zig", fuzz_parsers_step);
    addFuzzHarness(fuzz_ctx, "util", "tests/fuzz/util.zig", fuzz_parsers_step);
    addFuzzHarness(fuzz_ctx, "claims", "tests/fuzz/claims.zig", fuzz_parsers_step);
    addFuzzHarness(fuzz_ctx, "pem", "tests/fuzz/pem.zig", fuzz_parsers_step);
    addFuzzHarness(fuzz_ctx, "paserk_keys", "tests/fuzz/paserk_keys.zig", fuzz_parsers_step);

    addFuzzHarness(fuzz_ctx, "paserk_pie", "tests/fuzz/paserk_pie.zig", fuzz_envelopes_step);
    addFuzzHarness(fuzz_ctx, "paserk_pke", "tests/fuzz/paserk_pke.zig", fuzz_envelopes_step);
    addFuzzHarness(fuzz_ctx, "paserk_pbkw", "tests/fuzz/paserk_pbkw.zig", fuzz_envelopes_step);
    addFuzzHarness(fuzz_ctx, "paserk_id", "tests/fuzz/paserk_id.zig", fuzz_envelopes_step);

    addFuzzHarness(fuzz_ctx, "v4_local", "tests/fuzz/v4_local.zig", fuzz_envelopes_step);
    addFuzzHarness(fuzz_ctx, "v4_public", "tests/fuzz/v4_public.zig", fuzz_envelopes_step);
    addFuzzHarness(fuzz_ctx, "v3_local", "tests/fuzz/v3_local.zig", fuzz_envelopes_step);
    addFuzzHarness(fuzz_ctx, "v3_public", "tests/fuzz/v3_public.zig", fuzz_envelopes_step);

    addFuzzHarness(fuzz_ctx, "scenario", "tests/fuzz/scenarios.zig", fuzz_scenarios_step);
}

const FuzzCtx = struct {
    b: *std.Build,
    paseto_mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    all_step: *std.Build.Step,
};

fn addFuzzHarness(
    ctx: FuzzCtx,
    comptime name: []const u8,
    comptime rel_path: []const u8,
    group_step: *std.Build.Step,
) void {
    const mod = ctx.b.createModule(.{
        .root_source_file = ctx.b.path(rel_path),
        .target = ctx.target,
        .optimize = ctx.optimize,
    });
    mod.addImport("paseto", ctx.paseto_mod);
    const t = ctx.b.addTest(.{ .root_module = mod });
    const run = ctx.b.addRunArtifact(t);
    group_step.dependOn(&run.step);
    if (group_step != ctx.all_step) ctx.all_step.dependOn(&run.step);

    const own = ctx.b.step("fuzz-" ++ name, "Run the " ++ name ++ " fuzz harness (seed-only by default; add --fuzz and optional --webui)");
    own.dependOn(&run.step);
}
