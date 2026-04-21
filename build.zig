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
}
