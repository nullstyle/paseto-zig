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

    const test_step = b.step("test", "Run library and vector tests");

    const unit_tests = b.addTest(.{
        .root_module = paseto_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    const vectors_mod = b.createModule(.{
        .root_source_file = b.path("tests/vectors.zig"),
        .target = target,
        .optimize = optimize,
    });
    vectors_mod.addImport("paseto", paseto_mod);
    const vectors_tests = b.addTest(.{
        .root_module = vectors_mod,
    });
    const run_vectors_tests = b.addRunArtifact(vectors_tests);
    test_step.dependOn(&run_vectors_tests.step);

    const e2e_mod = b.createModule(.{
        .root_source_file = b.path("tests/e2e.zig"),
        .target = target,
        .optimize = optimize,
    });
    e2e_mod.addImport("paseto", paseto_mod);
    const e2e_tests = b.addTest(.{
        .root_module = e2e_mod,
    });
    const run_e2e_tests = b.addRunArtifact(e2e_tests);
    test_step.dependOn(&run_e2e_tests.step);
}
