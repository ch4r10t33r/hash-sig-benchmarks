const std = @import("std");
const hash_sig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Zig hash-zig Key Generation Benchmark\n", .{});
    std.debug.print("======================================\n", .{});
    std.debug.print("Lifetime: 2^16 = 65,536 signatures\n", .{});
    std.debug.print("Parameters: 64 chains of length 8 (w=8)\n", .{});
    std.debug.print("Hash: Poseidon2\n", .{});
    std.debug.print("\n", .{});

    // Initialize with lifetime_2_16
    const params = hash_sig.Parameters.init(.lifetime_2_16);
    var sig_scheme = try hash_sig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    // Generate a fixed seed for reproducibility
    const seed: [32]u8 = .{42} ** 32;

    std.debug.print("Generating keypair...\n", .{});

    const start_time = std.time.nanoTimestamp();
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed);
    const end_time = std.time.nanoTimestamp();
    defer keypair.deinit(allocator);

    const duration_ns = end_time - start_time;
    const duration_sec = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;

    std.debug.print("Key generation completed in {d:.3} seconds\n", .{duration_sec});
    std.debug.print("\n", .{});

    // Output in format compatible with benchmark script
    std.debug.print("BENCHMARK_RESULT: {d:.6}\n", .{duration_sec});
}
