const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Zig hash-zig Standard Implementation Benchmark\n", .{});
    std.debug.print("===============================================\n", .{});
    std.debug.print("Lifetime: 2^10 = 1,024 signatures\n", .{});
    std.debug.print("Architecture: Rust-compatible (Generalized XMSS)\n", .{});
    std.debug.print("Parameters: Winternitz (22 chains of length 256, w=8)\n", .{});
    std.debug.print("Hash: Poseidon2 (width=16, KoalaBear field)\n", .{});
    std.debug.print("\n", .{});

    // Initialize parameters with recommended Winternitz configuration (matching Rust)
    const params = hash_zig.Parameters.init(.lifetime_2_10);

    // Read SEED_HEX env var (64 hex chars => 32 bytes). Default to 0x42 repeated
    var seed: [32]u8 = undefined;
    if (std.process.getEnvVarOwned(allocator, "SEED_HEX")) |seed_hex| {
        defer allocator.free(seed_hex);
        if (seed_hex.len >= 64) {
            for (0..32) |i| {
                const hi = std.fmt.parseInt(u4, seed_hex[i * 2 .. i * 2 + 1], 16) catch 0;
                const lo = std.fmt.parseInt(u4, seed_hex[i * 2 + 1 .. i * 2 + 2], 16) catch 0;
                seed[i] = @as(u8, @intCast((@as(u8, hi) << 4) | @as(u8, lo)));
            }
        } else {
            @memset(&seed, 0x42);
        }
    } else |_| {
        @memset(&seed, 0x42);
    }

    // Emit seed for reproducibility
    std.debug.print("SEED: ", .{});
    for (seed) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    // Debug: Print actual parameters being used
    std.debug.print("DEBUG: Tree height: {}\n", .{params.tree_height});
    std.debug.print("DEBUG: Winternitz w: {}\n", .{params.winternitz_w});
    std.debug.print("DEBUG: Num chains: {}\n", .{params.num_chains});
    std.debug.print("DEBUG: Hash output len: {}\n", .{params.hash_output_len});
    std.debug.print("DEBUG: Chain length: {}\n", .{@as(u32, 1) << @intCast(params.winternitz_w)});

    std.debug.print("\nGenerating keypair (Rust-compatible implementation)...\n", .{});

    // Initialize signature scheme
    var sig_scheme = try hash_zig.HashSignature.init(allocator, params);
    defer sig_scheme.deinit();

    // Key generation benchmark
    const start_time = std.time.nanoTimestamp();
    var keypair = try sig_scheme.generateKeyPair(allocator, &seed, 0, 0);
    const end_time = std.time.nanoTimestamp();
    defer keypair.deinit(allocator);

    const duration_ns = end_time - start_time;
    const duration_sec = @as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0;

    // Display key information
    std.debug.print("Key generation completed in {d:.3} seconds\n\n", .{duration_sec});

    std.debug.print("Key Structure (Rust-compatible):\n", .{});
    std.debug.print("  Public Key:\n", .{});
    std.debug.print("    Root: {d} bytes\n", .{keypair.public_key.root.len});
    std.debug.print("  Secret Key:\n", .{});
    std.debug.print("    PRF key: {d} bytes\n", .{keypair.secret_key.prf_key.len});
    std.debug.print("    Tree nodes: {d}\n", .{keypair.secret_key.tree.len});
    std.debug.print("    Activation epoch: {d}\n", .{keypair.secret_key.activation_epoch});
    std.debug.print("    Active epochs: {d}\n\n", .{keypair.secret_key.num_active_epochs});

    // Self-verify: sign and verify a message
    const msg = "benchmark-message";

    std.debug.print("Testing sign/verify operations...\n", .{});

    // Generate RNG seed for encoding randomness
    var rng_seed: [32]u8 = undefined;
    std.crypto.random.bytes(&rng_seed);

    // Sign
    const sign_start = std.time.nanoTimestamp();
    var signature = try sig_scheme.sign(allocator, msg, &keypair.secret_key, 0, &rng_seed);
    const sign_end = std.time.nanoTimestamp();
    defer signature.deinit(allocator);

    const sign_duration = @as(f64, @floatFromInt(sign_end - sign_start)) / 1_000_000.0;

    // Verify
    const verify_start = std.time.nanoTimestamp();
    const verify_ok = try sig_scheme.verify(allocator, msg, signature, &keypair.public_key);
    const verify_end = std.time.nanoTimestamp();

    const verify_duration = @as(f64, @floatFromInt(verify_end - verify_start)) / 1_000_000.0;

    std.debug.print("  Sign: {d:.2} ms\n", .{sign_duration});
    std.debug.print("  Verify: {d:.2} ms\n", .{verify_duration});
    std.debug.print("  Signature valid: {}\n\n", .{verify_ok});

    // Hash the public key bytes for comparison
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(keypair.public_key.root);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);

    // Output results
    std.debug.print("PUBLIC_SHA3: ", .{});
    for (digest) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\nVERIFY_OK: {}\n", .{verify_ok});
    std.debug.print("BENCHMARK_RESULT: {d:.6}\n", .{duration_sec});

    std.debug.print("\n✅ Benchmark completed successfully!\n", .{});
    std.debug.print("Implementation: Standard Rust-compatible (HashSignature)\n", .{});
    std.debug.print("Parameters: Winternitz (22 chains × 256 length, w=8)\n", .{});
}
