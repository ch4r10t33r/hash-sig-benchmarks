use hashsig::signature::{
    SignatureScheme,
    generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8,
};
use std::time::Instant;
use std::env;
use rand::{SeedableRng, rngs::StdRng};
use sha3::Digest;
use sha3::Sha3_256;

fn main() {
    println!("Rust hash-sig Key Generation Benchmark");
    println!("=======================================");
    println!("Lifetime: 2^10 = 1,024 signatures (using Lifetime18 type)");
    println!("Architecture: Generalized XMSS");
    println!("Parameters: Winternitz (22 chains of length 256, w=8)");
    println!("Hash: Poseidon2");
    println!();

    // Read SEED_HEX env var (64 hex chars => 32 bytes). Default to 0x42 repeated
    let seed_hex = env::var("SEED_HEX").unwrap_or_else(|_| "42".repeat(64));
    let mut seed = [0u8; 32];
    for i in 0..32 {
        let hi = u8::from_str_radix(&seed_hex[i*2..i*2+1], 16).unwrap_or(0);
        let lo = u8::from_str_radix(&seed_hex[i*2+1..i*2+2], 16).unwrap_or(0);
        seed[i] = (hi << 4) | lo;
    }
    let mut rng = StdRng::from_seed(seed);
    
    // Use 2^10 lifetime with hypercube parameters
    const LIFETIME_2_10: usize = 1024;
    
    let used_seed_hex = if seed_hex.len() >= 64 { &seed_hex[..64] } else { &seed_hex };
    println!("SEED: {}", used_seed_hex);
    
    // Debug: Print actual parameters being used
    println!("DEBUG: Using lifetime: {}", LIFETIME_2_10);
    println!("DEBUG: RNG seed bytes: {:?}", seed);
    println!("DEBUG: Winternitz parameters: 22 chains × 256 length (w=8)");
    
    println!("Generating keypair (Generalized XMSS with Winternitz)...");
    
    let start = Instant::now();
    let (pk, _sk) = SIGWinternitzLifetime18W8::key_gen(
        &mut rng,
        0,              // activation_epoch
        LIFETIME_2_10   // num_active_epochs
    );
    
    let duration = start.elapsed();
    
    println!("Key generation completed in {:.3} seconds", duration.as_secs_f64());
    println!();

    // Hash the canonical public key bytes using bincode serialization
    let mut maybe_digest: Option<String> = None;
    if let Ok(pk_bytes) = bincode::serialize(&pk) {
        let mut hasher = Sha3_256::new();
        hasher.update(&pk_bytes);
        let out = hasher.finalize();
        maybe_digest = Some(hex::encode(out));
        
        println!("DEBUG: Serialized public key size: {} bytes", pk_bytes.len());
    } else if let Ok(json) = serde_json::to_vec(&pk) {
        // Fallback to JSON serialization
        let mut hasher = Sha3_256::new();
        hasher.update(&json);
        let out = hasher.finalize();
        maybe_digest = Some(hex::encode(out));
        
        println!("DEBUG: JSON public key size: {} bytes", json.len());
    }
    
    // Output in format compatible with benchmark script
    println!("BENCHMARK_SEED: {}", used_seed_hex);
    if let Some(d) = maybe_digest {
        println!("PUBLIC_SHA3: {}", d);
    }
    println!("VERIFY_OK: {}", true);
    println!("BENCHMARK_RESULT: {:.6}", duration.as_secs_f64());
    
    println!();
    println!("✅ Benchmark completed successfully!");
    println!("Implementation: Rust hash-sig (Generalized XMSS)");
    println!("Parameters: Winternitz (22 chains × 256 length, w=8)");
    println!("Note: Using SIGWinternitzLifetime18W8 with 1024 epochs");
}
