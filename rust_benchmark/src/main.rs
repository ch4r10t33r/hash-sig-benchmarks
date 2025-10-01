use hashsig::signature::{
    SignatureScheme,
    generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8,
};
use std::time::Instant;

fn main() {
    println!("Rust hash-sig Key Generation Benchmark");
    println!("=======================================");
    println!("Lifetime: 2^16 = 65,536 signatures");
    println!("Parameters: 22 chains of length 256 (w=8)");
    println!("Hash: Poseidon2");
    println!();

    let mut rng = rand::rng();
    
    // Use 2^16 lifetime (the instantiation supports up to 2^18, but we use smaller value)
    const LIFETIME_2_16: usize = 65536;
    
    println!("Generating keypair...");
    let start = Instant::now();
    let (_pk, _sk) = SIGWinternitzLifetime18W8::key_gen(
        &mut rng,
        0,
        LIFETIME_2_16
    );
    let duration = start.elapsed();
    
    println!("Key generation completed in {:.3} seconds", duration.as_secs_f64());
    println!();
    
    // Output in format compatible with benchmark script
    println!("BENCHMARK_RESULT: {:.6}", duration.as_secs_f64());
}

