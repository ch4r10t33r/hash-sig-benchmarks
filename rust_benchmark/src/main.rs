use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W8;
use hashsig::signature::SignatureScheme;
use std::time::Instant;

fn main() {
    println!("Rust hash-sig Key Generation Benchmark");
    println!("=======================================");
    println!("Lifetime: 2^18 = 262,144 signatures");
    println!("Parameters: 64 chains of length 8 (w=8)");
    println!("Hash: Poseidon2");
    println!();

    let mut rng = rand::rng();
    
    println!("Generating keypair...");
    let start = Instant::now();
    let (_pk, _sk) = SIGWinternitzLifetime18W8::key_gen(
        &mut rng,
        0,
        SIGWinternitzLifetime18W8::LIFETIME as usize
    );
    let duration = start.elapsed();
    
    println!("Key generation completed in {:.3} seconds", duration.as_secs_f64());
    println!();
    
    // Output in format compatible with benchmark script
    println!("BENCHMARK_RESULT: {:.6}", duration.as_secs_f64());
}

