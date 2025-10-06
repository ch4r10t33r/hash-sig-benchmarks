#!/usr/bin/env python3
"""
Hash-Based Signature Benchmark Suite
Modular benchmarking framework for comparing hash-sig implementations
"""

import subprocess
import time
import os
import sys
import json
import shutil
from pathlib import Path
import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod


@dataclass
class KeyGenResult:
    """Results from a single key generation run"""
    time: float
    private_key_size: int
    public_key_size: int
    success: bool
    error_message: Optional[str] = None
    secret_hex: Optional[str] = None
    public_hex: Optional[str] = None


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark runs"""
    lifetime: int = 1024  # 2^10 (1,024 signatures)
    height: int = 10
    iterations: int = 3
    timeout: int = 1800  # seconds (30 minutes for larger tree)
    

class HashSigImplementation(ABC):
    """Abstract base class for hash signature implementations"""
    
    def __init__(self, name: str, output_dir: Path):
        self.name = name
        self.output_dir = output_dir
    
    @abstractmethod
    def build(self) -> bool:
        """Build the implementation"""
        pass
    
    @abstractmethod
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate a keypair and return timing results"""
        pass
    
    def cleanup(self):
        """Clean up generated files"""
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)


class HashSigImplementationRust(HashSigImplementation):
    """hash-sig Rust implementation wrapper"""
    
    def __init__(self, output_dir: Path):
        super().__init__('hash-sig', output_dir / 'hash-sig')
        # Path to our custom benchmark wrapper
        self.wrapper_dir = Path.cwd() / 'rust_benchmark'
    
    def build(self) -> bool:
        """Build hash-sig wrapper binary using cargo"""
        try:
            print(f"  Building {self.name} wrapper with cargo...")
            # Build our custom wrapper that uses the hash-sig library
            result = subprocess.run(
                ['cargo', 'build', '--release'],
                cwd=str(self.wrapper_dir),
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"  Build failed: {result.stderr[:500]}")
                return False
            
            # Verify binary exists
            binary = self.wrapper_dir / 'target' / 'release' / 'keygen_bench'
            if not binary.exists():
                print(f"  Binary not found after build")
                return False
            
            print(f"  Build successful")
            return True
        except Exception as e:
            print(f"  Error building {self.name}: {e}")
            return False
    
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate key using our custom Rust wrapper"""
        
        try:
            # Run our custom wrapper binary
            binary = self.wrapper_dir / 'target' / 'release' / 'keygen_bench'
            
            if not binary.exists():
                # Attempt to build on-demand, then re-check
                _ = self.build()
                if not binary.exists():
                    return KeyGenResult(0, 0, 0, False, "Wrapper binary not found. Build may have failed.")
            
            print(f"", end='', flush=True)
            
            # Provide same fixed seed to rust wrapper via env as well (wrapper may ignore)
            env = os.environ.copy()
            env.setdefault('SEED_HEX', '42' * 64)

            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=config.timeout,
                env=env,
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return KeyGenResult(0, 0, 0, False, 
                                  f"Binary failed: {result.stderr[:300]}")
            
            # Parse output for benchmark result and test flags
            # Format: "BENCHMARK_RESULT: 233.329641"
            seed_hex = env.get('SEED_HEX')
            for line in result.stdout.split('\n'):
                if "BENCHMARK_RESULT:" in line:
                    try:
                        time_str = line.split("BENCHMARK_RESULT:")[-1].strip()
                        elapsed = float(time_str)
                        # Rust wrapper currently doesn't emit keys; attach seed for report
                        return KeyGenResult(elapsed, 0, 0, True, None, seed_hex, None)
                    except (ValueError, IndexError) as e:
                        print(f" ✗ Parse error: {e}")
                        continue
            
                if line.startswith("PUBLIC_SHA3:"):
                    try:
                        pk_str = line.split(":", 1)[1].strip()
                        return KeyGenResult(elapsed, 0, 0, True, None, seed_hex, pk_str)
                    except Exception:
                        pass
                if line.startswith("VERIFY_OK:"):
                    # could store/print but not needed for return
                    pass

            # Fallback: couldn't parse, use wall clock
            elapsed = end_time - start_time
            return KeyGenResult(elapsed, 0, 0, True, "Used wall clock time", seed_hex, None)
            
        except subprocess.TimeoutExpired:
            return KeyGenResult(0, 0, 0, False, f"Timeout after {config.timeout}s")
        except Exception as e:
            return KeyGenResult(0, 0, 0, False, str(e)[:200])


class HashZigImplementation(HashSigImplementation):
    """hash-zig standard (Rust-compatible) implementation wrapper"""
    
    def __init__(self, output_dir: Path):
        super().__init__('hash-zig', output_dir / 'hash-zig')
        # Path to the standalone zig benchmark project
        self.zig_proj_dir = Path.cwd() / 'zig_benchmark'
    
    def build(self) -> bool:
        """Build standalone zig benchmark using zig build"""
        try:
            print(f"  Building {self.name} (Standard Rust-compatible) with zig...")

            result = subprocess.run(
                ['zig', 'build', '-Doptimize=ReleaseFast'],
                cwd=str(self.zig_proj_dir),
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"  Build failed: {result.stderr[:500]}")
                return False
            
            # Verify binary exists
            binary = self.zig_proj_dir / 'zig-out' / 'bin' / 'keygen_bench'
            if not binary.exists():
                print(f"  Binary not found after build")
                return False
            
            print(f"  Build successful")
            return True
        except Exception as e:
            print(f"  Error building {self.name}: {e}")
            return False
    
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate key using standalone zig benchmark executable"""
        
        try:
            # Run the SIMD benchmark binary
            binary = self.zig_proj_dir / 'zig-out' / 'bin' / 'keygen_bench'
            
            if not binary.exists():
                # Attempt to build on-demand, then re-check
                _ = self.build()
                if not binary.exists():
                    return KeyGenResult(0, 0, 0, False, "SIMD benchmark binary not found. Build may have failed.")
            
            print(f"", end='', flush=True)
            
            # Provide a fixed seed via environment for reproducibility
            env = os.environ.copy()
            env.setdefault('SEED_HEX', '42' * 64)

            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=config.timeout,
                env=env,
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return KeyGenResult(0, 0, 0, False, 
                                  f"Binary failed: {result.stderr[:300]}")
            
            # Parse output for benchmark result and test flags (from standalone zig)
            # Format: "BENCHMARK_RESULT: 0.123456"
            seed_hex = env.get('SEED_HEX')
            for line in result.stdout.split('\n'):
                if line.startswith("BENCHMARK_RESULT:"):
                    try:
                        time_str = line.split(":", 1)[1].strip()
                        elapsed = float(time_str)
                        return KeyGenResult(elapsed, 0, 0, True, None, seed_hex, None)
                    except (ValueError, IndexError) as e:
                        print(f" ✗ Parse error: {e}")
                        continue
                if line.startswith("PUBLIC_SHA3:"):
                    # Optional logging hook for future comparison
                    pass
                if line.startswith("VERIFY_OK:"):
                    # Optional logging hook
                    pass
            
            # Fallback: use wall clock time
            elapsed = end_time - start_time
            return KeyGenResult(elapsed, 0, 0, True, "Used wall clock time", seed_hex, None)
            
        except subprocess.TimeoutExpired:
            return KeyGenResult(0, 0, 0, False, f"Timeout after {config.timeout}s")
        except Exception as e:
            return KeyGenResult(0, 0, 0, False, str(e)[:200])


class BenchmarkRunner:
    """Main benchmark orchestration"""
    
    def __init__(self, config: BenchmarkConfig, output_dir: Path):
        self.config = config
        self.output_dir = output_dir
        self.implementations: List[HashSigImplementation] = []
        self.results: Dict[str, List[KeyGenResult]] = {}
        self.repos_dir = Path.cwd()
        
    def add_implementation(self, impl: HashSigImplementation):
        """Add an implementation to benchmark"""
        self.implementations.append(impl)
        self.results[impl.name] = []
    
    def clone_repositories(self) -> bool:
        """Skip git clone - using local wrappers only"""
        print("\n" + "="*70)
        print("Using local benchmark wrappers (no git clone needed)")
        print("="*70)
        print("  Rust: rust_benchmark/")
        print("  Zig:  zig_benchmark/")
        return True
    
    def setup(self) -> bool:
        """Setup: clone repos and build wrappers"""
        # Clone repositories first
        if not self.clone_repositories():
            return False
        
        print("\n" + "="*70)
        print("BUILD PHASE")
        print("="*70)
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        for impl in self.implementations:
            print(f"\n{impl.name}:")
            
            if not impl.build():
                print(f"  ✗ Failed to build {impl.name}")
                return False
            print(f"  ✓ Build successful")
            
            impl.cleanup()
            print(f"  ✓ Output directory prepared")
        
        return True
    
    def run(self):
        """Execute benchmark for all implementations"""
        print("\n" + "="*70)
        print("BENCHMARK PHASE")
        print("="*70)
        print(f"Iterations: {self.config.iterations}")
        print(f"Key lifetime: 2^{self.config.height} = {self.config.lifetime} signatures")
        
        for i in range(self.config.iterations):
            print(f"\n--- Iteration {i+1}/{self.config.iterations} ---")
            
            for impl in self.implementations:
                print(f"  {impl.name}: ", end='', flush=True)
                
                result = impl.generate_key(i, self.config)
                self.results[impl.name].append(result)
                
                if result.success:
                    print(f"✓ {result.time:.3f}s")
                else:
                    print(f"✗ {result.error_message}")
    
    def analyze(self):
        """Analyze and display results"""
        print("\n" + "="*70)
        print("RESULTS")
        print("="*70)
        
        stats = {}
        
        for impl_name, results in self.results.items():
            successful = [r for r in results if r.success]
            
            print(f"\n{impl_name.upper()}")
            print("-" * 70)
            
            if not successful:
                print("  No successful runs")
                failed = [r for r in results if not r.success]
                if failed:
                    print(f"  Failed runs: {len(failed)}")
                    print(f"  Sample error: {failed[0].error_message}")
                continue
            
            times = [r.time for r in successful]
            priv_sizes = [r.private_key_size for r in successful]
            pub_sizes = [r.public_key_size for r in successful]
            
            mean_time = statistics.mean(times)
            
            stats[impl_name] = {
                'mean_time': mean_time,
                'successful_runs': len(successful)
            }
            
            print(f"  Successful runs: {len(successful)}/{len(results)}")
            print(f"\n  Key Generation Time:")
            print(f"    Mean:   {mean_time:.3f}s")
            print(f"    Median: {statistics.median(times):.3f}s")
            print(f"    Min:    {min(times):.3f}s")
            print(f"    Max:    {max(times):.3f}s")
            if len(times) > 1:
                print(f"    Stdev:  {statistics.stdev(times):.3f}s")
            
            if any(priv_sizes):
                print(f"\n  Key Sizes:")
                avg_priv = statistics.mean([s for s in priv_sizes if s > 0])
                print(f"    Private key: {avg_priv:,.0f} bytes")
                if any(pub_sizes):
                    avg_pub = statistics.mean([s for s in pub_sizes if s > 0])
                    print(f"    Public key:  {avg_pub:,.0f} bytes")
        
        # Comparison (and key equality if available)
        if len(stats) == 2:
            names = list(stats.keys())
            time1 = stats[names[0]]['mean_time']
            time2 = stats[names[1]]['mean_time']
            
            print("\n" + "="*70)
            print("COMPARISON")
            print("="*70)
            
            if time1 < time2:
                speedup = time2 / time1
                print(f"\n{names[0]} is {speedup:.2f}x faster than {names[1]}")
            else:
                speedup = time1 / time2
                print(f"\n{names[1]} is {speedup:.2f}x faster than {names[0]}")
            
            print(f"\nMean generation time:")
            for name in names:
                print(f"  {name}: {stats[name]['mean_time']:.3f}s")
            print(f"\nDifference: {abs(time1 - time2):.3f}s")

            # Key comparison if both provided keys
            rust_results = self.results.get('hash-sig', [])
            zig_results = self.results.get('hash-zig', [])
            if rust_results and zig_results:
                # Find first successful entries with keys
                rust_first = next((r for r in rust_results if r.success and r.secret_hex and r.public_hex), None)
                zig_first = next((r for r in zig_results if r.success and r.secret_hex and r.public_hex), None)
                if rust_first and zig_first:
                    same_secret = rust_first.secret_hex == zig_first.secret_hex
                    same_public = rust_first.public_hex == zig_first.public_hex
                    print("\nKey Comparison (same seed):")
                    print(f"  Secret keys: {'SAME' if same_secret else 'DIFFERENT'}")
                    print(f"  Public keys: {'SAME' if same_public else 'DIFFERENT'}")
                else:
                    print("\nKey Comparison: Not available (one or both implementations did not emit keys)")

        # Final report extras: seed and public keys if available
        print("\n" + "="*70)
        print("FINAL ARTIFACTS")
        print("="*70)
        # Seed used (prefer rust if present, else zig)
        rust_first = next((r for r in self.results.get('hash-sig', []) if r.success and r.secret_hex), None)
        zig_first = next((r for r in self.results.get('hash-zig-simd', []) if r.success and r.secret_hex), None)
        seed_hex = rust_first.secret_hex if rust_first else (zig_first.secret_hex if zig_first else None)
        if seed_hex:
            print(f"Seed used (hex): {seed_hex}")
        else:
            print("Seed used (hex): unavailable")

        # Public keys
        rust_pk = next((r.public_hex for r in self.results.get('hash-sig', []) if r.success and r.public_hex), None)
        zig_pk = next((r.public_hex for r in self.results.get('hash-zig-simd', []) if r.success and r.public_hex), None)
        print(f"Rust public key: {rust_pk if rust_pk else 'unavailable'}")
        print(f"Zig public key:  {zig_pk if zig_pk else 'unavailable'}")
    
    def save_results(self, filename: str = 'benchmark_results.json'):
        """Save results to JSON"""
        output = {
            'config': asdict(self.config),
            'results': {
                name: [asdict(r) for r in results]
                for name, results in self.results.items()
            }
        }
        
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n✓ Results saved to {filepath}")


def check_dependencies():
    """Check if required tools are installed"""
    deps = {
        'git': 'Git',
        'cargo': 'Rust (cargo)',
        'zig': 'Zig compiler'
    }
    
    missing = []
    for cmd, name in deps.items():
        if shutil.which(cmd) is None:
            missing.append(name)
    
    if missing:
        print("Missing dependencies:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nPlease install missing dependencies:")
        print("  Rust: https://rustup.rs/")
        print("  Zig: https://ziglang.org/download/")
        return False
    
    return True


def main():
    """Main entry point"""
    print("Hash-Based Signature Benchmark Suite")
    print("="*70)
    print("Comparing hash-sig (Rust) vs hash-zig (Zig Standard)")
    print("Both use Generalized XMSS architecture")
    print()
    
    if not check_dependencies():
        return 1
    
    # Parse arguments
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    
    # Configuration
    config = BenchmarkConfig(iterations=iterations)
    output_dir = Path('benchmark_output')
    
    # Setup benchmark
    runner = BenchmarkRunner(config, output_dir)
    runner.add_implementation(HashSigImplementationRust(output_dir))
    runner.add_implementation(HashZigImplementation(output_dir))
    
    try:
        # Setup phase
        if not runner.setup():
            print("\n✗ Setup failed")
            return 1
        
        # Benchmark phase
        runner.run()
        
        # Analysis phase
        runner.analyze()
        
        # Save results
        runner.save_results()
        
        print("\n✓ Benchmark complete")
        return 0
        
    except KeyboardInterrupt:
        print("\n\n✗ Benchmark interrupted by user")
        runner.analyze()
        runner.save_results('benchmark_results_partial.json')
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
