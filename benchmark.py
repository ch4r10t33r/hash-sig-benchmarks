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


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark runs"""
    lifetime: int = 262144  # 2^18 (both implementations support this)
    height: int = 18
    iterations: int = 3  # Fewer iterations for large lifetimes
    timeout: int = 600  # seconds (10 minutes)
    

class HashSigImplementation(ABC):
    """Abstract base class for hash signature implementations"""
    
    def __init__(self, name: str, repo_url: str, output_dir: Path):
        self.name = name
        self.repo_url = repo_url
        self.output_dir = output_dir
        self.repo_dir = Path(name)
        
    @abstractmethod
    def clone(self) -> bool:
        """Clone the repository"""
        pass
    
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
        super().__init__(
            'hash-sig',
            'https://github.com/b-wagn/hash-sig.git',
            output_dir / 'hash-sig'
        )
        # hash-sig only supports lifetimes 2^18 and 2^20
        self.supported_lifetimes = {18, 20}
    
    def clone(self) -> bool:
        """Clone hash-sig repository"""
        try:
            if self.repo_dir.exists():
                print(f"  {self.name} directory exists, pulling latest...")
                result = subprocess.run(
                    ['git', '-C', str(self.repo_dir), 'pull'],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 0
            else:
                print(f"  Cloning {self.name}...")
                result = subprocess.run(
                    ['git', 'clone', self.repo_url, str(self.repo_dir)],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 0
        except Exception as e:
            print(f"  Error cloning {self.name}: {e}")
            return False
    
    def build(self) -> bool:
        """Build hash-sig benchmarks using cargo"""
        try:
            print(f"  Building {self.name} with cargo (this may take a while)...")
            # Build the benchmarks (not just the library)
            result = subprocess.run(
                ['cargo', 'bench', '--no-run'],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"  Benchmark build failed: {result.stderr[:500]}")
                return False
            
            print(f"  Benchmark build successful")
            return True
        except Exception as e:
            print(f"  Error building {self.name}: {e}")
            return False
    
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate key using hash-sig's criterion benchmarks"""
        
        # Check if lifetime is supported
        if config.height not in self.supported_lifetimes:
            return KeyGenResult(0, 0, 0, False, 
                              f"Unsupported lifetime 2^{config.height}. Only 2^18 and 2^20 supported.")
        
        try:
            # Run criterion bench with specific filter
            # Format: "Poseidon/Lifetime 18/Winternitz/w 8/Key Generation"
            bench_filter = f"Lifetime {config.height}/Winternitz/w 8/Key Generation"
            
            print(f"      Running criterion benchmark (this takes ~60s per run)...", end='', flush=True)
            
            result = subprocess.run(
                ['cargo', 'bench', '--', bench_filter, '--warm-up-time', '1', '--measurement-time', '5'],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            
            if result.returncode != 0:
                # Try without filter
                result = subprocess.run(
                    ['cargo', 'bench', '--bench', 'benchmark'],
                    cwd=str(self.repo_dir),
                    capture_output=True,
                    text=True,
                    timeout=config.timeout
                )
                
                if result.returncode != 0:
                    return KeyGenResult(0, 0, 0, False, 
                                      f"Benchmark failed: {result.stderr[:300]}")
            
            # Parse criterion output for timing
            # Format: "time:   [42.532 s 42.890 s 43.267 s]"
            for line in result.stdout.split('\n') + result.stderr.split('\n'):
                if 'time:' in line.lower() and '[' in line and 's' in line:
                    try:
                        # Extract the middle value from [lower mean upper]
                        parts = line.split('[')[1].split(']')[0].split()
                        if len(parts) >= 5:  # [42.532 s 42.890 s 43.267 s]
                            mean_val = float(parts[2])  # Middle value
                            unit = parts[3]  # 's', 'ms', etc.
                            
                            # Convert to seconds
                            if unit == 's':
                                elapsed = mean_val
                            elif unit == 'ms':
                                elapsed = mean_val / 1000.0
                            elif unit == 'µs' or unit == 'us':
                                elapsed = mean_val / 1_000_000.0
                            else:
                                elapsed = mean_val  # Assume seconds
                            
                            return KeyGenResult(elapsed, 0, 0, True)
                    except (ValueError, IndexError) as e:
                        continue
            
            # Couldn't parse timing
            return KeyGenResult(0, 0, 0, False, 
                              "Could not parse benchmark output")
            
        except subprocess.TimeoutExpired:
            return KeyGenResult(0, 0, 0, False, f"Timeout after {config.timeout}s")
        except Exception as e:
            return KeyGenResult(0, 0, 0, False, str(e)[:200])


class HashZigImplementation(HashSigImplementation):
    """hash-zig Zig implementation wrapper"""
    
    def __init__(self, output_dir: Path):
        super().__init__(
            'hash-zig',
            'https://github.com/ch4r10t33r/hash-zig.git',
            output_dir / 'hash-zig'
        )
    
    def clone(self) -> bool:
        """Clone hash-zig repository"""
        try:
            if self.repo_dir.exists():
                print(f"  {self.name} directory exists, pulling latest...")
                result = subprocess.run(
                    ['git', '-C', str(self.repo_dir), 'pull'],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 0
            else:
                print(f"  Cloning {self.name}...")
                result = subprocess.run(
                    ['git', 'clone', self.repo_url, str(self.repo_dir)],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 0
        except Exception as e:
            print(f"  Error cloning {self.name}: {e}")
            return False
    
    def build(self) -> bool:
        """Build hash-zig using zig build"""
        try:
            print(f"  Building {self.name} with zig...")
            result = subprocess.run(
                ['zig', 'build', '-Doptimize=ReleaseFast'],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"  Build failed: {result.stderr}")
                return False
            
            print(f"  Build successful")
            return True
        except Exception as e:
            print(f"  Error building {self.name}: {e}")
            return False
    
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate key using hash-zig example"""
        
        try:
            # hash-zig prints timing in its example output
            # We run the example and parse the timing
            
            start_time = time.perf_counter()
            result = subprocess.run(
                ['zig', 'build', 'run', '-Doptimize=ReleaseFast'],
                cwd=str(self.repo_dir),
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return KeyGenResult(0, 0, 0, False, 
                                  f"Build/run failed: {result.stderr[:200]}")
            
            # Parse output for key generation timing
            # Format: "Key generation completed in 40282.19 ms"
            for line in result.stdout.split('\n'):
                if "Key generation completed in" in line and "ms" in line:
                    try:
                        time_part = line.split("in")[-1].split("ms")[0].strip()
                        elapsed_ms = float(time_part)
                        elapsed_sec = elapsed_ms / 1000.0
                        
                        # Also get key sizes from output
                        pub_size = 0
                        priv_size = 0
                        
                        lines = result.stdout.split('\n')
                        for i, l in enumerate(lines):
                            if "Public Key:" in l and i + 1 < len(lines):
                                next_line = lines[i + 1]
                                if "Length:" in next_line and "bytes" in next_line:
                                    try:
                                        pub_size = int(next_line.split("Length:")[-1].split("bytes")[0].strip())
                                    except:
                                        pass
                            if "Secret Key:" in l and i + 1 < len(lines):
                                next_line = lines[i + 1]
                                if "Length:" in next_line and "bytes" in next_line:
                                    try:
                                        priv_size = int(next_line.split("Length:")[-1].split("bytes")[0].strip())
                                    except:
                                        pass
                        
                        return KeyGenResult(elapsed_sec, priv_size, pub_size, True)
                    except (ValueError, IndexError) as e:
                        pass
            
            # Fallback: use wall clock time
            elapsed = end_time - start_time
            return KeyGenResult(elapsed, 0, 0, True, "Used wall clock time")
            
        except subprocess.TimeoutExpired:
            return KeyGenResult(0, 0, 0, False, "Timeout")
        except Exception as e:
            return KeyGenResult(0, 0, 0, False, str(e)[:200])


class BenchmarkRunner:
    """Main benchmark orchestration"""
    
    def __init__(self, config: BenchmarkConfig, output_dir: Path):
        self.config = config
        self.output_dir = output_dir
        self.implementations: List[HashSigImplementation] = []
        self.results: Dict[str, List[KeyGenResult]] = {}
        
    def add_implementation(self, impl: HashSigImplementation):
        """Add an implementation to benchmark"""
        self.implementations.append(impl)
        self.results[impl.name] = []
    
    def setup(self) -> bool:
        """Clone and build all implementations"""
        print("\n" + "="*70)
        print("SETUP PHASE")
        print("="*70)
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        for impl in self.implementations:
            print(f"\n{impl.name}:")
            
            if not impl.clone():
                print(f"  ✗ Failed to clone {impl.name}")
                return False
            print(f"  ✓ Repository ready")
            
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
        
        # Comparison
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
    print("Comparing hash-sig (Rust) vs hash-zig (Zig)")
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
