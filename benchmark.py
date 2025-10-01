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
    lifetime: int = 65536  # 2^16 (65,536 signatures)
    height: int = 16
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
                return KeyGenResult(0, 0, 0, False, "Wrapper binary not found. Build may have failed.")
            
            print(f"", end='', flush=True)
            
            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return KeyGenResult(0, 0, 0, False, 
                                  f"Binary failed: {result.stderr[:300]}")
            
            # Parse output for benchmark result
            # Format: "BENCHMARK_RESULT: 233.329641"
            for line in result.stdout.split('\n'):
                if "BENCHMARK_RESULT:" in line:
                    try:
                        time_str = line.split("BENCHMARK_RESULT:")[-1].strip()
                        elapsed = float(time_str)
                        return KeyGenResult(elapsed, 0, 0, True)
                    except (ValueError, IndexError) as e:
                        print(f" ✗ Parse error: {e}")
                        continue
            
            # Fallback: couldn't parse, use wall clock
            elapsed = end_time - start_time
            return KeyGenResult(elapsed, 0, 0, True, "Used wall clock time")
            
        except subprocess.TimeoutExpired:
            return KeyGenResult(0, 0, 0, False, f"Timeout after {config.timeout}s")
        except Exception as e:
            return KeyGenResult(0, 0, 0, False, str(e)[:200])


class HashZigImplementation(HashSigImplementation):
    """hash-zig Zig implementation wrapper"""
    
    def __init__(self, output_dir: Path):
        super().__init__('hash-zig', output_dir / 'hash-zig')
        # Path to our custom benchmark wrapper
        self.wrapper_dir = Path.cwd() / 'zig_benchmark'
    
    def build(self) -> bool:
        """Build hash-zig wrapper using zig build"""
        try:
            print(f"  Building {self.name} wrapper with zig...")
            
            # Use Zig 0.14.1 (required for hash-zig)
            zig_path = '/Users/partha/.local/share/zigup/0.14.1/files/zig'
            
            # Build our custom wrapper that uses the hash-zig library
            result = subprocess.run(
                [zig_path, 'build', '-Doptimize=ReleaseFast'],
                cwd=str(self.wrapper_dir),
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"  Build failed: {result.stderr[:500]}")
                return False
            
            # Verify binary exists
            binary = self.wrapper_dir / 'zig-out' / 'bin' / 'keygen_bench'
            if not binary.exists():
                print(f"  Binary not found after build")
                return False
            
            print(f"  Build successful")
            return True
        except Exception as e:
            print(f"  Error building {self.name}: {e}")
            return False
    
    def generate_key(self, iteration: int, config: BenchmarkConfig) -> KeyGenResult:
        """Generate key using our custom Zig wrapper"""
        
        try:
            # Run our custom wrapper binary
            binary = self.wrapper_dir / 'zig-out' / 'bin' / 'keygen_bench'
            
            if not binary.exists():
                return KeyGenResult(0, 0, 0, False, "Wrapper binary not found. Build may have failed.")
            
            print(f"", end='', flush=True)
            
            start_time = time.perf_counter()
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            end_time = time.perf_counter()
            
            if result.returncode != 0:
                return KeyGenResult(0, 0, 0, False, 
                                  f"Binary failed: {result.stderr[:300]}")
            
            # Parse output for benchmark result
            # Format: "BENCHMARK_RESULT: 10496.123456"
            for line in result.stdout.split('\n'):
                if "BENCHMARK_RESULT:" in line:
                    try:
                        time_str = line.split("BENCHMARK_RESULT:")[-1].strip()
                        elapsed = float(time_str)
                        return KeyGenResult(elapsed, 0, 0, True)
                    except (ValueError, IndexError) as e:
                        print(f" ✗ Parse error: {e}")
                        continue
            
            # Fallback: use wall clock time
            elapsed = end_time - start_time
            return KeyGenResult(elapsed, 0, 0, True, "Used wall clock time")
            
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
        """Clone or update required repositories to latest code"""
        repos = {
            'hash-sig': 'https://github.com/b-wagn/hash-sig.git',
            'hash-zig': 'https://github.com/ch4r10t33r/hash-zig.git',
        }
        
        print("\n" + "="*70)
        print("UPDATING REPOSITORIES TO LATEST")
        print("="*70)
        
        for name, url in repos.items():
            repo_path = self.repos_dir / name
            
            if repo_path.exists():
                print(f"\n{name}:")
                print(f"  Repository exists, ensuring we have latest code...")
                
                # First, fetch all remote changes
                fetch_result = subprocess.run(
                    ['git', '-C', str(repo_path), 'fetch', '--all'],
                    capture_output=True,
                    text=True
                )
                
                if fetch_result.returncode != 0:
                    print(f"  ⚠ Fetch failed: {fetch_result.stderr[:200]}")
                    print(f"  Removing and re-cloning...")
                    if repo_path.is_symlink():
                        repo_path.unlink()
                    else:
                        shutil.rmtree(repo_path)
                else:
                    # Reset to latest origin/main to ensure clean state
                    reset_result = subprocess.run(
                        ['git', '-C', str(repo_path), 'reset', '--hard', 'origin/main'],
                        capture_output=True,
                        text=True
                    )
                    
                    if reset_result.returncode == 0:
                        print(f"  ✓ Reset to latest origin/main")
                    else:
                        # If reset fails, try pull as fallback
                        pull_result = subprocess.run(
                            ['git', '-C', str(repo_path), 'pull', 'origin', 'main'],
                            capture_output=True,
                            text=True
                        )
                        if pull_result.returncode == 0:
                            print(f"  ✓ Updated to latest")
                        else:
                            print(f"  ⚠ Pull failed, removing and re-cloning: {pull_result.stderr[:200]}")
                            if repo_path.is_symlink():
                                repo_path.unlink()
                            else:
                                shutil.rmtree(repo_path)
            
            # If directory doesn't exist or was removed, clone fresh
            if not repo_path.exists():
                print(f"\n{name}:")
                print(f"  Cloning fresh from {url}...")
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', url, str(repo_path)],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    print(f"  ✗ Clone failed: {result.stderr[:300]}")
                    return False
                print(f"  ✓ Cloned successfully")
        
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
