#!/usr/bin/env python3
"""
Solana Security Swarm - Performance Benchmark Suite
Collects real performance metrics to replace estimated values in documentation.
"""

import subprocess
import json
import time
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

class BenchmarkRunner:
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.binary_path = repo_root / "target" / "release" / "orchestrator"
        self.test_programs = [
            repo_root / "programs" / "vulnerable-vault",
            repo_root / "programs" / "exploit-registry",
        ]
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "system_info": {},
            "benchmarks": {},
            "analyzer_timings": {}
        }
    
    def collect_system_info(self):
        """Collect system information for context"""
        try:
            # CPU info
            cpu_info = subprocess.check_output(
                ["lscpu"], 
                text=True
            ).strip()
            
            # Extract key CPU details
            cpu_model = ""
            cpu_cores = ""
            for line in cpu_info.split('\n'):
                if 'Model name:' in line:
                    cpu_model = line.split(':')[1].strip()
                elif 'CPU(s):' in line and 'NUMA' not in line and 'On-line' not in line:
                    cpu_cores = line.split(':')[1].strip()
            
            # Memory info
            mem_info = subprocess.check_output(
                ["free", "-h"], 
                text=True
            ).strip()
            total_mem = mem_info.split('\n')[1].split()[1]
            
            self.results["system_info"] = {
                "cpu_model": cpu_model,
                "cpu_cores": cpu_cores,
                "total_memory": total_mem,
                "os": subprocess.check_output(["uname", "-s"], text=True).strip(),
                "kernel": subprocess.check_output(["uname", "-r"], text=True).strip(),
            }
            
            print(f"📊 System Info:")
            print(f"   CPU: {cpu_model}")
            print(f"   Cores: {cpu_cores}")
            print(f"   Memory: {total_mem}")
            print(f"   OS: {self.results['system_info']['os']} {self.results['system_info']['kernel']}")
            print()
            
        except Exception as e:
            print(f"⚠️  Warning: Could not collect full system info: {e}")
            self.results["system_info"] = {"error": str(e)}
    
    def build_release_binary(self):
        """Ensure release binary is built"""
        print("🔨 Building release binary...")
        try:
            subprocess.check_call(
                ["cargo", "build", "--release", "-p", "orchestrator"],
                cwd=self.repo_root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("✅ Release binary ready\n")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Build failed: {e}")
            return False
    
    def run_benchmark(
        self, 
        name: str, 
        program_path: Path, 
        flags: List[str] = None,
        iterations: int = 3
    ) -> Dict:
        """Run a single benchmark test"""
        if flags is None:
            flags = []
        
        print(f"🔄 Running benchmark: {name} ({iterations} iterations)")
        
        timings = []
        output_dir = self.repo_root / "benchmark_output"
        output_dir.mkdir(exist_ok=True)
        
        for i in range(iterations):
            cmd = [
                str(self.binary_path),
                "audit",
                "--repo", str(program_path),
                "--output-dir", str(output_dir),
            ] + flags
            
            start = time.time()
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                elapsed = time.time() - start
                timings.append(elapsed)
                print(f"   Iteration {i+1}: {elapsed:.2f}s")
                
            except subprocess.TimeoutExpired:
                print(f"   ⚠️  Iteration {i+1} timed out")
                continue
            except Exception as e:
                print(f"   ❌ Iteration {i+1} failed: {e}")
                continue
        
        if not timings:
            return {"error": "All iterations failed"}
        
        avg_time = sum(timings) / len(timings)
        min_time = min(timings)
        max_time = max(timings)
        
        benchmark_result = {
            "iterations": len(timings),
            "average_seconds": round(avg_time, 2),
            "min_seconds": round(min_time, 2),
            "max_seconds": round(max_time, 2),
            "all_timings": [round(t, 2) for t in timings]
        }
        
        print(f"   ✅ Average: {avg_time:.2f}s (min: {min_time:.2f}s, max: {max_time:.2f}s)\n")
        
        return benchmark_result
    
    def parse_analyzer_timings(self, report_path: Path) -> Dict:
        """Extract per-analyzer timings from JSON report"""
        try:
            with open(report_path) as f:
                report = json.load(f)
            
            # Extract execution times from various report sections
            timings = {}
            
            if report.get("kani_report"):
                kani = report["kani_report"]
                if "execution_time_ms" in kani:
                    timings["kani"] = kani["execution_time_ms"] / 1000.0
            
            if report.get("certora_report"):
                certora = report["certora_report"]
                if "total_time_seconds" in certora:
                    timings["certora"] = certora["total_time_seconds"]
            
            if report.get("wacana_report"):
                wacana = report["wacana_report"]
                if "execution_time_ms" in wacana:
                    timings["wacana"] = wacana["execution_time_ms"] / 1000.0
            
            if report.get("trident_report"):
                trident = report["trident_report"]
                if "execution_time_ms" in trident:
                    timings["trident"] = trident["execution_time_ms"] / 1000.0
            
            if report.get("fuzzdelsol_report"):
                fds = report["fuzzdelsol_report"]
                if "execution_time_ms" in fds:
                    timings["fuzzdelsol"] = fds["execution_time_ms"] / 1000.0
            
            if report.get("sec3_report"):
                sec3 = report["sec3_report"]
                if "execution_time_ms" in sec3:
                    timings["sec3"] = sec3["execution_time_ms"] / 1000.0
            
            if report.get("l3x_report"):
                l3x = report["l3x_report"]
                if "execution_time_ms" in l3x:
                    timings["l3x"] = l3x["execution_time_ms"] / 1000.0
            
            if report.get("geiger_report"):
                geiger = report["geiger_report"]
                if "execution_time_ms" in geiger:
                    timings["geiger"] = geiger["execution_time_ms"] / 1000.0
            
            if report.get("anchor_report"):
                anchor = report["anchor_report"]
                if "execution_time_ms" in anchor:
                    timings["anchor"] = anchor["execution_time_ms"] / 1000.0
            
            return timings
            
        except Exception as e:
            print(f"   ⚠️  Could not parse analyzer timings: {e}")
            return {}
    
    def run_all_benchmarks(self):
        """Run complete benchmark suite"""
        print("=" * 70)
        print("🚀 Solana Security Swarm - Performance Benchmark Suite")
        print("=" * 70)
        print()
        
        # Collect system info
        self.collect_system_info()
        
        # Build binary
        if not self.build_release_binary():
            print("❌ Cannot run benchmarks without successful build")
            return False
        
        # Benchmark 1: Static Analysis Only (Fastest)
        print("📋 Benchmark 1: Static Analysis Only")
        self.results["benchmarks"]["static_analysis_only"] = self.run_benchmark(
            "Static Analysis",
            self.test_programs[0],
            flags=["--no-wacana", "--no-trident", "--no-fuzzdelsol", "--no-sec3", "--no-l3x"]
        )
        
        # Benchmark 2: With Formal Verification
        print("📋 Benchmark 2: Static + Formal Verification")
        self.results["benchmarks"]["with_formal_verification"] = self.run_benchmark(
            "Formal Verification",
            self.test_programs[0],
            flags=[]
        )
        
        # Benchmark 3: Full Analysis Suite
        print("📋 Benchmark 3: Full Analysis Suite (All Analyzers)")
        self.results["benchmarks"]["full_analysis"] = self.run_benchmark(
            "Full Analysis",
            self.test_programs[0],
            flags=["--wacana", "--trident", "--fuzzdelsol", "--sec3", "--l3x", "--geiger", "--anchor"]
        )
        
        # Benchmark 4: Large codebase (if available)
        if len(self.test_programs) > 1:
            print("📋 Benchmark 4: Multiple Programs")
            self.results["benchmarks"]["multiple_programs"] = self.run_benchmark(
                "Multiple Programs",
                self.repo_root / "programs",
                flags=[]
            )
        
        # Try to extract per-analyzer timings
        output_dir = self.repo_root / "benchmark_output"
        report_files = list(output_dir.glob("*_report.json"))
        if report_files:
            print("📊 Extracting per-analyzer timings...")
            timings = self.parse_analyzer_timings(report_files[-1])
            if timings:
                self.results["analyzer_timings"] = timings
                print("✅ Per-analyzer timings extracted\n")
        
        return True
    
    def generate_report(self, output_path: Path):
        """Generate benchmark report"""
        # Save JSON
        json_path = output_path / "benchmark_results.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate Markdown report
        md_path = output_path / "BENCHMARK_RESULTS.md"
        with open(md_path, 'w') as f:
            f.write("# Solana Security Swarm - Performance Benchmarks\n\n")
            f.write(f"**Generated**: {self.results['timestamp']}\n\n")
            
            # System Info
            f.write("## System Information\n\n")
            sysinfo = self.results.get("system_info", {})
            f.write(f"- **CPU**: {sysinfo.get('cpu_model', 'Unknown')}\n")
            f.write(f"- **Cores**: {sysinfo.get('cpu_cores', 'Unknown')}\n")
            f.write(f"- **Memory**: {sysinfo.get('total_memory', 'Unknown')}\n")
            f.write(f"- **OS**: {sysinfo.get('os', 'Unknown')} {sysinfo.get('kernel', '')}\n\n")
            
            # Benchmark Results
            f.write("## Benchmark Results\n\n")
            f.write("| Test | Average | Min | Max | Iterations |\n")
            f.write("|------|---------|-----|-----|------------|\n")
            
            for name, data in self.results.get("benchmarks", {}).items():
                if "error" in data:
                    f.write(f"| {name} | ERROR | - | - | - |\n")
                else:
                    f.write(f"| {name} | {data['average_seconds']}s | {data['min_seconds']}s | {data['max_seconds']}s | {data['iterations']} |\n")
            
            f.write("\n")
            
            # Per-Analyzer Timings
            analyzer_timings = self.results.get("analyzer_timings", {})
            if analyzer_timings:
                f.write("## Per-Analyzer Execution Times\n\n")
                f.write("| Analyzer | Time (seconds) |\n")
                f.write("|----------|----------------|\n")
                for analyzer, time_sec in sorted(analyzer_timings.items()):
                    f.write(f"| {analyzer.capitalize()} | {time_sec:.2f}s |\n")
                f.write("\n")
            
            # Detailed Results
            f.write("## Detailed Results\n\n")
            f.write("```json\n")
            f.write(json.dumps(self.results["benchmarks"], indent=2))
            f.write("\n```\n")
        
        print("=" * 70)
        print("📊 Benchmark Results:")
        print("=" * 70)
        print()
        
        for name, data in self.results.get("benchmarks", {}).items():
            if "error" not in data:
                print(f"  {name:.<40} {data['average_seconds']:.2f}s")
        
        print()
        print(f"✅ Full report saved to: {md_path}")
        print(f"✅ JSON data saved to: {json_path}")
        print()

def main():
    repo_root = Path(__file__).parent
    
    runner = BenchmarkRunner(repo_root)
    
    if runner.run_all_benchmarks():
        runner.generate_report(repo_root)
        print("✅ Benchmark suite completed successfully!")
        return 0
    else:
        print("❌ Benchmark suite failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
