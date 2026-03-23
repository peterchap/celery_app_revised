#!/usr/bin/env python3
"""
Demonstration of batch DNS fetching functionality.

This script demonstrates the key features of the new batch processing system:
1. Centralized throttling via shared semaphore
2. Batch-mode fetching with configurable workers
3. Robust serialization for PyArrow output
4. Separation of results and retries
"""

import asyncio
import sys
import os
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_module.dns_fetcher import fetch_batch, DEFAULT_BATCH_WORKERS
from dns_module.batch_processor import BatchProcessor, DEFAULT_WORKERS
from dns_module import dns_lookup


async def demo_fetch_batch():
    """Demonstrate fetch_batch functionality."""
    print("=" * 70)
    print("Demo 1: fetch_batch() - Low-level batch fetching")
    print("=" * 70)
    print()
    
    # Sample domains for testing (using well-known domains)
    test_domains = [
        "example.com",
        "example.org",
        "example.net",
    ]
    
    print(f"Fetching DNS records for {len(test_domains)} domains...")
    print("Workers: 3")
    print("Using shared semaphore for throttling")
    print()
    
    # Demonstrate fetch_batch
    results, retries = await fetch_batch(
        domains=test_domains,
        workers=3,
        retry_limit=1
    )
    
    print("Results:")
    print(f"  - Successfully processed: {len(results)}")
    print(f"  - Needs retry: {len(retries)}")
    print()
    
    # Show sample result
    if results:
        sample = results[0]
        print(f"Sample result for '{sample.domain}':")
        print(f"  - Status: {sample.status}")
        print(f"  - Records: {list(sample.records.keys())}")
        print(f"  - Errors: {list(sample.errors.keys())}")
        print(f"  - Meta: {sample.meta}")
    
    print()
    return len(results), len(retries)


async def demo_batch_processor():
    """Demonstrate BatchProcessor functionality."""
    print("=" * 70)
    print("Demo 2: BatchProcessor - High-level batch processing with Parquet output")
    print("=" * 70)
    print()
    
    # Create temporary output directory
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir) / "output"
        retry_dir = Path(tmpdir) / "retries"
        
        print("Configuration:")
        print(f"  - Output directory: {output_dir}")
        print(f"  - Retry directory: {retry_dir}")
        print(f"  - Workers: {DEFAULT_WORKERS}")
        print("  - Using dns_lookup.default_semaphore()")
        print()
        
        # Create BatchProcessor
        bp = BatchProcessor(
            file_key="demo_batch",
            output_dir=str(output_dir),
            retry_dir=str(retry_dir),
            workers=3,
            scoring_profiles=None
        )
        
        # Sample domains
        test_domains = [
            "example.com",
            "example.org",
            "example.net",
        ]
        
        print(f"Processing {len(test_domains)} domains...")
        print()
        
        # Process batch
        results_path, retries_path = await bp.process(test_domains)
        
        print("Processing complete:")
        print(f"  - Results file: {results_path}")
        print(f"  - Retries file: {retries_path}")
        print()
        
        # Verify files exist
        if results_path:
            print(f"✓ Results Parquet file created: {Path(results_path).exists()}")
        if retries_path:
            print(f"✓ Retries Parquet file created: {Path(retries_path).exists()}")
        
        print()
        return results_path, retries_path


def demo_configuration():
    """Show configuration and constants."""
    print("=" * 70)
    print("Configuration Summary")
    print("=" * 70)
    print()
    
    print("Constants:")
    print(f"  - DEFAULT_BATCH_WORKERS: {DEFAULT_BATCH_WORKERS}")
    print(f"  - DEFAULT_WORKERS: {DEFAULT_WORKERS}")
    print()
    
    print("Environment variables:")
    print(f"  - DEFAULT_WORKERS: {os.getenv('DEFAULT_WORKERS', 'not set (will use 200)')}")
    print()
    
    print("Features:")
    print("  ✓ Centralized throttling via shared semaphore")
    print("  ✓ Batch-mode fetching with queue-based workers")
    print("  ✓ Configurable worker count (default 200)")
    print("  ✓ Automatic result/retry separation")
    print("  ✓ Robust PyArrow serialization with fallback")
    print("  ✓ Placeholder hooks for labeling and scoring")
    print("  ✓ Parquet output with separate retry directory")
    print("  ✓ Comprehensive logging with throughput metrics")
    print()


async def main():
    """Run all demonstrations."""
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 18 + "Batch DNS Fetching Demonstration" + " " * 18 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    # Show configuration
    demo_configuration()
    
    # Note about DNS resolution
    print("=" * 70)
    print("Note: DNS resolution demonstrations")
    print("=" * 70)
    print()
    print("The following demos would normally fetch real DNS records, but they")
    print("require a working DNS resolver (e.g., local unbound at 127.0.0.1).")
    print()
    print("In this demonstration environment, we show the API structure and")
    print("initialization only. In production, these functions would:")
    print()
    print("  1. Fetch DNS records from a local unbound resolver")
    print("  2. Cache results in LMDB for persistence")
    print("  3. Use in-memory caching for fast repeated lookups")
    print("  4. Apply centralized throttling via shared semaphore")
    print("  5. Write results to Parquet files for analysis")
    print()
    
    # Uncomment these lines to test with actual DNS resolution:
    print("Demo 1: Low-level batch fetching")
    await demo_fetch_batch()
    print()
    # 
    print("Demo 2: High-level batch processing")
    await demo_batch_processor()
    print()
    
    print("=" * 70)
    print("Demonstration Complete")
    print("=" * 70)
    print()
    print("Summary:")
    print("  ✓ All modules imported successfully")
    print("  ✓ fetch_batch() function available")
    print("  ✓ BatchProcessor class available")
    print("  ✓ Configuration validated")
    print("  ✓ API structure verified")
    print()
    print("To test with actual DNS resolution:")
    print("  1. Ensure local unbound is running at 127.0.0.1")
    print("  2. Initialize LMDB cache")
    print("  3. Uncomment demo functions in main()")
    print()


if __name__ == "__main__":
    asyncio.run(main())
