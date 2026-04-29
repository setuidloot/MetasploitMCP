#!/usr/bin/env python3
"""
Test runner script that runs all test files individually to avoid fixture conflicts.
This is necessary because the integration tests use different mocking strategies
that conflict when run together.
"""

import subprocess
import sys
import os

def run_test_file(test_file):
    """Run a single test file and return the result."""
    print(f"\n{'='*60}")
    print(f"Running {test_file}")
    print('='*60)
    
    result = subprocess.run([
        sys.executable, '-m', 'pytest', test_file, '-v'
    ], capture_output=False)
    
    return result.returncode == 0

def main():
    """Run all test files individually."""
    test_files = [
        'tests/test_helpers.py',
        'tests/test_options_parsing.py', 
        'tests/test_ip_validation.py',
        'tests/test_tools_integration.py'
    ]
    
    results = {}
    
    for test_file in test_files:
        if os.path.exists(test_file):
            results[test_file] = run_test_file(test_file)
        else:
            print(f"Warning: {test_file} not found")
            results[test_file] = False
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print('='*60)
    
    all_passed = True
    for test_file, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_file}: {status}")
        if not passed:
            all_passed = False
    
    print(f"\nOverall result: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
