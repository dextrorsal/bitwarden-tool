#!/usr/bin/env python3
"""
Simple Example Script for Bitwarden Duplicate Checker
===================================================

This script demonstrates how to use the BitwardenDuplicateChecker class
programmatically for custom analysis.
"""

from bitwarden_duplicate_checker import BitwardenDuplicateChecker
import json

def main():
    # Initialize the checker with example export file
    json_file = "example_bitwarden_export.json"
    checker = BitwardenDuplicateChecker(json_file, scan_passes=3)
    
    # Run the analysis with all features
    print("Starting comprehensive duplicate analysis...")
    results = checker.run_analysis(
        output_format='txt',
        export_csv=True,
        create_clean_export=True,
        clean_export_format='json'
    )
    
    if results:
        print(f"\n=== ANALYSIS RESULTS ===")
        print(f"Password duplicate groups: {results['password_duplicate_groups']}")
        print(f"Username duplicate groups: {results['username_duplicate_groups']}")
        print(f"Comprehensive duplicate groups: {results['comprehensive_duplicate_groups']}")
        print(f"URL duplicate groups: {results['url_duplicate_groups']}")
        print(f"Domain duplicate groups: {results['domain_duplicate_groups']}")
        print(f"Total duplicate groups: {results['total_duplicate_groups']}")
        
        print(f"\nMost common passwords:")
        for password, count in results['most_common_passwords'][:5]:
            masked = password[:3] + "*" * (len(password) - 6) + password[-3:] if len(password) > 6 else "*" * len(password)
            print(f"  {masked} (used {count} times)")
        
        print(f"\nMost common URLs:")
        for url, count in results['most_common_urls'][:5]:
            print(f"  {url} (used {count} times)")
        
        print(f"\nFiles created:")
        print(f"Report: {results['report_filename']}")
        if 'csv_export' in results:
            print(f"CSV export: {results['csv_export']}")
        if 'clean_export' in results:
            print(f"Clean export: {results['clean_export']}")
    else:
        print("Analysis failed!")

if __name__ == "__main__":
    main()
