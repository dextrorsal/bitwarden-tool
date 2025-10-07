#!/usr/bin/env python3
"""
Bitwarden Duplicate Checker Launcher
===================================

Simple launcher script that provides options to run GUI or CLI version.
"""

import sys
import os
import subprocess

def main():
    print("=" * 50)
    print("Bitwarden Duplicate Checker")
    print("=" * 50)
    print()
    print("Choose how to run the application:")
    print("1. GUI Application (Recommended)")
    print("2. Command Line Interface")
    print("3. Exit")
    print()
    
    while True:
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == "1":
            print("\nStarting GUI application...")
            try:
                subprocess.run([sys.executable, "bitwarden_duplicate_checker_gui.py"])
            except FileNotFoundError:
                print("Error: GUI file not found. Make sure 'bitwarden_duplicate_checker_gui.py' exists.")
            break
            
        elif choice == "2":
            print("\nCommand Line Interface")
            print("Usage: python bitwarden_duplicate_checker.py <export_file.json> [options]")
            print("\nOptions:")
            print("  --passes N     Number of scan passes (default: 3)")
            print("  --no-csv       Skip CSV export")
            print("  --verbose      Enable verbose logging")
            print("\nExample:")
            print("  python bitwarden_duplicate_checker.py example_bitwarden_export.json --passes 3")
            break
            
        elif choice == "3":
            print("\nGoodbye!")
            break
            
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
