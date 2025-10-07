# Bitwarden Duplicate Checker - Development Makefile

.PHONY: install test lint format clean run help

# Default target
help:
	@echo "Bitwarden Duplicate Checker - Development Commands"
	@echo "================================================="
	@echo "install     - Install dependencies"
	@echo "test        - Run test suite"
	@echo "lint        - Run code linting"
	@echo "format      - Format code with black"
	@echo "clean       - Clean up generated files"
	@echo "run         - Run the checker with example data"
	@echo "run-async   - Run with async processing"
	@echo "benchmark   - Run performance benchmarks"
	@echo "help        - Show this help"

install:
	pip install -r requirements.txt

test:
	python -m pytest test_bitwarden_checker.py -v

lint:
	flake8 bitwarden_duplicate_checker.py
	mypy bitwarden_duplicate_checker.py --ignore-missing-imports

format:
	black bitwarden_duplicate_checker.py test_bitwarden_checker.py

clean:
	rm -f *.log
	rm -f duplicate_analysis_report_*.txt
	rm -f bitwarden_duplicates_*.csv
	rm -f bitwarden_clean_export_*.json
	rm -f bitwarden_clean_export_*.csv
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

run:
	python bitwarden_duplicate_checker.py example_bitwarden_export.json --passes 2

run-async:
	python bitwarden_duplicate_checker.py example_bitwarden_export.json --passes 2 --async --ml-analysis

benchmark:
	python bitwarden_duplicate_checker.py example_bitwarden_export.json --passes 1 --async --max-workers 8

# Development shortcuts
dev-install: install
	@echo "Development environment ready!"

quick-test:
	python bitwarden_duplicate_checker.py example_bitwarden_export.json --passes 1 --no-csv

full-test:
	python bitwarden_duplicate_checker.py example_bitwarden_export.json --passes 3 --async --ml-analysis --clean-export
