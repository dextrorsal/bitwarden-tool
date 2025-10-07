# Bitwarden Duplicate Checker

A comprehensive Python tool to detect duplicate passwords, URLs, and domains in Bitwarden export files.

## Features

- Multiple scan types (passwords, URLs, domains)
- Configurable scan passes for thoroughness
- Simple GUI with progress tracking
- Detailed reporting with masked passwords
- CSV export capabilities
- Security-first design

## Installation

No additional dependencies required - uses only Python standard library.

## Usage

### GUI (Recommended)
```bash
python bitwarden_duplicate_checker_gui.py
```

### Command Line
```bash
python bitwarden_duplicate_checker.py your_export.json --passes 3
```

## Requirements

- Python 3.7+

## License

MIT License - see LICENSE file for details.
