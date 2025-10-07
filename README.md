# 🔐 Bitwarden Duplicate Checker

<div align="center">

![Python](https://img.shields.io/badge/python-3.7+-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=white)
![Security](https://img.shields.io/badge/Security-Local%20Only-red.svg?style=for-the-badge&logo=security&logoColor=white)
![Privacy](https://img.shields.io/badge/Privacy-No%20Data%20Sent-blue.svg?style=for-the-badge&logo=privacy&logoColor=white)

**A comprehensive Python tool to detect duplicate passwords, URLs, and usernames in Bitwarden export files with multiple scanning passes for thoroughness and safety.**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/bitwarden-duplicate-checker?style=social)](https://github.com/yourusername/bitwarden-duplicate-checker)

</div>

---

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Security](#security)
- [License](#license)

---

## 🚀 Quick Start

1. **Download and run:**
   ```bash
   git clone https://github.com/yourusername/bitwarden-duplicate-checker.git
   cd bitwarden-duplicate-checker
   python bitwarden_duplicate_checker_gui.py
   ```

2. **Select your Bitwarden export file** (JSON or CSV)

3. **Click "Start Analysis"** and review results

---

## 🎯 Features

### Duplicate Detection
- **Password Duplicates**: Find identical passwords across different sites
- **Username Duplicates**: Detect reused usernames across accounts  
- **URL Duplicates**: Detect multiple accounts on the same URL
- **Domain Duplicates**: Identify multiple services on the same domain
- **Comprehensive Duplicates**: Same username + password + URL combinations

### Advanced Analysis
- **Machine Learning Analysis**: Optional ML-based password similarity detection
- **Multiple Input Formats**: Support for both JSON and CSV Bitwarden exports
- **Multiple Scan Passes**: Configurable scanning passes (1-10) for thoroughness
- **Clean Export**: Generate duplicate-free exports in Bitwarden format

### User Interface
- **Simple GUI**: User-friendly interface with progress tracking
- **Command Line Support**: Full CLI for automation and scripting
- **Detailed Reporting**: Comprehensive text reports with masked passwords
- **CSV Export**: Structured data export for further analysis

---

## 📦 Installation

### Requirements
- **Python 3.7 or higher**
- **Optional**: scikit-learn for ML analysis (`pip install scikit-learn`)

### Download
```bash
git clone https://github.com/yourusername/bitwarden-duplicate-checker.git
cd bitwarden-duplicate-checker
```

---

## 💻 Usage

### GUI Application (Recommended)
```bash
python bitwarden_duplicate_checker_gui.py
```

### Command Line
```bash
# Basic usage
python bitwarden_duplicate_checker.py your_export.json

# With clean export
python bitwarden_duplicate_checker.py your_export.json --clean-export --clean-format json

# Multiple scan passes
python bitwarden_duplicate_checker.py your_export.json --passes 5
```

### Programmatic Usage
```python
from bitwarden_duplicate_checker import BitwardenDuplicateChecker

checker = BitwardenDuplicateChecker("export.json", scan_passes=3)
results = checker.run_analysis(
    output_format='txt',
    export_csv=True,
    create_clean_export=True,
    clean_export_format='json'
)
```

---

## 📖 Examples

### What It Detects

**Password Duplicates:**
```
Password: MyPass***123
├── Gmail (user@gmail.com) - gmail.com
├── Facebook (user@gmail.com) - facebook.com  
└── Twitter (user@gmail.com) - twitter.com
```

**URL Duplicates:**
```
URL: gmail.com
├── Gmail Personal (personal@gmail.com) - Password: Per***123
├── Gmail Work (work@gmail.com) - Password: Wor***456
└── Gmail Backup (backup@gmail.com) - Password: Bac***789
```

**Comprehensive Duplicates:**
```
Comprehensive: user@gmail.com + MyPass***123 + gmail.com
├── Gmail Account 1
└── Gmail Account 2 (duplicate)
```

### Command Line Options
```bash
usage: bitwarden_duplicate_checker.py [-h] [--passes PASSES] [--no-csv]
                                      [--clean-export]
                                      [--clean-format {json,csv}]
                                      [--output {txt,json}] [--verbose]
                                      json_file

positional arguments:
  json_file             Path to Bitwarden JSON or CSV export file

options:
  -h, --help            show this help message and exit
  --passes PASSES       Number of scanning passes (default: 3)
  --no-csv              Skip CSV export
  --clean-export        Create clean export with duplicates removed
  --clean-format {json,csv}
                        Format for clean export (default: json)
  --output {txt,json}   Output format for report (default: txt)
  --verbose, -v         Enable verbose logging
```

### Output Files
After running analysis, you'll get:
- `duplicate_analysis_report_YYYYMMDD_HHMMSS.txt` - Detailed analysis report
- `bitwarden_duplicates_YYYYMMDD_HHMMSS.csv` - CSV export of duplicates
- `bitwarden_clean_export_YYYYMMDD_HHMMSS.json` - Clean export (if enabled)

---

## 🛡️ Security

### Data Security
- **Local Processing Only**: All analysis happens on your device
- **No Network Access**: Tool doesn't connect to the internet
- **Password Masking**: Passwords are masked in all reports
- **Secure Hashing**: Passwords are hashed for comparison, not stored

### Privacy Protection
- **No Data Collection**: Tool doesn't collect or store any data
- **No Telemetry**: No usage statistics or analytics
- **Open Source**: Full source code available for audit
- **No Dependencies**: Minimal external dependencies

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### ⭐ **Star this repository if you find it useful!** ⭐

**Made with ❤️ for the security-conscious community**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/bitwarden-duplicate-checker?style=social)](https://github.com/yourusername/bitwarden-duplicate-checker)

</div>