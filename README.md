# 🔐 Bitwarden Duplicate Checker

<div align="center">

![Python](https://img.shields.io/badge/python-3.7+-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=white)
![GUI](https://img.shields.io/badge/GUI-tkinter-orange.svg?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Local%20Only-red.svg?style=for-the-badge&logo=security&logoColor=white)
![Privacy](https://img.shields.io/badge/Privacy-No%20Data%20Sent-blue.svg?style=for-the-badge&logo=privacy&logoColor=white)

**A comprehensive Python tool to detect duplicate passwords, URLs, and usernames in Bitwarden export files with multiple scanning passes for thoroughness and safety.**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/bitwarden-duplicate-checker?style=social)](https://github.com/yourusername/bitwarden-duplicate-checker)
[![GitHub forks](https://img.shields.io/github/forks/yourusername/bitwarden-duplicate-checker?style=social)](https://github.com/yourusername/bitwarden-duplicate-checker)

</div>

---

## 🛡️ **Privacy & Security First**

<div align="center">

### 🔒 **100% Local Processing**
- **No data sent to external servers**
- **No internet connection required**
- **Your passwords never leave your device**
- **Open source and auditable**

</div>

This tool runs entirely on your local machine. Your sensitive password data is never transmitted anywhere - it stays completely private and secure on your device.

---

## 🎯 **Features**

### 🔍 **Comprehensive Duplicate Detection**
- **Password Duplicates**: Find identical passwords across different sites
- **Username Duplicates**: Detect reused usernames across accounts  
- **URL Duplicates**: Detect multiple accounts on the same URL
- **Domain Duplicates**: Identify multiple services on the same domain
- **Comprehensive Duplicates**: Same username + password + URL combinations

### 🤖 **Advanced Analysis**
- **Machine Learning Analysis**: Optional ML-based password similarity detection using scikit-learn
- **Multiple Input Formats**: Support for both JSON and CSV Bitwarden exports
- **Multiple Scan Passes**: Configurable scanning passes (1-10) for thoroughness

### 🧹 **Clean Export & Organization**
- **Clean Export**: Generate duplicate-free exports in Bitwarden format
- **Bitwarden Format**: Exports in the same format as Bitwarden (JSON or CSV)
- **Folder Preservation**: Maintains folder structure from original export
- **Safe Operation**: Keeps the first occurrence of each duplicate group

### 🖥️ **User-Friendly Interface**
- **Simple GUI**: User-friendly interface with progress tracking
- **Command Line Support**: Full CLI for automation and scripting
- **Detailed Reporting**: Comprehensive text reports with masked passwords
- **CSV Export**: Structured data export for further analysis
- **Progress Tracking**: Real-time progress updates and logging

---

## 🚀 **Quick Start**

### 🖥️ **GUI Application (Recommended)**

1. **Download the files**:
   ```bash
   git clone https://github.com/yourusername/bitwarden-duplicate-checker.git
   cd bitwarden-duplicate-checker
   ```

2. **Run the GUI**:
   ```bash
   python bitwarden_duplicate_checker_gui.py
   ```

3. **Select your Bitwarden export file** (JSON or CSV) and configure scan options

4. **Choose export options**:
   - Export Analysis to CSV
   - Create Clean Export (removes duplicates)
   - Select format (JSON or CSV)

5. **Click "Start Analysis"** and watch the progress!

### 💻 **Command Line Usage**

```bash
# Basic usage
python bitwarden_duplicate_checker.py your_export.json

# With CSV input
python bitwarden_duplicate_checker.py your_export.csv

# Advanced usage with clean export
python bitwarden_duplicate_checker.py your_export.json --passes 5 --clean-export --clean-format json

# With ML analysis (requires scikit-learn)
python bitwarden_duplicate_checker.py your_export.json --passes 3 --clean-export
```

---

## 📋 **Requirements**

- **Python 3.7 or higher**
- **Optional**: scikit-learn for ML analysis (`pip install scikit-learn`)
- **No additional dependencies required** for basic functionality

---

## 📁 **Project Structure**

```
bitwarden-duplicate-checker/
├── 📄 bitwarden_duplicate_checker.py      # Core analysis engine
├── 🖥️ bitwarden_duplicate_checker_gui.py  # GUI application
├── 📊 example_bitwarden_export.json       # Sample JSON data for testing
├── 📊 example_bitwarden_export.csv        # Sample CSV data for testing
├── 🔧 example_usage.py                     # Example script showing programmatic usage
├── 🚀 run.py                              # Simple launcher script
├── 📖 README.md                           # This file
├── 📄 LICENSE                             # MIT License
├── 📄 setup.py                            # Python setup script
├── 📄 .gitignore                          # Git ignore rules
└── 📄 CHANGELOG.md                        # Version history
```

---

## 🧹 **Clean Export Feature**

The tool can generate a clean export with duplicates removed:

- **Comprehensive Duplicate Removal**: Removes entries where username + password + URL are identical
- **Bitwarden Format**: Exports in the same format as Bitwarden (JSON or CSV)
- **Folder Preservation**: Maintains folder structure from original export
- **Safe Operation**: Keeps the first occurrence of each duplicate group

### 📄 **Example Output Files**

After running analysis, you'll get:
- `duplicate_analysis_report_YYYYMMDD_HHMMSS.txt` - Detailed analysis report
- `bitwarden_duplicates_YYYYMMDD_HHMMSS.csv` - CSV export of duplicates
- `bitwarden_clean_export_YYYYMMDD_HHMMSS.json` - Clean export (if enabled)
- `bitwarden_clean_export_YYYYMMDD_HHMMSS.csv` - Clean export in CSV format (if enabled)

---

## 🔍 **What It Detects**

### 🔑 **Password Duplicates**
Same password used across different sites:
```
Password: MyPass***123
├── Gmail (user@gmail.com) - gmail.com
├── Facebook (user@gmail.com) - facebook.com  
└── Twitter (user@gmail.com) - twitter.com
```

### 🌐 **URL Duplicates**
Multiple accounts on the same URL:
```
URL: gmail.com
├── Gmail Personal (personal@gmail.com) - Password: Per***123
├── Gmail Work (work@gmail.com) - Password: Wor***456
└── Gmail Backup (backup@gmail.com) - Password: Bac***789
```

### 🏢 **Domain Duplicates**
Multiple services on the same domain:
```
Domain: google.com
├── Gmail (user@gmail.com) - Password: Gma***123
├── Google Drive (user@gmail.com) - Password: Dri***456
└── YouTube (user@gmail.com) - Password: You***789
```

### 👤 **Username Duplicates**
Same username across different services:
```
Username: user@gmail.com
├── Gmail - Password: Gma***123
├── Facebook - Password: Fac***456
└── Twitter - Password: Twi***789
```

### 🎯 **Comprehensive Duplicates**
Identical username + password + URL combinations:
```
Comprehensive: user@gmail.com + MyPass***123 + gmail.com
├── Gmail Account 1
└── Gmail Account 2 (duplicate)
```

---

## 🛠️ **Installation**

### **Option 1: Direct Download**
```bash
git clone https://github.com/yourusername/bitwarden-duplicate-checker.git
cd bitwarden-duplicate-checker
```

### **Option 2: Using pip (if published)**
```bash
pip install bitwarden-duplicate-checker
```

### **Optional: Install ML Dependencies**
```bash
pip install scikit-learn
```

---

## 📖 **Usage Examples**

### **GUI Usage**
1. Run `python bitwarden_duplicate_checker_gui.py`
2. Select your Bitwarden export file
3. Configure scan options
4. Click "Start Analysis"
5. Review results and download clean export

### **Command Line Examples**
```bash
# Basic analysis
python bitwarden_duplicate_checker.py export.json

# Multiple scan passes for thoroughness
python bitwarden_duplicate_checker.py export.json --passes 5

# Create clean export
python bitwarden_duplicate_checker.py export.json --clean-export --clean-format json

# Skip CSV export
python bitwarden_duplicate_checker.py export.json --no-csv

# Verbose logging
python bitwarden_duplicate_checker.py export.json --verbose
```

### **Programmatic Usage**
```python
from bitwarden_duplicate_checker import BitwardenDuplicateChecker

# Initialize checker
checker = BitwardenDuplicateChecker("export.json", scan_passes=3)

# Run analysis
results = checker.run_analysis(
    output_format='txt',
    export_csv=True,
    create_clean_export=True,
    clean_export_format='json'
)

print(f"Found {results['total_duplicate_groups']} duplicate groups")
```

---

## 🔧 **Command Line Options**

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

---

## 🛡️ **Security & Privacy**

### **🔒 Data Security**
- **Local Processing Only**: All analysis happens on your device
- **No Network Access**: Tool doesn't connect to the internet
- **Password Masking**: Passwords are masked in all reports
- **Secure Hashing**: Passwords are hashed for comparison, not stored

### **🔐 Privacy Protection**
- **No Data Collection**: Tool doesn't collect or store any data
- **No Telemetry**: No usage statistics or analytics
- **Open Source**: Full source code available for audit
- **No Dependencies**: Minimal external dependencies

### **✅ Safe to Use**
- **Audited Code**: Open source and reviewable
- **Local Execution**: Runs entirely on your machine
- **No External Services**: No third-party services involved
- **MIT License**: Free to use and modify

---

## 🤝 **Contributing**

We welcome contributions! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **Bitwarden** for creating an amazing password manager
- **Python Community** for excellent libraries and tools
- **Open Source Community** for inspiration and support

---

## 📞 **Support**

If you encounter any issues or have questions:

1. **Check the Issues**: Look through existing issues on GitHub
2. **Create an Issue**: Open a new issue with detailed information
3. **Community Help**: Ask questions in discussions

---

<div align="center">

### ⭐ **Star this repository if you find it useful!** ⭐

**Made with ❤️ for the security-conscious community**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/bitwarden-duplicate-checker?style=social)](https://github.com/yourusername/bitwarden-duplicate-checker)
[![GitHub forks](https://img.shields.io/github/forks/yourusername/bitwarden-duplicate-checker?style=social)](https://github.com/yourusername/bitwarden-duplicate-checker)

</div>