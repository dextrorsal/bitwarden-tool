# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-06

### Added
- Initial release of Bitwarden Duplicate Checker
- Password duplicate detection across all login entries
- URL duplicate detection for identical URLs
- Domain duplicate detection for same-domain services
- Multiple scan passes for thoroughness (1-10 configurable)
- Simple GUI application with tkinter
- Progress tracking and loading animations
- Detailed text reports with masked passwords
- CSV export functionality
- Command-line interface
- Example Bitwarden export file for testing
- Comprehensive documentation and README
- MIT License

### Features
- **Password Analysis**: Detects exact password duplicates across different sites
- **URL Analysis**: Finds multiple accounts on the same URL
- **Domain Analysis**: Identifies multiple services on the same domain
- **Security**: All passwords masked in outputs for safety
- **Thoroughness**: Multiple scan passes ensure comprehensive analysis
- **User-Friendly**: Both GUI and command-line interfaces available
- **Export Options**: Text reports and CSV exports for further analysis

### Technical Details
- Built with Python standard library only (no external dependencies)
- Cross-platform compatibility (Windows, macOS, Linux)
- Thread-safe GUI operations
- Comprehensive error handling
- Detailed logging and progress tracking
- Memory-efficient processing for large export files
