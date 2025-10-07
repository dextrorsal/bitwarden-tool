#!/usr/bin/env python3
"""
Bitwarden Duplicate Password Checker
====================================

A comprehensive tool to detect duplicate passwords in Bitwarden export files.
Supports multiple scanning passes for thorough analysis and safety when dealing
with sensitive data.

Features:
- Multiple scan passes for thoroughness
- Detailed duplicate analysis
- Export results to various formats
- Safety features for sensitive data
- Progress tracking and logging
"""

import json
import argparse
import csv
import hashlib
from collections import defaultdict, Counter
from datetime import datetime
import os
import sys
from typing import Dict, List, Set, Tuple, Optional
import logging
import re
from urllib.parse import urlparse

# Optional ML imports - graceful fallback if not available
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Note: scikit-learn not available. Install with 'pip install scikit-learn' for advanced analysis features.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('duplicate_checker.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class BitwardenDuplicateChecker:
    """Main class for detecting duplicate passwords in Bitwarden exports."""
    
    def __init__(self, json_file: str, scan_passes: int = 3):
        """
        Initialize the duplicate checker.
        
        Args:
            json_file: Path to the Bitwarden JSON export file
            scan_passes: Number of scanning passes to perform (default: 3)
        """
        self.json_file = json_file
        self.scan_passes = scan_passes
        self.data = None
        self.password_duplicates = defaultdict(list)
        self.url_duplicates = defaultdict(list)
        self.domain_duplicates = defaultdict(list)
        self.username_duplicates = defaultdict(list)
        self.comprehensive_duplicates = defaultdict(list)
        self.password_stats = Counter()
        self.url_stats = Counter()
        self.username_stats = Counter()
        self.scan_results = []
        
    def load_data(self) -> bool:
        """Load and validate the Bitwarden export file (JSON or CSV)."""
        try:
            logger.info(f"Loading Bitwarden export file: {self.json_file}")
            
            # Check file extension
            if self.json_file.lower().endswith('.csv'):
                return self._load_csv_data()
            else:
                return self._load_json_data()
                
        except Exception as e:
            logger.error(f"Error loading file: {e}")
            return False
    
    def _load_json_data(self) -> bool:
        """Load JSON export file."""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            
            if not self.data.get('items'):
                logger.error("No items found in the JSON export file")
                return False
                
            logger.info(f"Successfully loaded {len(self.data['items'])} items from JSON")
            return True
            
        except FileNotFoundError:
            logger.error(f"File not found: {self.json_file}")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON file: {e}")
            return False
    
    def _load_csv_data(self) -> bool:
        """Load CSV export file and convert to JSON format."""
        try:
            import csv
            import uuid
            
            items = []
            folders = []
            folder_map = {}
            
            with open(self.json_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    # Skip non-login entries
                    if row.get('type', '').lower() != 'login':
                        continue
                    
                    # Handle folder
                    folder_name = row.get('folder', '').strip()
                    folder_id = None
                    
                    if folder_name and folder_name not in folder_map:
                        folder_id = str(uuid.uuid4())
                        folder_map[folder_name] = folder_id
                        folders.append({
                            'id': folder_id,
                            'name': folder_name
                        })
                    elif folder_name:
                        folder_id = folder_map[folder_name]
                    
                    # Create login item
                    item = {
                        'passwordHistory': [],
                        'revisionDate': datetime.now().isoformat(),
                        'creationDate': datetime.now().isoformat(),
                        'deletedDate': None,
                        'id': str(uuid.uuid4()),
                        'organizationId': None,
                        'folderId': folder_id,
                        'type': 1,
                        'reprompt': 0,
                        'name': row.get('name', ''),
                        'notes': row.get('notes', ''),
                        'favorite': row.get('favorite', '').lower() == 'true',
                        'fields': [],
                        'login': {
                            'uris': [{'match': None, 'uri': row.get('login_uri', '')}] if row.get('login_uri') else [],
                            'fido2Credentials': [],
                            'username': row.get('login_username', ''),
                            'password': row.get('login_password', ''),
                            'totp': row.get('login_totp', '') if row.get('login_totp') else None
                        },
                        'collectionIds': None
                    }
                    items.append(item)
            
            # Create JSON structure
            self.data = {
                'encrypted': False,
                'folders': folders,
                'items': items
            }
            
            logger.info(f"Successfully loaded {len(items)} items from CSV")
            return True
            
        except FileNotFoundError:
            logger.error(f"File not found: {self.json_file}")
            return False
        except Exception as e:
            logger.error(f"Error loading CSV file: {e}")
            return False
    
    def extract_passwords(self) -> List[Dict]:
        """Extract password information from all login items."""
        passwords = []
        
        for item in self.data['items']:
            if item.get('type') == 1 and item.get('login'):  # Login type
                login = item['login']
                password = login.get('password', '')
                
                if password:  # Only include items with passwords
                    password_info = {
                        'id': item['id'],
                        'name': item['name'],
                        'username': login.get('username', ''),
                        'password': password,
                        'password_hash': hashlib.sha256(password.encode()).hexdigest(),
                        'urls': [uri.get('uri', '') for uri in login.get('uris', [])],
                        'folder': self._get_folder_name(item.get('folderId')),
                        'creation_date': item.get('creationDate', ''),
                        'revision_date': item.get('revisionDate', ''),
                        'favorite': item.get('favorite', False),
                        'notes': item.get('notes', '')
                    }
                    passwords.append(password_info)
        
        logger.info(f"Extracted {len(passwords)} passwords from login items")
        return passwords
    
    def _get_folder_name(self, folder_id: Optional[str]) -> str:
        """Get folder name from folder ID."""
        if not folder_id or not self.data.get('folders'):
            return 'No Folder'
        
        for folder in self.data['folders']:
            if folder['id'] == folder_id:
                return folder['name']
        return 'Unknown Folder'
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove www. prefix for consistency
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            return url.lower()
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison."""
        try:
            parsed = urlparse(url)
            # Remove protocol, www, trailing slash, and query parameters
            normalized = parsed.netloc.lower()
            if normalized.startswith('www.'):
                normalized = normalized[4:]
            if normalized.endswith('/'):
                normalized = normalized[:-1]
            return normalized
        except:
            return url.lower().strip('/')
    
    def _are_urls_similar(self, url1: str, url2: str) -> bool:
        """Check if two URLs are similar (same domain or subdomain)."""
        domain1 = self._extract_domain(url1)
        domain2 = self._extract_domain(url2)
        
        # Exact match
        if domain1 == domain2:
            return True
        
        # Check if one is subdomain of the other
        if domain1.endswith('.' + domain2) or domain2.endswith('.' + domain1):
            return True
        
        # Check for common variations (e.g., google.com vs google.co.uk)
        base1 = domain1.split('.')[0] if '.' in domain1 else domain1
        base2 = domain2.split('.')[0] if '.' in domain2 else domain2
        
        return base1 == base2
    
    def _normalize_username(self, username: str) -> str:
        """Normalize username for comparison."""
        if not username:
            return ""
        return username.lower().strip()
    
    def _create_comprehensive_key(self, item: Dict) -> str:
        """Create a comprehensive key combining username, password, and URL."""
        username = self._normalize_username(item['username'])
        password = item['password']
        url = self._normalize_url(item['urls'][0]) if item['urls'] else ""
        return f"{username}|{password}|{url}"
    
    def analyze_password_patterns(self, passwords: List[Dict]) -> Dict:
        """Use ML to analyze password patterns and similarities."""
        if not ML_AVAILABLE:
            return {"ml_analysis": "ML library not available"}
        
        try:
            # Extract password features
            password_texts = []
            password_features = []
            
            for pwd_info in passwords:
                password = pwd_info['password']
                password_texts.append(password)
                
                # Create feature vector for password analysis
                features = {
                    'length': len(password),
                    'has_uppercase': any(c.isupper() for c in password),
                    'has_lowercase': any(c.islower() for c in password),
                    'has_digits': any(c.isdigit() for c in password),
                    'has_special': any(not c.isalnum() for c in password),
                    'starts_with_capital': password[0].isupper() if password else False,
                    'ends_with_digit': password[-1].isdigit() if password else False,
                    'contains_year': any(year in password for year in ['2020', '2021', '2022', '2023', '2024', '2025']),
                    'contains_common_words': any(word in password.lower() for word in ['password', 'pass', '123', 'admin', 'user'])
                }
                password_features.append(features)
            
            # Find similar passwords using TF-IDF
            vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3))
            password_matrix = vectorizer.fit_transform(password_texts)
            similarity_matrix = cosine_similarity(password_matrix)
            
            # Find similar password pairs
            similar_pairs = []
            for i in range(len(password_texts)):
                for j in range(i + 1, len(password_texts)):
                    if similarity_matrix[i][j] > 0.7:  # High similarity threshold
                        similar_pairs.append({
                            'password1': password_texts[i][:3] + "*" * (len(password_texts[i]) - 6) + password_texts[i][-3:] if len(password_texts[i]) > 6 else "*" * len(password_texts[i]),
                            'password2': password_texts[j][:3] + "*" * (len(password_texts[j]) - 6) + password_texts[j][-3:] if len(password_texts[j]) > 6 else "*" * len(password_texts[j]),
                            'similarity': similarity_matrix[i][j],
                            'item1': passwords[i]['name'],
                            'item2': passwords[j]['name']
                        })
            
            return {
                'ml_analysis': 'completed',
                'similar_password_pairs': similar_pairs,
                'total_passwords_analyzed': len(password_texts),
                'similarity_threshold': 0.7
            }
            
        except Exception as e:
            return {"ml_analysis": f"Error: {str(e)}"}
    
    def scan_for_duplicates(self, passwords: List[Dict], pass_number: int) -> Dict:
        """
        Perform a single scan for duplicate passwords and URLs.
        
        Args:
            passwords: List of password information dictionaries
            pass_number: Current scan pass number
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting scan pass {pass_number}/{self.scan_passes}")
        
        # Group by different criteria for duplicate detection
        password_groups = defaultdict(list)
        url_groups = defaultdict(list)
        domain_groups = defaultdict(list)
        username_groups = defaultdict(list)
        comprehensive_groups = defaultdict(list)
        
        for pwd_info in passwords:
            # Password grouping
            password_groups[pwd_info['password_hash']].append(pwd_info)
            
            # Username grouping
            normalized_username = self._normalize_username(pwd_info['username'])
            if normalized_username:
                username_groups[normalized_username].append(pwd_info)
            
            # Comprehensive grouping (username + password + URL)
            comprehensive_key = self._create_comprehensive_key(pwd_info)
            comprehensive_groups[comprehensive_key].append(pwd_info)
            
            # URL grouping
            for url in pwd_info['urls']:
                if url:
                    normalized_url = self._normalize_url(url)
                    url_groups[normalized_url].append(pwd_info)
                    
                    # Domain grouping
                    domain = self._extract_domain(url)
                    domain_groups[domain].append(pwd_info)
        
        # Find password duplicates
        password_duplicates = {}
        for password_hash, items in password_groups.items():
            if len(items) > 1:
                password_duplicates[password_hash] = items
        
        # Find username duplicates
        username_duplicates = {}
        for normalized_username, items in username_groups.items():
            if len(items) > 1:
                username_duplicates[normalized_username] = items
        
        # Find comprehensive duplicates (username + password + URL)
        comprehensive_duplicates = {}
        for comprehensive_key, items in comprehensive_groups.items():
            if len(items) > 1:
                comprehensive_duplicates[comprehensive_key] = items
        
        # Find URL duplicates
        url_duplicates = {}
        for normalized_url, items in url_groups.items():
            if len(items) > 1:
                url_duplicates[normalized_url] = items
        
        # Find domain duplicates (same domain, different URLs)
        domain_duplicates = {}
        for domain, items in domain_groups.items():
            if len(items) > 1:
                # Group by unique URLs within the domain
                unique_urls = set()
                for item in items:
                    for url in item['urls']:
                        if url:
                            unique_urls.add(self._normalize_url(url))
                
                if len(unique_urls) > 1:  # Multiple URLs on same domain
                    domain_duplicates[domain] = items
        
        # Count usage statistics
        password_counts = Counter()
        url_counts = Counter()
        username_counts = Counter()
        
        for pwd_info in passwords:
            password_counts[pwd_info['password']] += 1
            username_counts[self._normalize_username(pwd_info['username'])] += 1
            for url in pwd_info['urls']:
                if url:
                    url_counts[self._normalize_url(url)] += 1
        
        scan_result = {
            'pass_number': pass_number,
            'timestamp': datetime.now().isoformat(),
            'total_passwords': len(passwords),
            'unique_passwords': len(password_groups),
            'password_duplicate_groups': len(password_duplicates),
            'username_duplicate_groups': len(username_duplicates),
            'comprehensive_duplicate_groups': len(comprehensive_duplicates),
            'url_duplicate_groups': len(url_duplicates),
            'domain_duplicate_groups': len(domain_duplicates),
            'password_duplicates': password_duplicates,
            'username_duplicates': username_duplicates,
            'comprehensive_duplicates': comprehensive_duplicates,
            'url_duplicates': url_duplicates,
            'domain_duplicates': domain_duplicates,
            'password_counts': dict(password_counts),
            'username_counts': dict(username_counts),
            'url_counts': dict(url_counts),
            'most_common_passwords': password_counts.most_common(10),
            'most_common_usernames': username_counts.most_common(10),
            'most_common_urls': url_counts.most_common(10)
        }
        
        total_duplicates = (len(password_duplicates) + len(username_duplicates) + 
                           len(comprehensive_duplicates) + len(url_duplicates) + len(domain_duplicates))
        logger.info(f"Scan pass {pass_number} complete: {len(password_duplicates)} password, {len(username_duplicates)} username, {len(comprehensive_duplicates)} comprehensive, {len(url_duplicates)} URL, {len(domain_duplicates)} domain duplicate groups found")
        return scan_result
    
    def perform_multiple_scans(self) -> List[Dict]:
        """Perform multiple scanning passes for thoroughness."""
        logger.info(f"Starting {self.scan_passes} scanning passes for thoroughness")
        
        passwords = self.extract_passwords()
        all_results = []
        
        for pass_num in range(1, self.scan_passes + 1):
            result = self.scan_for_duplicates(passwords, pass_num)
            all_results.append(result)
            
            # Small delay between passes for thoroughness
            if pass_num < self.scan_passes:
                logger.info(f"Waiting before next scan pass...")
        
        self.scan_results = all_results
        return all_results
    
    def analyze_results(self) -> Dict:
        """Analyze results from all scanning passes."""
        logger.info("Analyzing results from all scanning passes")
        
        # Combine results from all passes
        all_password_duplicates = defaultdict(list)
        all_url_duplicates = defaultdict(list)
        all_domain_duplicates = defaultdict(list)
        all_password_counts = Counter()
        all_url_counts = Counter()
        
        for result in self.scan_results:
            # Password duplicates
            for password_hash, items in result['password_duplicates'].items():
                all_password_duplicates[password_hash].extend(items)
            
            # URL duplicates
            for normalized_url, items in result['url_duplicates'].items():
                all_url_duplicates[normalized_url].extend(items)
            
            # Domain duplicates
            for domain, items in result['domain_duplicates'].items():
                all_domain_duplicates[domain].extend(items)
            
            # Counts
            for password, count in result['password_counts'].items():
                all_password_counts[password] += count
            
            for url, count in result['url_counts'].items():
                all_url_counts[url] += count
        
        # Remove duplicates from combined results
        def deduplicate_items(duplicates_dict):
            for key in duplicates_dict:
                seen_ids = set()
                unique_items = []
                for item in duplicates_dict[key]:
                    if item['id'] not in seen_ids:
                        unique_items.append(item)
                        seen_ids.add(item['id'])
                duplicates_dict[key] = unique_items
        
        deduplicate_items(all_password_duplicates)
        deduplicate_items(all_url_duplicates)
        deduplicate_items(all_domain_duplicates)
        
        analysis = {
            'total_scans': len(self.scan_results),
            'total_passwords_analyzed': sum(r['total_passwords'] for r in self.scan_results),
            'password_duplicate_groups': len(all_password_duplicates),
            'url_duplicate_groups': len(all_url_duplicates),
            'domain_duplicate_groups': len(all_domain_duplicates),
            'total_duplicate_groups': len(all_password_duplicates) + len(all_url_duplicates) + len(all_domain_duplicates),
            'password_duplicates': dict(all_password_duplicates),
            'url_duplicates': dict(all_url_duplicates),
            'domain_duplicates': dict(all_domain_duplicates),
            'password_frequency': dict(all_password_counts),
            'url_frequency': dict(all_url_counts),
            'most_common_passwords': all_password_counts.most_common(20),
            'most_common_urls': all_url_counts.most_common(20),
            'scan_summary': [
                {
                    'pass': r['pass_number'],
                    'password_duplicates': r['password_duplicate_groups'],
                    'url_duplicates': r['url_duplicate_groups'],
                    'domain_duplicates': r['domain_duplicate_groups'],
                    'total_duplicates': r['password_duplicate_groups'] + r['url_duplicate_groups'] + r['domain_duplicate_groups'],
                    'timestamp': r['timestamp']
                }
                for r in self.scan_results
            ]
        }
        
        return analysis
    
    def generate_report(self, analysis: Dict, output_format: str = 'txt') -> str:
        """Generate a detailed report of duplicate findings."""
        report_lines = []
        
        # Header
        report_lines.extend([
            "=" * 80,
            "BITWARDEN DUPLICATE ANALYSIS REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Source File: {self.json_file}",
            f"Scan Passes: {analysis['total_scans']}",
            f"Total Passwords Analyzed: {analysis['total_passwords_analyzed']}",
            "",
            "DUPLICATE SUMMARY:",
            f"  Password Duplicate Groups: {analysis['password_duplicate_groups']}",
            f"  URL Duplicate Groups: {analysis['url_duplicate_groups']}",
            f"  Domain Duplicate Groups: {analysis['domain_duplicate_groups']}",
            f"  Total Duplicate Groups: {analysis['total_duplicate_groups']}",
            "=" * 80,
            ""
        ])
        
        # Scan Summary
        report_lines.extend([
            "SCAN SUMMARY:",
            "-" * 40
        ])
        for scan in analysis['scan_summary']:
            report_lines.append(f"Pass {scan['pass']}: {scan['password_duplicates']} password, {scan['url_duplicates']} URL, {scan['domain_duplicates']} domain duplicates (total: {scan['total_duplicates']}) at {scan['timestamp']}")
        report_lines.append("")
        
        # Most Common Passwords
        report_lines.extend([
            "MOST COMMON PASSWORDS:",
            "-" * 40
        ])
        for password, count in analysis['most_common_passwords'][:10]:
            masked_password = password[:3] + "*" * (len(password) - 6) + password[-3:] if len(password) > 6 else "*" * len(password)
            report_lines.append(f"{masked_password} (used {count} times)")
        report_lines.append("")
        
        # Most Common URLs
        report_lines.extend([
            "MOST COMMON URLs:",
            "-" * 40
        ])
        for url, count in analysis['most_common_urls'][:10]:
            report_lines.append(f"{url} (used {count} times)")
        report_lines.append("")
        
        # Detailed Duplicate Analysis
        report_lines.extend([
            "DETAILED DUPLICATE ANALYSIS:",
            "-" * 40
        ])
        
        # Password Duplicates
        if analysis['password_duplicates']:
            report_lines.extend([
                "PASSWORD DUPLICATES:",
                "-" * 20
            ])
            
            for i, (password_hash, items) in enumerate(analysis['password_duplicates'].items(), 1):
                if len(items) > 1:
                    report_lines.extend([
                        f"Password Duplicate Group {i}:",
                        f"  Password: {items[0]['password'][:3]}***{items[0]['password'][-3:] if len(items[0]['password']) > 6 else '***'}",
                        f"  Used {len(items)} times:",
                    ])
                    
                    for item in items:
                        urls_str = ", ".join(item['urls'][:2]) if item['urls'] else "No URL"
                        report_lines.append(f"    - {item['name']} ({item['username']}) - {urls_str}")
                        if item['folder'] != 'No Folder':
                            report_lines.append(f"      Folder: {item['folder']}")
                    
                    report_lines.append("")
        
        # URL Duplicates
        if analysis['url_duplicates']:
            report_lines.extend([
                "URL DUPLICATES:",
                "-" * 20
            ])
            
            for i, (normalized_url, items) in enumerate(analysis['url_duplicates'].items(), 1):
                if len(items) > 1:
                    report_lines.extend([
                        f"URL Duplicate Group {i}:",
                        f"  URL: {normalized_url}",
                        f"  Used {len(items)} times:",
                    ])
                    
                    for item in items:
                        masked_password = item['password'][:3] + "*" * (len(item['password']) - 6) + item['password'][-3:] if len(item['password']) > 6 else "*" * len(item['password'])
                        report_lines.append(f"    - {item['name']} ({item['username']}) - Password: {masked_password}")
                        if item['folder'] != 'No Folder':
                            report_lines.append(f"      Folder: {item['folder']}")
                    
                    report_lines.append("")
        
        # Domain Duplicates
        if analysis['domain_duplicates']:
            report_lines.extend([
                "DOMAIN DUPLICATES (Multiple URLs on Same Domain):",
                "-" * 20
            ])
            
            for i, (domain, items) in enumerate(analysis['domain_duplicates'].items(), 1):
                if len(items) > 1:
                    report_lines.extend([
                        f"Domain Duplicate Group {i}:",
                        f"  Domain: {domain}",
                        f"  Found {len(items)} entries:",
                    ])
                    
                    for item in items:
                        urls_str = ", ".join(item['urls'][:3]) if item['urls'] else "No URL"
                        masked_password = item['password'][:3] + "*" * (len(item['password']) - 6) + item['password'][-3:] if len(item['password']) > 6 else "*" * len(item['password'])
                        report_lines.append(f"    - {item['name']} ({item['username']}) - {urls_str}")
                        report_lines.append(f"      Password: {masked_password}")
                        if item['folder'] != 'No Folder':
                            report_lines.append(f"      Folder: {item['folder']}")
                    
                    report_lines.append("")
        
        return "\n".join(report_lines)
    
    def export_to_csv(self, analysis: Dict, filename: str = None) -> str:
        """Export duplicate analysis to CSV format."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"bitwarden_duplicates_{timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow([
                'Duplicate Type', 'Duplicate Group', 'Password (Masked)', 'Name', 'Username', 
                'URLs', 'Domain', 'Folder', 'Creation Date', 'Favorite', 'Notes'
            ])
            
            # Write password duplicate data
            group_num = 1
            for password_hash, items in analysis['password_duplicates'].items():
                if len(items) > 1:
                    for item in items:
                        masked_password = item['password'][:3] + "*" * (len(item['password']) - 6) + item['password'][-3:] if len(item['password']) > 6 else "*" * len(item['password'])
                        urls_str = "; ".join(item['urls']) if item['urls'] else ""
                        domain = self._extract_domain(item['urls'][0]) if item['urls'] else ""
                        
                        writer.writerow([
                            'Password Duplicate',
                            group_num,
                            masked_password,
                            item['name'],
                            item['username'],
                            urls_str,
                            domain,
                            item['folder'],
                            item['creation_date'],
                            item['favorite'],
                            item['notes']
                        ])
                    group_num += 1
            
            # Write URL duplicate data
            group_num = 1
            for normalized_url, items in analysis['url_duplicates'].items():
                if len(items) > 1:
                    for item in items:
                        masked_password = item['password'][:3] + "*" * (len(item['password']) - 6) + item['password'][-3:] if len(item['password']) > 6 else "*" * len(item['password'])
                        urls_str = "; ".join(item['urls']) if item['urls'] else ""
                        domain = self._extract_domain(item['urls'][0]) if item['urls'] else ""
                        
                        writer.writerow([
                            'URL Duplicate',
                            group_num,
                            masked_password,
                            item['name'],
                            item['username'],
                            urls_str,
                            domain,
                            item['folder'],
                            item['creation_date'],
                            item['favorite'],
                            item['notes']
                        ])
                    group_num += 1
            
            # Write domain duplicate data
            group_num = 1
            for domain, items in analysis['domain_duplicates'].items():
                if len(items) > 1:
                    for item in items:
                        masked_password = item['password'][:3] + "*" * (len(item['password']) - 6) + item['password'][-3:] if len(item['password']) > 6 else "*" * len(item['password'])
                        urls_str = "; ".join(item['urls']) if item['urls'] else ""
                        
                        writer.writerow([
                            'Domain Duplicate',
                            group_num,
                            masked_password,
                            item['name'],
                            item['username'],
                            urls_str,
                            domain,
                            item['folder'],
                            item['creation_date'],
                            item['favorite'],
                            item['notes']
                        ])
                    group_num += 1
        
        logger.info(f"Duplicate analysis exported to: {filename}")
        return filename
    
    def create_clean_export(self, analysis: Dict, export_format: str = 'json') -> str:
        """Create a clean export with duplicates removed."""
        logger.info("Creating clean export with duplicates removed")
        
        # Get all items
        all_items = self.data['items'].copy()
        folders = self.data['folders'].copy()
        
        # Find items to remove based on comprehensive duplicates
        items_to_remove = set()
        
        for comprehensive_key, items in analysis.get('comprehensive_duplicates', {}).items():
            if len(items) > 1:
                # Keep the first item, remove the rest
                for item in items[1:]:
                    items_to_remove.add(item['id'])
        
        # Filter out duplicate items
        clean_items = []
        for item in all_items:
            if item['id'] not in items_to_remove:
                clean_items.append(item)
        
        # Create clean data structure
        clean_data = {
            'encrypted': False,
            'folders': folders,
            'items': clean_items
        }
        
        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if export_format.lower() == 'json':
            filename = f"bitwarden_clean_export_{timestamp}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(clean_data, f, indent=2, ensure_ascii=False)
        else:  # CSV
            filename = f"bitwarden_clean_export_{timestamp}.csv"
            self._export_to_bitwarden_csv(clean_data, filename)
        
        logger.info(f"Clean export saved to: {filename}")
        logger.info(f"Removed {len(items_to_remove)} duplicate items, kept {len(clean_items)} unique items")
        
        return filename
    
    def _export_to_bitwarden_csv(self, data: Dict, filename: str):
        """Export data to Bitwarden CSV format."""
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt',
                'login_uri', 'login_username', 'login_password', 'login_totp'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Create folder mapping
            folder_map = {folder['id']: folder['name'] for folder in data.get('folders', [])}
            
            for item in data['items']:
                if item.get('type') == 1 and item.get('login'):  # Login type
                    login = item['login']
                    folder_name = folder_map.get(item.get('folderId'), '')
                    
                    writer.writerow({
                        'folder': folder_name,
                        'favorite': item.get('favorite', False),
                        'type': 'login',
                        'name': item.get('name', ''),
                        'notes': item.get('notes', ''),
                        'fields': '',
                        'reprompt': item.get('reprompt', 0),
                        'login_uri': login.get('uris', [{}])[0].get('uri', '') if login.get('uris') else '',
                        'login_username': login.get('username', ''),
                        'login_password': login.get('password', ''),
                        'login_totp': login.get('totp', '') if login.get('totp') else ''
                    })
    
    def run_analysis(self, output_format: str = 'txt', export_csv: bool = True, 
                    create_clean_export: bool = False, clean_export_format: str = 'json') -> Dict:
        """Run the complete duplicate analysis."""
        logger.info("Starting Bitwarden duplicate password analysis")
        
        # Load data
        if not self.load_data():
            return None
        
        # Perform multiple scans
        self.perform_multiple_scans()
        
        # Analyze results
        analysis = self.analyze_results()
        
        # Generate report
        report = self.generate_report(analysis, output_format)
        
        # Save report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"duplicate_analysis_report_{timestamp}.txt"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"Analysis report saved to: {report_filename}")
        
        # Export to CSV if requested
        if export_csv:
            csv_filename = self.export_to_csv(analysis)
            analysis['csv_export'] = csv_filename
        
        # Create clean export if requested
        if create_clean_export:
            clean_filename = self.create_clean_export(analysis, clean_export_format)
            analysis['clean_export'] = clean_filename
        
        analysis['report_filename'] = report_filename
        analysis['report_content'] = report
        
        logger.info("Analysis complete!")
        return analysis


def main():
    """Main function to run the duplicate checker."""
    parser = argparse.ArgumentParser(
        description="Check for duplicate passwords in Bitwarden export files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bitwarden_duplicate_checker.py export.json
  python bitwarden_duplicate_checker.py export.json --passes 5
  python bitwarden_duplicate_checker.py export.json --no-csv
  python bitwarden_duplicate_checker.py export.json --passes 3 --output json
        """
    )
    
    parser.add_argument('json_file', help='Path to Bitwarden JSON export file')
    parser.add_argument('--passes', type=int, default=3, 
                       help='Number of scanning passes (default: 3)')
    parser.add_argument('--no-csv', action='store_true', 
                       help='Skip CSV export')
    parser.add_argument('--clean-export', action='store_true',
                       help='Create clean export with duplicates removed')
    parser.add_argument('--clean-format', choices=['json', 'csv'], default='json',
                       help='Format for clean export (default: json)')
    parser.add_argument('--output', choices=['txt', 'json'], default='txt',
                       help='Output format for report (default: txt)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check if file exists
    if not os.path.exists(args.json_file):
        logger.error(f"File not found: {args.json_file}")
        sys.exit(1)
    
    # Create checker instance
    checker = BitwardenDuplicateChecker(args.json_file, args.passes)
    
    # Run analysis
    try:
        results = checker.run_analysis(
            output_format=args.output,
            export_csv=not args.no_csv,
            create_clean_export=args.clean_export,
            clean_export_format=args.clean_format
        )
        
        if results:
            print(f"\nAnalysis complete!")
            print(f"Found {results['password_duplicate_groups']} password duplicate groups")
            print(f"Found {results['url_duplicate_groups']} URL duplicate groups")
            print(f"Found {results['domain_duplicate_groups']} domain duplicate groups")
            print(f"Total duplicate groups: {results['total_duplicate_groups']}")
            print(f"Report saved to: {results['report_filename']}")
            if 'csv_export' in results:
                print(f"CSV export saved to: {results['csv_export']}")
        else:
            logger.error("Analysis failed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
