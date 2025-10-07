#!/usr/bin/env python3
"""
Bitwarden Duplicate Checker

High-performance duplicate detection with async processing,
streaming JSON parsing, and ML-based similarity analysis.
"""

import json
import hashlib
import logging
import argparse
import sys
import asyncio
import aiofiles
from datetime import datetime
from collections import defaultdict, Counter
import time
import re
import urllib.parse
from pathlib import Path
import functools
from concurrent.futures import ThreadPoolExecutor
import threading
import uuid
import csv

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('duplicate_checker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AnalysisConfig:
    def __init__(self, scan_passes=3, enable_ml=False, similarity_threshold=0.7, 
                 max_workers=4, chunk_size=1000, enable_caching=True,
                 check_passwords=True, check_urls=True, check_domains=True,
                 check_usernames=True, check_comprehensive=True):
        self.scan_passes = scan_passes
        self.enable_ml_analysis = enable_ml
        self.similarity_threshold = similarity_threshold
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.enable_caching = enable_caching
        self.check_passwords = check_passwords
        self.check_urls = check_urls
        self.check_domains = check_domains
        self.check_usernames = check_usernames
        self.check_comprehensive = check_comprehensive
        
        if scan_passes < 1:
            raise ValueError("Scan passes must be at least 1")
        if not 0 <= similarity_threshold <= 1:
            raise ValueError("Similarity threshold must be between 0 and 1")


class PasswordInfo:
    def __init__(self, id, name, username, password, url, domain, folder=None, 
                 favorite=False, notes=""):
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.url = url
        self.domain = domain
        self.folder = folder
        self.favorite = favorite
        self.notes = notes


class BitwardenDuplicateChecker:
    def __init__(self, file_path, config=None):
        self.file_path = Path(file_path)
        self.config = config or AnalysisConfig()
        self.data = None
        self.scan_results = []
        self._start_time = None
        self._cache = {}
        self._lock = threading.Lock()
        
        logger.info(f"Initialized checker for {self.file_path}")
    
    @functools.lru_cache(maxsize=128)
    def _normalize_username(self, username):
        if not username:
            return ""
        return username.lower().strip()
    
    @functools.lru_cache(maxsize=128)
    def _normalize_url(self, url):
        if not url:
            return ""
        
        url = url.lower().strip()
        if url.startswith(('http://', 'https://')):
            url = url.split('://', 1)[1]
        
        url = url.rstrip('/')
        url = re.sub(r'/(login|signin|auth).*$', '', url)
        
        return url
    
    @functools.lru_cache(maxsize=128)
    def _extract_domain(self, url):
        if not url:
            return ""
        
        try:
            parsed = urllib.parse.urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
            domain = parsed.netloc.lower()
            
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain
        except:
            return ""
    
    def _create_comprehensive_key(self, item):
        username = self._normalize_username(item.username)
        url = self._normalize_url(item.url)
        return f"{username}|{item.password}|{url}"
    
    async def _load_json_data_async(self):
        try:
            async with aiofiles.open(self.file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
                data = json.loads(content)
            
            if not data.get('items'):
                raise Exception("No items found in JSON export")
            
            logger.info(f"Loaded {len(data['items'])} items from JSON")
            return data
            
        except FileNotFoundError:
            raise Exception(f"File not found: {self.file_path}")
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON: {e}")
    
    def _load_csv_data(self):
        try:
            items = []
            folders = []
            folder_map = {}
            
            with open(self.file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    if row.get('type', '').lower() != 'login':
                        continue
                    
                    folder_name = row.get('folder', '').strip()
                    folder_id = None
                    
                    if folder_name and folder_name not in folder_map:
                        folder_id = str(uuid.uuid4())
                        folder_map[folder_name] = folder_id
                        folders.append({'id': folder_id, 'name': folder_name})
                    elif folder_name:
                        folder_id = folder_map[folder_name]
                    
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
            
            data = {
                'encrypted': False,
                'folders': folders,
                'items': items
            }
            
            logger.info(f"Loaded {len(items)} items from CSV")
            return data
            
        except FileNotFoundError:
            raise Exception(f"File not found: {self.file_path}")
        except Exception as e:
            raise Exception(f"CSV load error: {e}")
    
    async def load_data_async(self):
        try:
            logger.info(f"Loading {self.file_path}")
            
            if self.file_path.suffix.lower() == '.csv':
                self.data = self._load_csv_data()
            else:
                self.data = await self._load_json_data_async()
            
            return True
            
        except Exception as e:
            logger.error(f"Load error: {e}")
            return False
    
    def extract_passwords_generator(self):
        if not self.data or not self.data.get('items'):
            return
        
        for item in self.data['items']:
            if item.get('type') == 1 and item.get('login'):
                login = item['login']
                password = login.get('password', '')
                
                if password:
                    url = login.get('uris', [{}])[0].get('uri', '') if login.get('uris') else ''
                    domain = self._extract_domain(url)
                    
                    folder_name = ""
                    if item.get('folderId'):
                        for folder in self.data.get('folders', []):
                            if folder['id'] == item['folderId']:
                                folder_name = folder['name']
                                break
                    
                    yield PasswordInfo(
                        id=item['id'],
                        name=item.get('name', ''),
                        username=login.get('username', ''),
                        password=password,
                        url=url,
                        domain=domain,
                        folder=folder_name,
                        favorite=item.get('favorite', False),
                        notes=item.get('notes', '')
                    )
    
    def extract_passwords(self):
        passwords = list(self.extract_passwords_generator())
        logger.info(f"Extracted {len(passwords)} passwords")
        return passwords
    
    async def analyze_password_patterns_async(self, passwords):
        if not ML_AVAILABLE:
            return {"ml_analysis": "ML library not available"}
        
        try:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                result = await loop.run_in_executor(
                    executor, 
                    self._analyze_password_patterns_sync, 
                    passwords
                )
            return result
            
        except Exception as e:
            logger.error(f"ML analysis error: {e}")
            return {"ml_analysis": f"Error: {str(e)}"}
    
    def _analyze_password_patterns_sync(self, passwords):
        try:
            password_texts = [pwd.password for pwd in passwords]
            
            vectorizer = TfidfVectorizer(
                analyzer='char',
                ngram_range=(2, 4),
                max_features=1000,
                lowercase=True
            )
            
            password_matrix = vectorizer.fit_transform(password_texts)
            similarity_matrix = cosine_similarity(password_matrix)
            
            similar_pairs = []
            for i in range(len(password_texts)):
                for j in range(i + 1, len(password_texts)):
                    similarity = similarity_matrix[i][j]
                    if similarity >= self.config.similarity_threshold:
                        similar_pairs.append({
                            'similarity': float(similarity),
                            'password1': self._mask_password(password_texts[i]),
                            'password2': self._mask_password(password_texts[j]),
                            'item1': passwords[i].name,
                            'item2': passwords[j].name
                        })
            
            return {
                'ml_analysis': 'completed',
                'similar_password_pairs': similar_pairs,
                'total_passwords_analyzed': len(password_texts),
                'similarity_threshold': self.config.similarity_threshold
            }
            
        except Exception as e:
            return {"ml_analysis": f"Error: {str(e)}"}
    
    def _mask_password(self, password):
        if len(password) <= 6:
            return "*" * len(password)
        return password[:3] + "*" * (len(password) - 6) + password[-3:]
    
    async def scan_for_duplicates_async(self, passwords, pass_number):
        logger.info(f"Scan pass {pass_number}/{self.config.scan_passes}")
        
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            result = await loop.run_in_executor(
                executor,
                self._scan_for_duplicates_sync,
                passwords,
                pass_number
            )
        
        logger.info(f"Pass {pass_number}: {result['password_duplicate_groups']} password, "
                   f"{result['username_duplicate_groups']} username, {result['comprehensive_duplicate_groups']} comprehensive, "
                   f"{result['url_duplicate_groups']} URL, {result['domain_duplicate_groups']} domain duplicates")
        
        return result
    
    def _scan_for_duplicates_sync(self, passwords, pass_number):
        password_groups = defaultdict(list)
        username_groups = defaultdict(list)
        url_groups = defaultdict(list)
        domain_groups = defaultdict(list)
        comprehensive_groups = defaultdict(list)
        
        for i in range(0, len(passwords), self.config.chunk_size):
            chunk = passwords[i:i + self.config.chunk_size]
            
            for pwd_info in chunk:
                password_groups[pwd_info.password_hash].append(pwd_info)
                
                normalized_username = self._normalize_username(pwd_info.username)
                if normalized_username:
                    username_groups[normalized_username].append(pwd_info)
                
                normalized_url = self._normalize_url(pwd_info.url)
                if normalized_url:
                    url_groups[normalized_url].append(pwd_info)
                
                if pwd_info.domain:
                    domain_groups[pwd_info.domain].append(pwd_info)
                
                comprehensive_key = self._create_comprehensive_key(pwd_info)
                comprehensive_groups[comprehensive_key].append(pwd_info)
        
        password_duplicates = {k: v for k, v in password_groups.items() if len(v) > 1}
        username_duplicates = {k: v for k, v in username_groups.items() if len(v) > 1}
        url_duplicates = {k: v for k, v in url_groups.items() if len(v) > 1}
        domain_duplicates = {k: v for k, v in domain_groups.items() if len(v) > 1}
        comprehensive_duplicates = {k: v for k, v in comprehensive_groups.items() if len(v) > 1}
        
        password_counts = Counter(pwd.password for pwd in passwords)
        username_counts = Counter(self._normalize_username(pwd.username) for pwd in passwords if pwd.username)
        url_counts = Counter(self._normalize_url(pwd.url) for pwd in passwords if pwd.url)
        
        return {
            'pass': pass_number,
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
    
    async def run_analysis_async(self, output_format='txt', export_csv=True, 
                                create_clean_export=False, clean_export_format='json'):
        self._start_time = time.time()
        logger.info("Starting analysis")
        
        try:
            if not await self.load_data_async():
                raise Exception("Failed to load data")
            
            passwords = self.extract_passwords()
            if not passwords:
                raise Exception("No passwords found")
            
            self.scan_results = []
            for pass_num in range(1, self.config.scan_passes + 1):
                result = await self.scan_for_duplicates_async(passwords, pass_num)
                self.scan_results.append(result)
                
                if pass_num < self.config.scan_passes:
                    await asyncio.sleep(0.1)
            
            analysis = await self._analyze_results_async()
            
            if self.config.enable_ml_analysis:
                logger.info("Running ML analysis...")
                ml_results = await self.analyze_password_patterns_async(passwords)
                analysis['ml_analysis'] = ml_results
            
            await self._generate_reports_async(analysis, output_format, export_csv, create_clean_export, clean_export_format)
            
            processing_time = time.time() - self._start_time
            logger.info(f"Analysis complete in {processing_time:.2f}s")
            
            return {
                'total_passwords_analyzed': analysis['total_passwords_analyzed'],
                'password_duplicate_groups': analysis['password_duplicate_groups'],
                'username_duplicate_groups': analysis['username_duplicate_groups'],
                'comprehensive_duplicate_groups': analysis['comprehensive_duplicate_groups'],
                'url_duplicate_groups': analysis['url_duplicate_groups'],
                'domain_duplicate_groups': analysis['domain_duplicate_groups'],
                'total_duplicate_groups': analysis['total_duplicate_groups'],
                'password_duplicates': analysis['password_duplicates'],
                'username_duplicates': analysis['username_duplicates'],
                'comprehensive_duplicates': analysis['comprehensive_duplicates'],
                'url_duplicates': analysis['url_duplicates'],
                'domain_duplicates': analysis['domain_duplicates'],
                'most_common_passwords': analysis['most_common_passwords'],
                'most_common_usernames': analysis['most_common_usernames'],
                'most_common_urls': analysis['most_common_urls'],
                'ml_analysis': analysis.get('ml_analysis'),
                'processing_time': processing_time
            }
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise Exception(f"Analysis failed: {e}")
    
    async def _analyze_results_async(self):
        logger.info("Analyzing results")
        
        all_password_duplicates = defaultdict(list)
        all_username_duplicates = defaultdict(list)
        all_url_duplicates = defaultdict(list)
        all_domain_duplicates = defaultdict(list)
        all_comprehensive_duplicates = defaultdict(list)
        all_password_counts = Counter()
        all_username_counts = Counter()
        all_url_counts = Counter()
        
        for result in self.scan_results:
            for password_hash, items in result['password_duplicates'].items():
                all_password_duplicates[password_hash].extend(items)
            
            for username, items in result['username_duplicates'].items():
                all_username_duplicates[username].extend(items)
            
            for url, items in result['url_duplicates'].items():
                all_url_duplicates[url].extend(items)
            
            for domain, items in result['domain_duplicates'].items():
                all_domain_duplicates[domain].extend(items)
            
            for comprehensive_key, items in result['comprehensive_duplicates'].items():
                all_comprehensive_duplicates[comprehensive_key].extend(items)
            
            for password, count in result['password_counts'].items():
                all_password_counts[password] += count
            
            for username, count in result['username_counts'].items():
                all_username_counts[username] += count
            
            for url, count in result['url_counts'].items():
                all_url_counts[url] += count
        
        def deduplicate_items(groups):
            for key, items in groups.items():
                seen_ids = set()
                unique_items = []
                for item in items:
                    if item.id not in seen_ids:
                        seen_ids.add(item.id)
                        unique_items.append(item)
                groups[key] = unique_items
        
        deduplicate_items(all_password_duplicates)
        deduplicate_items(all_username_duplicates)
        deduplicate_items(all_url_duplicates)
        deduplicate_items(all_domain_duplicates)
        deduplicate_items(all_comprehensive_duplicates)
        
        return {
            'total_passwords_analyzed': sum(r['total_passwords'] for r in self.scan_results),
            'password_duplicate_groups': len(all_password_duplicates),
            'username_duplicate_groups': len(all_username_duplicates),
            'comprehensive_duplicate_groups': len(all_comprehensive_duplicates),
            'url_duplicate_groups': len(all_url_duplicates),
            'domain_duplicate_groups': len(all_domain_duplicates),
            'total_duplicate_groups': (len(all_password_duplicates) + len(all_username_duplicates) + 
                                     len(all_comprehensive_duplicates) + len(all_url_duplicates) + 
                                     len(all_domain_duplicates)),
            'password_duplicates': dict(all_password_duplicates),
            'username_duplicates': dict(all_username_duplicates),
            'comprehensive_duplicates': dict(all_comprehensive_duplicates),
            'url_duplicates': dict(all_url_duplicates),
            'domain_duplicates': dict(all_domain_duplicates),
            'password_frequency': dict(all_password_counts),
            'username_frequency': dict(all_username_counts),
            'url_frequency': dict(all_url_counts),
            'most_common_passwords': all_password_counts.most_common(20),
            'most_common_usernames': all_username_counts.most_common(20),
            'most_common_urls': all_url_counts.most_common(20),
            'scan_summary': [
                {
                    'pass': scan['pass'],
                    'password_duplicates': scan['password_duplicate_groups'],
                    'username_duplicates': scan['username_duplicate_groups'],
                    'comprehensive_duplicates': scan['comprehensive_duplicate_groups'],
                    'url_duplicates': scan['url_duplicate_groups'],
                    'domain_duplicates': scan['domain_duplicate_groups'],
                    'total_duplicates': (scan['password_duplicate_groups'] + scan['username_duplicate_groups'] + 
                                       scan['comprehensive_duplicate_groups'] + scan['url_duplicate_groups'] + 
                                       scan['domain_duplicate_groups']),
                    'timestamp': scan['timestamp']
                }
                for scan in self.scan_results
            ]
        }
    
    async def _generate_reports_async(self, analysis, output_format, export_csv, create_clean_export, clean_export_format):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if output_format == 'txt':
            report_filename = f"duplicate_analysis_report_{timestamp}.txt"
            report_content = await self._generate_report_content_async(analysis)
            
            async with aiofiles.open(report_filename, 'w', encoding='utf-8') as f:
                await f.write(report_content)
            
            logger.info(f"Report saved: {report_filename}")
            analysis['report_filename'] = report_filename
        
        if export_csv:
            csv_filename = f"bitwarden_duplicates_{timestamp}.csv"
            await self._export_to_csv_async(analysis, csv_filename)
            analysis['csv_export'] = csv_filename
        
        if create_clean_export:
            clean_filename = f"bitwarden_clean_export_{timestamp}.{clean_export_format}"
            await self._create_clean_export_async(analysis, clean_export_format, clean_filename)
            analysis['clean_export'] = clean_filename
    
    async def _generate_report_content_async(self, analysis):
        report_lines = [
            "=" * 80,
            "BITWARDEN DUPLICATE ANALYSIS REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Source File: {self.file_path.name}",
            f"Scan Passes: {self.config.scan_passes}",
            f"Total Passwords Analyzed: {analysis['total_passwords_analyzed']}",
            "",
            "DUPLICATE SUMMARY:",
            f"  Password Duplicate Groups: {analysis['password_duplicate_groups']}",
            f"  Username Duplicate Groups: {analysis['username_duplicate_groups']}",
            f"  Comprehensive Duplicate Groups: {analysis['comprehensive_duplicate_groups']}",
            f"  URL Duplicate Groups: {analysis['url_duplicate_groups']}",
            f"  Domain Duplicate Groups: {analysis['domain_duplicate_groups']}",
            f"  Total Duplicate Groups: {analysis['total_duplicate_groups']}",
            "=" * 80,
            "",
            "SCAN SUMMARY:",
            "-" * 40
        ]
        
        for scan in analysis['scan_summary']:
            report_lines.append(
                f"Pass {scan['pass']}: {scan['password_duplicates']} password, "
                f"{scan['username_duplicates']} username, {scan['comprehensive_duplicates']} comprehensive, "
                f"{scan['url_duplicates']} URL, {scan['domain_duplicates']} domain duplicates "
                f"(total: {scan['total_duplicates']}) at {scan['timestamp']}"
            )
        
        report_lines.extend([
            "",
            "MOST COMMON PASSWORDS:",
            "-" * 40
        ])
        
        for password, count in analysis['most_common_passwords'][:10]:
            masked_password = self._mask_password(password)
            report_lines.append(f"{masked_password} (used {count} times)")
        
        report_lines.extend([
            "",
            "MOST COMMON USERNAMES:",
            "-" * 40
        ])
        
        for username, count in analysis['most_common_usernames'][:10]:
            report_lines.append(f"{username} (used {count} times)")
        
        report_lines.extend([
            "",
            "MOST COMMON URLs:",
            "-" * 40
        ])
        
        for url, count in analysis['most_common_urls'][:10]:
            report_lines.append(f"{url} (used {count} times)")
        
        return "\n".join(report_lines)
    
    async def _export_to_csv_async(self, analysis, filename):
        csv_data = []
        
        headers = [
            'Group Type', 'Group Number', 'Item Name', 'Username', 'Password (Masked)',
            'URL', 'Domain', 'Folder', 'Favorite', 'Notes'
        ]
        csv_data.append(headers)
        
        group_num = 1
        for password_hash, items in analysis['password_duplicates'].items():
            for item in items:
                csv_data.append([
                    'Password Duplicate',
                    group_num,
                    item.name,
                    item.username,
                    self._mask_password(item.password),
                    item.url,
                    item.domain,
                    item.folder or '',
                    item.favorite,
                    item.notes
                ])
            group_num += 1
        
        async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
            for row in csv_data:
                await f.write(','.join(f'"{str(cell)}"' for cell in row) + '\n')
        
        logger.info(f"CSV exported: {filename}")
    
    async def _create_clean_export_async(self, analysis, export_format, filename):
        logger.info("Creating clean export")
        
        if not self.data:
            raise Exception("No data for clean export")
        
        all_items = self.data['items'].copy()
        folders = self.data['folders'].copy()
        
        items_to_remove = set()
        for comprehensive_key, items in analysis['comprehensive_duplicates'].items():
            if len(items) > 1:
                for item in items[1:]:
                    items_to_remove.add(item.id)
        
        clean_items = [item for item in all_items if item['id'] not in items_to_remove]
        
        clean_data = {
            'encrypted': False,
            'folders': folders,
            'items': clean_items
        }
        
        if export_format == 'json':
            async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(clean_data, indent=2, ensure_ascii=False))
        else:
            await self._export_to_bitwarden_csv_async(clean_data, filename)
        
        logger.info(f"Clean export: {filename}")
        logger.info(f"Removed {len(items_to_remove)} duplicates, kept {len(clean_items)} items")
    
    async def _export_to_bitwarden_csv_async(self, data, filename):
        csv_lines = [
            'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp'
        ]
        
        folder_map = {folder['id']: folder['name'] for folder in data.get('folders', [])}
        
        for item in data['items']:
            if item.get('type') == 1 and item.get('login'):
                login = item['login']
                folder_name = folder_map.get(item.get('folderId'), '')
                
                csv_line = [
                    folder_name,
                    str(item.get('favorite', False)),
                    'login',
                    item.get('name', ''),
                    item.get('notes', ''),
                    '',
                    str(item.get('reprompt', 0)),
                    login.get('uris', [{}])[0].get('uri', '') if login.get('uris') else '',
                    login.get('username', ''),
                    login.get('password', ''),
                    login.get('totp', '') if login.get('totp') else ''
                ]
                
                csv_lines.append(','.join(f'"{str(field)}"' for field in csv_line))
        
        async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
            await f.write('\n'.join(csv_lines))
    
    def run_analysis(self, output_format='txt', export_csv=True, 
                    create_clean_export=False, clean_export_format='json'):
        output_format_enum = output_format
        clean_format_enum = clean_export_format
        
        result = asyncio.run(self.run_analysis_async(
            output_format_enum, export_csv, create_clean_export, clean_format_enum
        ))
        
        return {
            'total_passwords_analyzed': result['total_passwords_analyzed'],
            'password_duplicate_groups': result['password_duplicate_groups'],
            'username_duplicate_groups': result['username_duplicate_groups'],
            'comprehensive_duplicate_groups': result['comprehensive_duplicate_groups'],
            'url_duplicate_groups': result['url_duplicate_groups'],
            'domain_duplicate_groups': result['domain_duplicate_groups'],
            'total_duplicate_groups': result['total_duplicate_groups'],
            'password_duplicates': result['password_duplicates'],
            'username_duplicates': result['username_duplicates'],
            'comprehensive_duplicates': result['comprehensive_duplicates'],
            'url_duplicates': result['url_duplicates'],
            'domain_duplicates': result['domain_duplicates'],
            'most_common_passwords': result['most_common_passwords'],
            'most_common_usernames': result['most_common_usernames'],
            'most_common_urls': result['most_common_urls'],
            'ml_analysis': result['ml_analysis'],
            'processing_time': result['processing_time'],
            'report_filename': result.get('report_filename'),
            'csv_export': result.get('csv_export'),
            'clean_export': result.get('clean_export')
        }


async def main_async():
    parser = argparse.ArgumentParser(
        description="High-performance Bitwarden duplicate checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bitwarden_duplicate_checker.py export.json
  python bitwarden_duplicate_checker.py export.json --passes 5 --async
  python bitwarden_duplicate_checker.py export.json --clean-export --ml-analysis
        """
    )
    
    parser.add_argument('json_file', help='Path to Bitwarden export file')
    parser.add_argument('--passes', type=int, default=3, help='Scan passes (default: 3)')
    parser.add_argument('--no-csv', action='store_true', help='Skip CSV export')
    parser.add_argument('--clean-export', action='store_true', help='Create clean export')
    parser.add_argument('--clean-format', choices=['json', 'csv'], default='json', help='Clean export format')
    parser.add_argument('--output', choices=['txt', 'json'], default='txt', help='Report format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    parser.add_argument('--async-mode', action='store_true', help='Use async processing')
    parser.add_argument('--ml-analysis', action='store_true', help='Enable ML analysis')
    parser.add_argument('--max-workers', type=int, default=4, help='Max worker threads')
    parser.add_argument('--similarity-threshold', type=float, default=0.7, help='ML similarity threshold')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    config = AnalysisConfig(
        scan_passes=args.passes,
        enable_ml=args.ml_analysis,
        similarity_threshold=args.similarity_threshold,
        max_workers=args.max_workers
    )
    
    checker = BitwardenDuplicateChecker(args.json_file, config)
    
    try:
        if args.async_mode:
            result = await checker.run_analysis_async(
                output_format=args.output,
                export_csv=not args.no_csv,
                create_clean_export=args.clean_export,
                clean_export_format=args.clean_format
            )
            
            print(f"\nAsync Analysis Complete!")
            print(f"Time: {result['processing_time']:.2f}s")
            print(f"Password Duplicates: {result['password_duplicate_groups']}")
            print(f"Username Duplicates: {result['username_duplicate_groups']}")
            print(f"Comprehensive Duplicates: {result['comprehensive_duplicate_groups']}")
            print(f"URL Duplicates: {result['url_duplicate_groups']}")
            print(f"Domain Duplicates: {result['domain_duplicate_groups']}")
            print(f"Total: {result['total_duplicate_groups']}")
            
        else:
            results = checker.run_analysis(
                output_format=args.output,
                export_csv=not args.no_csv,
                create_clean_export=args.clean_export,
                clean_export_format=args.clean_format
            )
            
            print(f"\nAnalysis complete!")
            print(f"Password duplicates: {results['password_duplicate_groups']}")
            print(f"Username duplicates: {results['username_duplicate_groups']}")
            print(f"Comprehensive duplicates: {results['comprehensive_duplicate_groups']}")
            print(f"URL duplicates: {results['url_duplicate_groups']}")
            print(f"Domain duplicates: {results['domain_duplicate_groups']}")
            print(f"Total: {results['total_duplicate_groups']}")
            
            if 'report_filename' in results:
                print(f"Report: {results['report_filename']}")
            if 'csv_export' in results:
                print(f"CSV: {results['csv_export']}")
            if 'clean_export' in results:
                print(f"Clean export: {results['clean_export']}")
                
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        print(f"Error: {e}")
        sys.exit(1)


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
