#!/usr/bin/env python3
"""
Bitwarden Duplicate Checker GUI

Clean, efficient interface for duplicate detection with async processing.
Supports all scan types and advanced features.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
from pathlib import Path
import json
from datetime import datetime

from bitwarden_duplicate_checker import BitwardenDuplicateChecker, AnalysisConfig


class BitwardenDuplicateCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Bitwarden Duplicate Checker")
        self.root.geometry("700x600")
        self.root.resizable(True, True)
        
        # Variables
        self.json_file_path = tk.StringVar()
        self.scan_passes = tk.IntVar(value=3)
        self.check_passwords = tk.BooleanVar(value=True)
        self.check_urls = tk.BooleanVar(value=True)
        self.check_domains = tk.BooleanVar(value=True)
        self.check_usernames = tk.BooleanVar(value=True)
        self.check_comprehensive = tk.BooleanVar(value=True)
        self.enable_ml_analysis = tk.BooleanVar(value=False)
        self.export_csv = tk.BooleanVar(value=True)
        self.create_clean_export = tk.BooleanVar(value=False)
        self.clean_export_format = tk.StringVar(value='json')
        self.use_async = tk.BooleanVar(value=True)
        self.max_workers = tk.IntVar(value=4)
        
        # Analysis results
        self.analysis_results = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 Bitwarden Duplicate Checker", 
                               font=("Arial", 18, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # File selection
        ttk.Label(main_frame, text="Export File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        file_entry = ttk.Entry(main_frame, textvariable=self.json_file_path, width=50)
        file_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(5, 5), pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=1, column=2, pady=5)
        
        # File type info
        ttk.Label(main_frame, text="Supports: JSON (.json) and CSV (.csv) files", 
                 font=("Arial", 8), foreground="gray").grid(row=2, column=1, sticky=tk.W, padx=(5, 0))
        
        # Configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="15")
        config_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=15)
        config_frame.columnconfigure(1, weight=1)
        
        # Scan passes
        ttk.Label(config_frame, text="Scan Passes:").grid(row=0, column=0, sticky=tk.W, pady=5)
        passes_spinbox = ttk.Spinbox(config_frame, from_=1, to=10, textvariable=self.scan_passes, width=10)
        passes_spinbox.grid(row=0, column=1, sticky=tk.W, padx=(5, 0), pady=5)
        ttk.Label(config_frame, text="(More passes = more thorough)").grid(row=0, column=2, sticky=tk.W, padx=(5, 0), pady=5)
        
        # Scan options
        ttk.Label(config_frame, text="Scan Options:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        checkboxes_frame = ttk.Frame(config_frame)
        checkboxes_frame.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=(5, 0), pady=5)
        
        # First row of checkboxes
        ttk.Checkbutton(checkboxes_frame, text="Password Duplicates", 
                       variable=self.check_passwords).grid(row=0, column=0, sticky=tk.W, padx=(0, 15))
        ttk.Checkbutton(checkboxes_frame, text="URL Duplicates", 
                       variable=self.check_urls).grid(row=0, column=1, sticky=tk.W, padx=(0, 15))
        ttk.Checkbutton(checkboxes_frame, text="Domain Duplicates", 
                       variable=self.check_domains).grid(row=0, column=2, sticky=tk.W)
        
        # Second row of checkboxes
        ttk.Checkbutton(checkboxes_frame, text="Username Duplicates", 
                       variable=self.check_usernames).grid(row=1, column=0, sticky=tk.W, padx=(0, 15), pady=(5, 0))
        ttk.Checkbutton(checkboxes_frame, text="Comprehensive Duplicates", 
                       variable=self.check_comprehensive).grid(row=1, column=1, sticky=tk.W, padx=(0, 15), pady=(5, 0))
        ttk.Checkbutton(checkboxes_frame, text="ML Analysis", 
                       variable=self.enable_ml_analysis).grid(row=1, column=2, sticky=tk.W, pady=(5, 0))
        
        # Export options
        export_frame = ttk.Frame(config_frame)
        export_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Checkbutton(export_frame, text="Export Analysis to CSV", 
                       variable=self.export_csv).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        
        ttk.Checkbutton(export_frame, text="Create Clean Export", 
                       variable=self.create_clean_export).grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        
        ttk.Label(export_frame, text="Format:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        format_combo = ttk.Combobox(export_frame, textvariable=self.clean_export_format, 
                                   values=['json', 'csv'], width=8, state='readonly')
        format_combo.grid(row=0, column=3, sticky=tk.W)
        
        # Advanced options
        advanced_frame = ttk.Frame(config_frame)
        advanced_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Checkbutton(advanced_frame, text="Async Processing", 
                       variable=self.use_async).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        
        ttk.Label(advanced_frame, text="Max Workers:").grid(row=0, column=1, sticky=tk.W, padx=(20, 0))
        workers_spinbox = ttk.Spinbox(advanced_frame, from_=1, to=16, textvariable=self.max_workers, width=8)
        workers_spinbox.grid(row=0, column=2, sticky=tk.W, padx=(5, 0))
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=20)
        
        self.start_button = ttk.Button(button_frame, text="🚀 Start Analysis", 
                                      command=self.start_analysis, style="Accent.TButton")
        self.start_button.grid(row=0, column=0, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", 
                                     command=self.clear_results)
        self.clear_button.grid(row=0, column=1, padx=(0, 10))
        
        self.open_folder_button = ttk.Button(button_frame, text="📁 Open Results Folder", 
                                            command=self.open_results_folder, state="disabled")
        self.open_folder_button.grid(row=0, column=2, padx=(0, 10))
        
        # Status display
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                                font=("Arial", 10), foreground="blue")
        status_label.grid(row=5, column=0, columnspan=3, pady=10)
        
        # Results display
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=80)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Bitwarden Export File",
            filetypes=[("Bitwarden files", "*.json;*.csv"), ("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            self.json_file_path.set(file_path)
            self.status_var.set(f"Selected: {os.path.basename(file_path)}")
    
    def start_analysis(self):
        if not self.json_file_path.get():
            messagebox.showerror("Error", "Please select a Bitwarden export file first.")
            return
        
        if not self._validate_inputs():
            return
        
        # Disable start button and show status
        self.start_button.config(state="disabled")
        self.status_var.set("🔄 Analysis in progress...")
        self.results_text.delete(1.0, tk.END)
        
        # Start analysis in separate thread
        analysis_thread = threading.Thread(target=self.run_analysis_thread)
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def clear_results(self):
        """Clear the results display."""
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Ready")
        self.open_folder_button.config(state="disabled")
        self.analysis_results = None
    
    def _validate_inputs(self):
        if not self.json_file_path.get():
            messagebox.showerror("Error", "Please select a Bitwarden export file.")
            return False
        
        if not os.path.exists(self.json_file_path.get()):
            messagebox.showerror("Error", "Selected file does not exist.")
            return False
        
        return True
    
    def run_analysis_thread(self):
        try:
            # Create configuration
            config = AnalysisConfig(
                scan_passes=self.scan_passes.get(),
                enable_ml=self.enable_ml_analysis.get(),
                max_workers=self.max_workers.get(),
                check_passwords=self.check_passwords.get(),
                check_urls=self.check_urls.get(),
                check_domains=self.check_domains.get(),
                check_usernames=self.check_usernames.get(),
                check_comprehensive=self.check_comprehensive.get()
            )
            
            # Create checker
            checker = BitwardenDuplicateChecker(self.json_file_path.get(), config)
            
            # Run analysis
            if self.use_async.get():
                # Use async processing
                import asyncio
                result = asyncio.run(checker.run_analysis_async(
                    output_format='txt',
                    export_csv=self.export_csv.get(),
                    create_clean_export=self.create_clean_export.get(),
                    clean_export_format=self.clean_export_format.get()
                ))
                
                # Convert to dict for display
                analysis = {
                    'total_passwords_analyzed': result['total_passwords_analyzed'],
                    'password_duplicate_groups': result['password_duplicate_groups'],
                    'username_duplicate_groups': result['username_duplicate_groups'],
                    'comprehensive_duplicate_groups': result['comprehensive_duplicate_groups'],
                    'url_duplicate_groups': result['url_duplicate_groups'],
                    'domain_duplicate_groups': result['domain_duplicate_groups'],
                    'total_duplicate_groups': result['total_duplicate_groups'],
                    'processing_time': result['processing_time'],
                    'ml_analysis': result.get('ml_analysis'),
                    'report_filename': result.get('report_filename'),
                    'csv_export': result.get('csv_export'),
                    'clean_export': result.get('clean_export')
                }
            else:
                # Use sync processing
                analysis = checker.run_analysis(
                    output_format='txt',
                    export_csv=self.export_csv.get(),
                    create_clean_export=self.create_clean_export.get(),
                    clean_export_format=self.clean_export_format.get()
                )
            
            # Update UI with results
            self.root.after(0, lambda: self.show_results(analysis))
            
        except Exception as e:
            self.root.after(0, lambda: self.show_error(f"Analysis failed: {str(e)}"))
    
    def show_results(self, analysis):
        # Enable buttons
        self.start_button.config(state="normal")
        self.open_folder_button.config(state="normal")
        
        # Update status
        self.status_var.set(f"✅ Analysis complete in {analysis['processing_time']:.2f}s")
        
        # Display results
        results_summary = f"""
🚀 ANALYSIS COMPLETE!

📊 SUMMARY:
-----------
Password Duplicates: {analysis['password_duplicate_groups']}
Username Duplicates: {analysis['username_duplicate_groups']}
Comprehensive Duplicates: {analysis['comprehensive_duplicate_groups']}
URL Duplicates: {analysis['url_duplicate_groups']}
Domain Duplicates: {analysis['domain_duplicate_groups']}
Total Duplicates: {analysis['total_duplicate_groups']}

⏱️  PROCESSING TIME: {analysis['processing_time']:.2f} seconds

📁 FILES CREATED:
-----------------
Report: {analysis.get('report_filename', 'N/A')}
CSV Export: {analysis.get('csv_export', 'Not created')}
Clean Export: {analysis.get('clean_export', 'Not created')}
"""
        
        # Add ML analysis results if available
        if analysis.get('ml_analysis') and analysis['ml_analysis'].get('ml_analysis') == 'completed':
            ml_data = analysis['ml_analysis']
            results_summary += f"""

🤖 ML ANALYSIS:
---------------
Similar Password Pairs: {len(ml_data.get('similar_password_pairs', []))}
Passwords Analyzed: {ml_data.get('total_passwords_analyzed', 0)}
Similarity Threshold: {ml_data.get('similarity_threshold', 0.7)}
"""
        elif analysis.get('ml_analysis'):
            results_summary += f"""

🤖 ML ANALYSIS:
---------------
{analysis['ml_analysis'].get('ml_analysis', 'Not available')}
"""
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, results_summary)
        
        # Store results for folder opening
        self.analysis_results = analysis
    
    def show_error(self, error_message):
        # Enable start button
        self.start_button.config(state="normal")
        
        # Update status
        self.status_var.set("❌ Analysis failed")
        
        # Show error
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(1.0, f"ERROR: {error_message}")
        
        # Show error dialog
        messagebox.showerror("Analysis Error", error_message)
    
    def open_results_folder(self):
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis results available.")
            return
        
        # Find the most recent file
        files_to_check = [
            self.analysis_results.get('report_filename'),
            self.analysis_results.get('csv_export'),
            self.analysis_results.get('clean_export')
        ]
        
        # Find the first existing file
        for file_path in files_to_check:
            if file_path and os.path.exists(file_path):
                folder_path = os.path.dirname(os.path.abspath(file_path))
                if sys.platform == "win32":
                    os.startfile(folder_path)
                elif sys.platform == "darwin":
                    os.system(f"open '{folder_path}'")
                else:
                    os.system(f"xdg-open '{folder_path}'")
                return
        
        messagebox.showinfo("Info", "No output files found to open.")


def main():
    root = tk.Tk()
    
    # Set window icon if available
    try:
        root.iconbitmap("icon.ico")
    except:
        pass
    
    # Center window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    app = BitwardenDuplicateCheckerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
