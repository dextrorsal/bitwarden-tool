#!/usr/bin/env python3
"""
Bitwarden Duplicate Checker GUI
===============================

A simple GUI application for the Bitwarden duplicate checker.
Allows users to configure scan options and monitor progress.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
from pathlib import Path
import json
from datetime import datetime

# Import our duplicate checker
from bitwarden_duplicate_checker import BitwardenDuplicateChecker


class BitwardenDuplicateCheckerGUI:
    """Main GUI application for the Bitwarden duplicate checker."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Bitwarden Duplicate Checker")
        self.root.geometry("600x500")
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
        
        # Analysis results
        self.analysis_results = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Bitwarden Duplicate Checker", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # File selection
        ttk.Label(main_frame, text="Bitwarden Export File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        file_entry = ttk.Entry(main_frame, textvariable=self.json_file_path, width=50)
        file_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(5, 5), pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=1, column=2, pady=5)
        
        # File type info
        ttk.Label(main_frame, text="Supports: JSON (.json) and CSV (.csv) files", 
                 font=("Arial", 8)).grid(row=2, column=1, sticky=tk.W, padx=(5, 0))
        
        # Scan configuration frame
        config_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="10")
        config_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        config_frame.columnconfigure(1, weight=1)
        
        # Number of scan passes
        ttk.Label(config_frame, text="Scan Passes:").grid(row=0, column=0, sticky=tk.W, pady=5)
        passes_spinbox = ttk.Spinbox(config_frame, from_=1, to=10, textvariable=self.scan_passes, width=10)
        passes_spinbox.grid(row=0, column=1, sticky=tk.W, padx=(5, 0), pady=5)
        ttk.Label(config_frame, text="(More passes = more thorough)").grid(row=0, column=2, sticky=tk.W, padx=(5, 0), pady=5)
        
        # Checkboxes for what to scan
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
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)
        
        self.start_button = ttk.Button(button_frame, text="Start Analysis", 
                                      command=self.start_analysis, style="Accent.TButton")
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", 
                                      command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.open_folder_button = ttk.Button(button_frame, text="Open Results Folder", 
                                            command=self.open_results_folder, state="disabled")
        self.open_folder_button.pack(side=tk.LEFT)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="10")
        progress_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.StringVar(value="Ready to start analysis...")
        self.progress_label = ttk.Label(progress_frame, textvariable=self.progress_var)
        self.progress_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=10, width=70)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
    def browse_file(self):
        """Open file dialog to select Bitwarden export file."""
        file_path = filedialog.askopenfilename(
            title="Select Bitwarden Export File",
            filetypes=[("Bitwarden files", "*.json;*.csv"), ("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            self.json_file_path.set(file_path)
            self.status_var.set(f"Selected: {os.path.basename(file_path)}")
    
    def start_analysis(self):
        """Start the duplicate analysis in a separate thread."""
        if not self.json_file_path.get():
            messagebox.showerror("Error", "Please select a Bitwarden JSON file first.")
            return
        
        if not os.path.exists(self.json_file_path.get()):
            messagebox.showerror("Error", "Selected file does not exist.")
            return
        
        if not any([self.check_passwords.get(), self.check_urls.get(), self.check_domains.get(), 
                   self.check_usernames.get(), self.check_comprehensive.get()]):
            messagebox.showerror("Error", "Please select at least one scan option.")
            return
        
        # Disable start button and start progress
        self.start_button.config(state="disabled")
        self.progress_bar.start()
        self.progress_var.set("Starting analysis...")
        self.status_var.set("Analysis in progress...")
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        
        # Start analysis in separate thread
        analysis_thread = threading.Thread(target=self.run_analysis_thread)
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def run_analysis_thread(self):
        """Run the analysis in a separate thread."""
        try:
            # Create checker instance
            checker = BitwardenDuplicateChecker(
                self.json_file_path.get(), 
                self.scan_passes.get()
            )
            
            # Update progress
            self.root.after(0, lambda: self.progress_var.set("Loading Bitwarden data..."))
            
            # Load data
            if not checker.load_data():
                self.root.after(0, lambda: self.show_error("Failed to load Bitwarden data"))
                return
            
            # Perform multiple scans
            for pass_num in range(1, checker.scan_passes + 1):
                self.root.after(0, lambda p=pass_num: self.progress_var.set(f"Scan pass {p}/{checker.scan_passes}..."))
                checker.perform_multiple_scans()
            
            # Update progress
            self.root.after(0, lambda: self.progress_var.set("Analyzing results..."))
            
            # Analyze results
            analysis = checker.analyze_results()
            
            # Run ML analysis if enabled
            if self.enable_ml_analysis.get():
                self.root.after(0, lambda: self.progress_var.set("Running ML analysis..."))
                passwords = checker.extract_passwords()
                ml_results = checker.analyze_password_patterns(passwords)
                analysis['ml_analysis'] = ml_results
            
            # Update progress
            self.root.after(0, lambda: self.progress_var.set("Generating report..."))
            
            # Run complete analysis with all export options
            results = checker.run_analysis(
                output_format='txt',
                export_csv=self.export_csv.get(),
                create_clean_export=self.create_clean_export.get(),
                clean_export_format=self.clean_export_format.get()
            )
            
            # Update UI with results
            self.root.after(0, lambda: self.show_results(results))
            
        except Exception as e:
            self.root.after(0, lambda: self.show_error(f"Analysis failed: {str(e)}"))
    
    def show_results(self, analysis):
        """Display analysis results in the UI."""
        # Stop progress bar
        self.progress_bar.stop()
        self.progress_var.set("Analysis complete!")
        self.status_var.set("Analysis completed successfully")
        
        # Enable start button
        self.start_button.config(state="normal")
        self.open_folder_button.config(state="normal")
        
        # Display results summary
        results_summary = f"""
ANALYSIS COMPLETE!

Summary:
--------
Password Duplicate Groups: {analysis.get('password_duplicate_groups', 0)}
Username Duplicate Groups: {analysis.get('username_duplicate_groups', 0)}
Comprehensive Duplicate Groups: {analysis.get('comprehensive_duplicate_groups', 0)}
URL Duplicate Groups: {analysis.get('url_duplicate_groups', 0)}
Domain Duplicate Groups: {analysis.get('domain_duplicate_groups', 0)}
Total Duplicate Groups: {analysis.get('total_duplicate_groups', 0)}

Files Created:
--------------
Report: {analysis.get('report_filename', 'N/A')}
CSV Export: {analysis.get('csv_export', 'Not created')}
Clean Export: {analysis.get('clean_export', 'Not created')}
"""
        
        # Add ML analysis results if available
        if 'ml_analysis' in analysis and analysis['ml_analysis'].get('ml_analysis') == 'completed':
            ml_data = analysis['ml_analysis']
            results_summary += f"""
ML Analysis:
------------
Similar Password Pairs Found: {len(ml_data.get('similar_password_pairs', []))}
Passwords Analyzed: {ml_data.get('total_passwords_analyzed', 0)}
Similarity Threshold: {ml_data.get('similarity_threshold', 0.7)}
"""
        elif 'ml_analysis' in analysis:
            results_summary += f"""
ML Analysis:
------------
{analysis['ml_analysis'].get('ml_analysis', 'Not available')}
"""
        
        results_summary += f"""
Files Generated:
---------------
Report: {report_filename}
"""
        if csv_filename:
            results_summary += f"CSV Export: {csv_filename}\n"
        
        results_summary += f"\nDetailed report saved to: {report_filename}"
        
        self.results_text.insert(tk.END, results_summary)
        
        # Show completion message
        messagebox.showinfo("Analysis Complete", 
                           f"Found {analysis['total_duplicate_groups']} duplicate groups!\n\n"
                           f"Report saved to: {report_filename}")
    
    def show_error(self, error_message):
        """Display error message."""
        self.progress_bar.stop()
        self.progress_var.set("Analysis failed")
        self.status_var.set("Error occurred")
        self.start_button.config(state="normal")
        
        self.results_text.insert(tk.END, f"ERROR: {error_message}")
        messagebox.showerror("Analysis Error", error_message)
    
    def clear_results(self):
        """Clear the results text area."""
        self.results_text.delete(1.0, tk.END)
        self.progress_var.set("Ready to start analysis...")
        self.status_var.set("Ready")
        self.open_folder_button.config(state="disabled")
    
    def open_results_folder(self):
        """Open the folder containing the results."""
        try:
            # Get the current working directory
            current_dir = os.getcwd()
            
            # Open folder based on OS
            if sys.platform == "win32":
                os.startfile(current_dir)
            elif sys.platform == "darwin":  # macOS
                os.system(f"open '{current_dir}'")
            else:  # Linux
                os.system(f"xdg-open '{current_dir}'")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {str(e)}")


def main():
    """Main function to run the GUI application."""
    root = tk.Tk()
    
    # Set window icon (if available)
    try:
        root.iconbitmap("icon.ico")
    except:
        pass  # Icon file not found, continue without it
    
    # Create and run the application
    app = BitwardenDuplicateCheckerGUI(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()


if __name__ == "__main__":
    main()
