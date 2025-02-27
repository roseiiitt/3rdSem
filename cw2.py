import os
import hashlib
import requests
import time
import logging
import threading
from tkinter import messagebox, filedialog, Scrollbar
import tkinter as tk
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if API_KEY is None:
    raise ValueError("API key not found. Please set the VIRUSTOTAL_API_KEY environment variable.")
else:
    print("API Key Loaded") 

API_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": API_KEY,
    "Accept": "application/json"
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def save_scan_results(file_path, results, log_file):
    log_file.write(f"\n\n{'-'*40}\n")
    log_file.write(f"Scan started for: {file_path}\n")
    log_file.write(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    clean_count = 0
    flagged_count = 0
    total_count = len(results["data"]["attributes"]["last_analysis_results"])

    for engine, result in results["data"]["attributes"]["last_analysis_results"].items():
        status = result['result']
        log_file.write(f"{engine}: {status}\n")
        if status == "clean":
            clean_count += 1
        elif status != "clean":
            flagged_count += 1

    score = (flagged_count / total_count) * 100
    log_file.write(f"\nScan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_file.write(f"Score: {score:.2f}% (based on clean engines)\n")
    
    if flagged_count > 0:
        log_file.write(f"\nWarning: Virus detected in {file_path}!\n")
    else:
        log_file.write(f"\nNo viruses detected in {file_path}.\n")

    log_file.write(f"\n{'-'*40}\n")

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except IOError:
        logging.error(f"Could not read file: {file_path}")
        return None

def scan_file_with_virustotal(file_path, gui_output, log_file):
    start_time = time.time()  # Start timer to log scan duration
    try:
        file_hash = calculate_file_hash(file_path)
        if not file_hash:
            gui_output.insert(tk.END, f"Skipping {file_path} due to read error.\n")
            return

        report_url = f"{API_URL}/files/{file_hash}"
        response = requests.get(report_url, headers=HEADERS)

        if response.status_code == 200:
            results = response.json()
            if results.get("data", {}).get("attributes", {}).get("last_analysis_results"):
                gui_output.insert(tk.END, f"Scan results for {file_path} (Previous Scan):\n")
                display_scan_results(results, gui_output, file_path)
                save_scan_results(file_path, results, log_file)  
            else:
                gui_output.insert(tk.END, f"No results found for {file_path}. Uploading file for analysis...\n")
                upload_file_for_analysis(file_path, gui_output, log_file)
        elif response.status_code == 404:
            gui_output.insert(tk.END, f"No results found for {file_path}. Uploading file for analysis...\n")
            upload_file_for_analysis(file_path, gui_output, log_file)
        else:
            gui_output.insert(tk.END, f"Error retrieving report for {file_path}: {response.text}\n")
    except Exception as e:
        gui_output.insert(tk.END, f"An error occurred while scanning {file_path}: {e}\n")
    finally:
        end_time = time.time()  # End timer
        elapsed_time = end_time - start_time
        log_message = f"Scan of {file_path} completed in {elapsed_time:.2f} seconds.\n"
        logging.info(log_message)
        log_file.write(log_message)

def display_scan_results(results, gui_output, file_path):
    clean_count = 0
    flagged_count = 0
    total_count = len(results["data"]["attributes"]["last_analysis_results"])

    for engine, result in results["data"]["attributes"]["last_analysis_results"].items():
        status = result['result']
        if status == "clean":
            clean_count += 1
            gui_output.insert(tk.END, f"{engine}: {status}\n")
        elif status != "clean":
            flagged_count += 1
            gui_output.insert(tk.END, f"{engine}: {status}\n")
    print("Total Count",total_count)

    score = (flagged_count / total_count) * 100
    gui_output.insert(tk.END, f"\nScan complete.\n")
    gui_output.insert(tk.END, f"Score: {score:.2f}% (based on clean engines)\n")

    if score > 0:
        gui_output.insert(tk.END, f"\nWarning: Virus detected in {file_path}!\n")
    else:
        gui_output.insert(tk.END, f"\nNo viruses detected in {file_path}.\n")

def upload_file_for_analysis(file_path, gui_output, log_file):
    upload_url = f"{API_URL}/files"
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        upload_response = requests.post(upload_url, headers=HEADERS, files=files)
        if upload_response.status_code == 200:
            analysis_id = upload_response.json()["data"]["id"]
            gui_output.insert(tk.END, f"File uploaded. Analysis ID: {analysis_id}\n")
            time.sleep(30)  # Wait for the analysis to complete
            scan_file_with_virustotal(file_path, gui_output, log_file)
        else:
            gui_output.insert(tk.END, f"Failed to upload file: {upload_response.text}\n")

def scan_file(file_path, gui_output, log_file):
    if os.path.isfile(file_path):
        gui_output.insert(tk.END, f"Scanning file: {file_path}\n")
        scan_file_with_virustotal(file_path, gui_output, log_file)
    else:
        gui_output.insert(tk.END, f"Invalid file path: {file_path}\n")

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Antivirus Tool")
        self.root.geometry("600x500")
        self.root.minsize(400, 400)

        self.directory_label = tk.Label(root, text="Enter File Path:")
        self.directory_label.pack(pady=10)

        self.path_entry = tk.Entry(root, width=50)
        self.path_entry.pack(pady=10)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse)
        self.browse_button.pack(pady=5)

        self.output_frame = tk.Frame(root)
        self.output_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        self.scrollbar = Scrollbar(self.output_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.gui_output = tk.Text(self.output_frame, wrap=tk.WORD, height=10, yscrollcommand=self.scrollbar.set)
        self.gui_output.pack(fill=tk.BOTH, expand=True)
        self.scrollbar.config(command=self.gui_output.yview)

        self.scan_button = tk.Button(root, text="Scan", command=self.scan)
        self.scan_button.pack(pady=5)

        self.clear_button = tk.Button(root, text="Clear Screen", command=self.clear_screen)
        self.clear_button.pack(pady=5)

    def browse(self):
        path = filedialog.askopenfilename()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def scan(self):
        path = self.path_entry.get()
        if os.path.isfile(path):
            self.gui_output.insert(tk.END, f"Scanning file: {path}\n")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"scan_results_{timestamp}.txt"
            log_file = open(log_filename, "w")
            threading.Thread(target=scan_file, args=(path, self.gui_output, log_file), daemon=True).start()
        else:
            messagebox.showerror("Error", "Invalid file path.")

    def clear_screen(self):
        self.gui_output.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()