import tkinter as tk
from tkinter import ttk
import re
import json

class ProcessLogSearch:
    def __init__(self, master, log_file="system_audit.log"):
        self.master = master
        master.title("Process Log Searcher")
        self.log_file = log_file
        self.log_data = self.load_log_data()
        self.create_widgets()

    def load_log_data(self):
        data = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - INFO - Process: ({.*?})", line)
                    if match:
                        timestamp, process_str = match.groups()
                        try:
                            process_data = json.loads(process_str)
                            data.append({"timestamp": timestamp, **process_data})
                        except json.JSONDecodeError as e:
                            continue
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found.")
            return []
        return data

    def create_widgets(self):
        tk.Label(self.master, text="Username:").grid(row=0, column=0, sticky="w")
        self.username_entry = tk.Entry(self.master)
        self.username_entry.grid(row=0, column=1, sticky="ew")

        tk.Label(self.master, text="PID:").grid(row=1, column=0, sticky="w")
        self.pid_entry = tk.Entry(self.master)
        self.pid_entry.grid(row=1, column=1, sticky="ew")

        tk.Label(self.master, text="Date (YYYY-MM-DD):").grid(row=2, column=0, sticky="w")
        self.date_entry = tk.Entry(self.master)
        self.date_entry.grid(row=2, column=1, sticky="ew")

        self.search_button = ttk.Button(self.master, text="Search", command=self.search_log)
        self.search_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.results_text = tk.Text(self.master, wrap=tk.WORD)
        self.results_text.grid(row=4, column=0, columnspan=2, sticky="nsew")
        self.results_text.config(state=tk.DISABLED)

        self.master.columnconfigure(1, weight=1)
        self.master.rowconfigure(4, weight=1)

    def search_log(self):
        username = self.username_entry.get()
        pid_str = self.pid_entry.get()
        date_str = self.date_entry.get()

        results = []
        for entry in self.log_data:
            if (not username or username.lower() in entry.get('username', '').lower()) and \
               (not pid_str or pid_str == str(entry.get('pid', ''))) and \
               (not date_str or date_str in entry['timestamp']):
                results.append(entry)

        self.display_results(results)

    def display_results(self, results):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)

        if results:
            for result in results:
                self.results_text.insert(tk.END, str(result) + "\n")
        else:
            self.results_text.insert(tk.END, "No matches found.")

        self.results_text.config(state=tk.DISABLED)

root = tk.Tk()
app = ProcessLogSearch(root)
root.mainloop()
