import tkinter as tk
from tkinter import ttk
import re

class ProcessLogFilter:
    def __init__(self, master, log_file="system_audit.log"):  #default log file
        self.master = master
        master.title("Process Log Filter")

        self.log_file = log_file
        self.log_data = self.load_log_data()

        self.create_widgets()

    def load_log_data(self):
        """Loads and parses the log file."""
        data = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - INFO - Process: ({.*?})", line)
                    if match:
                        timestamp, process_data = match.groups()
                        process_data = eval(process_data) # Safely evaluate the JSON-like string
                        data.append({"timestamp": timestamp, **process_data})
        except FileNotFoundError:
            print(f"Error: Log file '{self.log_file}' not found.")
        return data


    def create_widgets(self):
        """Creates and arranges the GUI elements."""

        # Search entries
        tk.Label(self.master, text="Username:").grid(row=0, column=0, sticky="w")
        self.username_entry = tk.Entry(self.master)
        self.username_entry.grid(row=0, column=1, sticky="ew")

        tk.Label(self.master, text="Time (YYYY-MM-DD HH:MM:SS):").grid(row=1, column=0, sticky="w")
        self.time_entry = tk.Entry(self.master)
        self.time_entry.grid(row=1, column=1, sticky="ew")

        tk.Label(self.master, text="PID:").grid(row=2, column=0, sticky="w")
        self.pid_entry = tk.Entry(self.master)
        self.pid_entry.grid(row=2, column=1, sticky="ew")


        # Search button
        self.search_button = ttk.Button(self.master, text="Search", command=self.search_log)
        self.search_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Results display
        self.results_text = tk.Text(self.master, wrap=tk.WORD)
        self.results_text.grid(row=4, column=0, columnspan=2, sticky="nsew")
        self.results_text.config(state=tk.DISABLED) #make it read-only

        self.master.columnconfigure(1, weight=1) #Make the entry fields take up the available space
        self.master.rowconfigure(4, weight=1) #Make the result text area expandable


    def search_log(self):
        """Searches the log data based on user input."""
        username = self.username_entry.get()
        time_str = self.time_entry.get()
        pid_str = self.pid_entry.get()

        results = []
        for entry in self.log_data:
            if (not username or username.lower() in entry['username'].lower()) and \
               (not time_str or time_str in entry['timestamp']) and \
               (not pid_str or pid_str == str(entry['pid'])):
                results.append(entry)

        self.display_results(results)

    def display_results(self, results):
        """Displays the search results in the text area."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)

        if results:
            for result in results:
                self.results_text.insert(tk.END, str(result) + "\n")
        else:
            self.results_text.insert(tk.END, "No matches found.")

        self.results_text.config(state=tk.DISABLED)

root = tk.Tk()
filter_app = ProcessLogFilter(root)
root.mainloop()
