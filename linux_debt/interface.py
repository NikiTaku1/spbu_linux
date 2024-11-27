import tkinter as tk
from tkinter import ttk
import threading
from scanner import NetworkScanner

class NetworkTrafficMonitor:
    def __init__(self, master):
        self.master = master
        master.title("Network Traffic Monitor")
        master.geometry("950x350")
        self.scanner = NetworkScanner()
        self.create_widgets()
        self.monitoring_active = False
        self.ip_counter = {} #To keep track of packet sizes for each IP
        self.suspicious_ips = set()
        self.blocked_ips = set()


    def create_widgets(self):
        # Frames
        all_ips_frame = tk.Frame(self.master)
        all_ips_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        suspicious_ips_frame = tk.Frame(self.master)
        suspicious_ips_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")

        blocked_ips_frame = tk.Frame(self.master)
        blocked_ips_frame.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")

        # All IPs Table
        tk.Label(all_ips_frame, text="All Incoming IPs").pack(side="top")
        self.all_ips_table = ttk.Treeview(all_ips_frame, columns=("IP", "Port", "Size"), show="headings", height=10)
        self.all_ips_table.heading("IP", text="IP Address")
        self.all_ips_table.heading("Port", text="Port")
        self.all_ips_table.heading("Size", text="Size")
        self.all_ips_table.column("IP", width=150, stretch=tk.NO)
        self.all_ips_table.column("Port", width=100, stretch=tk.NO)
        self.all_ips_table.column("Size", width=100, stretch=tk.NO)
        self.all_ips_table.pack(side="top", fill="both", expand=True)

        # Buttons Frame
        button_frame = tk.Frame(all_ips_frame)
        button_frame.pack(side="top", fill="x")
        self.start_button = tk.Button(button_frame, text="Start", command=self.start_monitoring)
        self.start_button.pack(side="left", fill="x", expand=True, padx=5)
        self.stop_button = tk.Button(button_frame, text="Stop", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="right", fill="x", expand=True, padx=5)

        # Suspicious IPs Table
        tk.Label(suspicious_ips_frame, text="Suspicious IPs").pack(side="top")
        self.suspicious_ips_table = ttk.Treeview(suspicious_ips_frame, columns=("IP", "Reason"), show="headings", height=10)
        self.suspicious_ips_table.heading("IP", text="IP Address")
        self.suspicious_ips_table.heading("Reason", text="Reason")
        self.suspicious_ips_table.column("IP", width=150, stretch=tk.NO)
        self.suspicious_ips_table.column("Reason", width=150, stretch=tk.NO)
        self.suspicious_ips_table.pack(side="top", fill="both", expand=True)
        self.block_button = tk.Button(suspicious_ips_frame, text="Block", command=self.block_ip)
        self.block_button.pack(fill="x", padx=0, pady=5)


        # Blocked IPs Table
        tk.Label(blocked_ips_frame, text="Blocked IPs").pack(side="top")
        self.blocked_ips_table = ttk.Treeview(blocked_ips_frame, columns=("IP",), show="headings", height=10)
        self.blocked_ips_table.heading("IP", text="IP Address")
        self.blocked_ips_table.column("IP", width=150, stretch=tk.NO)
        self.blocked_ips_table.pack(side="top", fill="both", expand=True)
        self.unblock_button = tk.Button(blocked_ips_frame, text="Unblock", command=self.unblock_ip)
        self.unblock_button.pack(fill="x", padx=0, pady=5)

        #Weight columns to distribute space
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=1)
        self.master.grid_columnconfigure(2, weight=1)


    def start_monitoring(self):
        self.clear_tables()
        self.monitoring_active = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.monitoring_thread = threading.Thread(target=self.scanner.start_monitoring)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        print("Monitoring started")

    def stop_monitoring(self):
        self.monitoring_active = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.scanner.stop_monitoring()
        print("Monitoring stopped")

    def block_ip(self):
        selected_item = self.suspicious_ips_table.selection()
        if selected_item:
            ip_address = self.suspicious_ips_table.item(selected_item[0])['values'][0]
            self.scanner.block_ip(ip_address)
            self.update_blocked_ips_table(ip_address)
            self.suspicious_ips_table.delete(selected_item[0])

    def unblock_ip(self):
        selected_item = self.blocked_ips_table.selection()
        if selected_item:
            ip_address = self.blocked_ips_table.item(selected_item[0])['values'][0]
            self.scanner.unblock_ip(ip_address)
            self.blocked_ips_table.delete(selected_item[0])

    def update_all_ips_table(self,ip_address, port, size):
        self.all_ips_table.insert("", "end", values=(ip_address, port, size))

    def update_suspicious_ips_table(self, ip_address):
        self.suspicious_ips_table.insert("", "end", values=(ip_address, "Packet size exceeded"))

    def update_blocked_ips_table(self, ip_address):
        self.blocked_ips_table.insert("", "end", values=(ip_address,))

    def clear_tables(self):
        self.all_ips_table.delete(*self.all_ips_table.get_children())
        self.suspicious_ips_table.delete(*self.suspicious_ips_table.get_children())
        self.blocked_ips_table.delete(*self.blocked_ips_table.get_children())

def main():
    root = tk.Tk()
    monitor = NetworkTrafficMonitor(root)
    root.mainloop()

if __name__ == "__main__":
    main()