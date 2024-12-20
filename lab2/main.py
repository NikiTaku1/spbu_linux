import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import subprocess

class MonitorT:

    #################
    ### Interface ###

    def __init__(self, master):
        self.master = master
        master.title("Traffic Monitor")
        master.geometry("950x700")
        master.resizable(False, False)

        self.ip_count = {}
        self.sus_ips = set()
        self.block_ips = set()
        self.mon_act = False
        
        self.dark_mode()
        self.create_widgets()
        
    def dark_mode(self):
        self.master.config(bg="#222222")

        style = ttk.Style()
        style.theme_use('clam')  # or 'alt'

        style.configure(".", background="#222222", foreground="#dddddd", font=("Consolas", 10))

        style.configure("TLabelframe", background="#333333", foreground="#dddddd", borderwidth=0, relief="flat")
        style.layout("TLabelframe",
                     [('Labelframe.border', {'sticky': 'nswe'}),
                      ('Labelframe.label', {'sticky': 'nswe'})])

        style.configure("Treeview", background="#333333", fieldbackground="#333333", foreground="#dddddd", highlightthickness=0, borderwidth=0)
        style.configure("Treeview.Heading", background="#444444", foreground="#dddddd", borderwidth=0, relief="flat")
        style.map("Treeview", background=[('selected', '#444444')])

        style.configure("TButton", background="#444444", foreground="#dddddd", borderwidth=0, relief="flat")


    def create_widgets(self):

        frame_all = tk.Frame(root)
        frame_all.grid(row=0, column=0, padx=5, pady=5, sticky="n")

        frame_sus = tk.Frame(root)
        frame_sus.grid(row=0, column=1, padx=5, pady=5, sticky="n")

        frame_block = tk.Frame(root)
        frame_block.grid(row=0, column=2, padx=5, pady=5, sticky="n")

        style = ttk.Style()
        style.configure("Treeview", rowheight = 20)
        
        frame_all = tk.LabelFrame(self.master, text="Received", borderwidth=0)
        frame_all.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        self.table_all = ttk.Treeview(frame_all, columns=("IPs", "Ports", "Packets"), show="headings", height=30)

        self.table_all.heading("IPs", text="IP")
        self.table_all.heading("Ports", text="Port")
        self.table_all.heading("Packets", text="Packet Size")
        self.table_all.column("IPs", width = 150, stretch = tk.NO)
        self.table_all.column("Ports", width = 150, stretch = tk.NO)
        self.table_all.column("Packets", width = 150, stretch = tk.NO)

        self.table_all.pack(side="top", fill="both", expand=True)

        button_frame = tk.Frame(frame_all)
        button_frame.pack(side="top", fill="x")

        self.start_button = tk.Button(button_frame, text="Start", command=self.begin_mon)
        self.start_button.pack(side="left", fill="x", expand = True, padx=5, pady=5)

        self.stop_button = tk.Button(button_frame, text="Stop", command=self.stop_mon)
        self.stop_button.pack(side="right", fill="x", expand = True, padx=5, pady=5)


        frame_sus = tk.LabelFrame(self.master, text="Flagged IPs", borderwidth=0)
        frame_sus.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        self.table_sus = ttk.Treeview(frame_sus, columns=("IPs", "Reason"), show="headings", height=30)

        self.table_sus.heading("IPs", text="IP")
        self.table_sus.heading("Reason", text="Flag")
        self.table_sus.column("IPs", width = 150, stretch = tk.NO)
        self.table_sus.column("Reason", width = 150, stretch = tk.NO)

        self.table_sus.pack(side="top", fill="both", expand=True)



        self.block_button = tk.Button(frame_sus, text="Block traffic", command=self.block_ip)
        self.block_button.pack(fill="x", padx=0, pady=5)


        frame_block = tk.LabelFrame(self.master, text="Blocked", borderwidth=0)
        frame_block.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")
        self.table_block = ttk.Treeview(frame_block, columns=("IPs",), show="headings", height=30)

        self.table_block.heading("IPs", text="IP")
        self.table_block.column("IPs", width = 150, stretch = tk.NO)

        self.table_block.pack(side="top", fill="both", expand=True)


        self.unblock_button = tk.Button(frame_block, text="Unblock traffic", command=self.unblock_ip)
        self.unblock_button.pack(fill="x", padx=0, pady=5)

    def packets(self, packet):
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP].src
            size = len(packet)

            if ip not in self.ip_count:
                self.ip_count[ip] = 0

            self.ip_count[ip] += size

            if self.ip_count[ip] > 200:
                if ip not in self.sus_ips:
                    self.sus_ips.add(ip)
                    self.table_sus.insert("", "end", values=(ip, "Packet size error"))

            if ip not in self.block_ips:
                self.table_all.insert("", "end", values=(ip, packet[scapy.IP].sport, size))

    def begin_mon(self):
        self.table_sus.delete(*self.table_sus.get_children())
        self.table_all.delete(*self.table_all.get_children())

        self.mon_act = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        monitoring_thread = threading.Thread(target=self.mon)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        print("Started.")

        ### /Interface ###
        ##################








    def mon(self):
        scapy.sniff(prn=self.packets, store=0)

    def stop_mon(self):
        self.mon_act = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        print("Stopped.")

    def block_ip(self):
        selected_item = self.table_sus.selection()
        if selected_item:
            ip = self.table_sus.item(selected_item[0])['values'][0]
            if ip not in self.block_ips:
                self.block_ips.add(ip)
                self.table_block.insert("", "end", values=(ip,))
                self.add_ip(ip)
                self.table_sus.delete(selected_item)

    def unblock_ip(self):
        selected_item = self.table_block.selection()
        if selected_item:
            ip = self.table_block.item(selected_item[0])['values'][0]
            if ip in self.block_ips:
                self.block_ips.remove(ip)
                self.remove_ip(ip)
                self.table_block.delete(selected_item)

    def add_ip(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"IP blocked: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Block error {ip}: {e}")

    def remove_ip(self, ip):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"IP unblocked: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Unblock {ip}: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    monitor = MonitorT(root)
    root.mainloop()
