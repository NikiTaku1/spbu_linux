import tkinter as tk
from tkinter import scrolledtext
from scanner import *

result = []
result_toggled = []


def scan_and_insert(ips: set, ports: set):
    global result

    result = scan_network(ips, ports)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, format_ip_result(result))


def scan_button_clicked():
    ips_text = ips_entry.get()
    if not ips_text:
        show_popup("Enter ips")
        return

    ports_text = ports_entry.get()
    if not ports_text:
        ports_text = "1-1024"

    global result

    ips = parse_ints(ips_text, expand_ip_range)
    ports = parse_ints(ports_text, expand_port_range)

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Scanning IPs: {list(ips)}\nPorts: {list(ports)}\n")

    scan_thread = threading.Thread(target=lambda: scan_and_insert(ips, ports))
    scan_thread.start()


def show_popup(text: str):
    popup = tk.Toplevel(root)
    popup.title("Info")

    label = tk.Label(popup, text=text)
    label.pack(padx=10, pady=10)

    close_button = tk.Button(popup, text="Ok", command=popup.destroy)
    close_button.pack(padx=10, pady=10)


def toggle_filter():
    global result
    global result_toggled

    filter_status.set("Enabled" if filter_status.get() == "Disabled" else "Disabled")

    if filter_status.get() == "Enabled":
        result_toggled = [ip for ip in result if ip["country"] == filter_entry.get()]
        print(
            f"Filter by country {filter_entry.get()}: {result_toggled}, {list(map(lambda x: x['country'], result))}"
        )

    result, result_toggled = result_toggled, result
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, format_ip_result(result))


def save_button_clicked():
    global result

    try:
        with open(file_entry.get(), "w") as file:
            file.write(format_ip_result(result))

        show_popup(f"Saved to {file_entry.get()}")
    except Exception as e:
        show_popup(f"Error to {e}")


root = tk.Tk()
root.title("Scanner")

ips_label = tk.Label(root, text="Ips")
ips_label.grid(row=0, column=0, sticky="w")
ips_entry = tk.Entry(root)
ips_entry.grid(row=0, column=1, pady=5)

ports_label = tk.Label(root, text="Ports")
ports_label.grid(row=1, column=0, sticky="w")
ports_entry = tk.Entry(root)
ports_entry.grid(row=1, column=1, pady=5)

scan_button = tk.Button(root, text="Scan", command=scan_button_clicked)
scan_button.grid(row=2, column=0, columnspan=2, pady=10)

filter_label = tk.Label(root, text="Filter by country")
filter_label.grid(row=3, column=0, sticky="w")
filter_entry = tk.Entry(root)
filter_entry.grid(row=3, column=1, pady=5)

filter_status = tk.StringVar()
filter_status.set("Disabled")
toggle_button = tk.Button(root, text="Enable/Disable Filter", command=toggle_filter)
toggle_button.grid(row=3, column=2, columnspan=2, pady=10)

file_label = tk.Label(root, text="File to save")
file_label.grid(row=4, column=0, sticky="w")
file_entry = tk.Entry(root)
file_entry.grid(row=4, column=1, pady=5)

save_button = tk.Button(root, text="Save", command=save_button_clicked)
save_button.grid(row=4, column=2, columnspan=2, pady=10)

result_text = scrolledtext.ScrolledText(root, width=60, height=30)
result_text.grid(row=5, column=0, columnspan=3, pady=10)

root.mainloop()
