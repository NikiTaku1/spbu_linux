import psutil
import time
import logging
import json
from tabulate import tabulate

logging.basicConfig(filename="system_audit.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - Process: %(message)s")


def escape_string_for_json(s):
    """Escapes a string for safe inclusion in JSON."""
    try:
        return json.dumps(s)
    except (TypeError, ValueError):
        return json.dumps(str(s))


def format_and_log_process(process_info):
    """Robustly formats process info for JSON logging, handling various errors."""
    try:
        cmdline = process_info.get('cmdline', [])
        if not cmdline:
            cmdline = []
        
        escaped_cmdline = escape_string_for_json(' '.join(cmdline))
        if "firefox" in cmdline:
            process_info["cmdline"] = []
        process_info["cmdline"] = escaped_cmdline.replace("\"", "")
        logging.info(json.dumps(process_info))
        return process_info
    except (TypeError, ValueError, AttributeError, OverflowError) as e:
        logging.error(f"Error formatting/logging process info: {e}, process_info: {process_info}")
        return None


def monitor_processes():
    count = 0
    headers = ["PID", "Name", "Username", "Command Line"]
    while True:
        process_data = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                process_info = proc.as_dict(attrs=['pid', 'name', 'username', 'cmdline'])
                formatted_info = format_and_log_process(process_info)
                if formatted_info:
                    cmdline_str = formatted_info['cmdline']
                    process_data.append([formatted_info['pid'], formatted_info['name'], formatted_info['username'], cmdline_str])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError) as e:
                logging.warning(f"Error accessing process information: {e}")
                continue

        print("\033c")
        print(tabulate(process_data, headers=headers, tablefmt="plain"))
        count += 1
        time.sleep(20)
        print(f"Iteration: {count}")


if __name__ == "__main__":
    monitor_processes()
