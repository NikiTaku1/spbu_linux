import psutil
import time
import logging

logging.basicConfig(filename="system_audit.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def monitor_processes():
    count = 0
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                process_info = proc.as_dict(attrs=['pid', 'name', 'username', 'cmdline'])
                logging.info(f"Process: {process_info}")
            except:
                pass
        count+=1
        time.sleep(2)
        print(count)
        
if __name__ == "__main__":
    monitor_processes()
