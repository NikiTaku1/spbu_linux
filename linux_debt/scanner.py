import scapy.all as scapy
import subprocess

class NetworkScanner:
    def __init__(self):
        self.ip_count = {}
        self.sus_ips = set()
        self.block_ips = set()

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            ip_address = packet[scapy.IP].src
            packet_size = len(packet)

            if ip_address not in self.ip_count:
                self.ip_count[ip_address] = 0
            self.ip_count[ip_address] += packet_size

            if self.ip_count[ip_address] > 200:
                if ip_address not in self.sus_ips:
                    self.sus_ips.add(ip_address)
                    #Signal the GUI about suspicious IP (see interface.py for details)

            #Signal the GUI about a new packet (see interface.py)

    def start_monitoring(self):
        scapy.sniff(prn=self.packet_callback, store=0)

    def stop_monitoring(self):
        scapy.sniff(prn=lambda x: None, store=0, count=1)

    def block_ip(self, ip_address):
        self._run_iptables_command(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])

    def unblock_ip(self, ip_address):
        self._run_iptables_command(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"])

    def _run_iptables_command(self, command):
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            print(f"IPTables command '{command}' successful: {result.stdout}")
        except subprocess.CalledProcessError as e:
            print(f"Error executing IPTables command '{command}': {e.stderr}")