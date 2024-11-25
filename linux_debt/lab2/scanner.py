import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP
import requests
import ipaddress

conf.verb = False


class IPInfo:
    ip: str
    services: dict
    mac: str
    country: str
    regionName: str
    city: str
    lat: float
    lon: float
    org: str


def format_ip_result(results: list) -> str:
    ips_with_open_ports = reduce(
        lambda acc, x: acc + 1 if len(x["services"]) > 0 else acc, results, 0
    )

    services_stat = {}

    for host in results:
        for service in host["services"].values():
            if service not in services_stat:
                services_stat[service] = 0
            services_stat[service] += 1

    format_stat = "".join(
        [f"{service}: {count}\n" for service, count in services_stat.items()]
    )

    return (
        f"Hosts with opened ports: {ips_with_open_ports}\nServices count:\n{format_stat}\n"
        + "\n".join(
            [
                "".join(
                    [
                        f"IP: '{res['ip']}'\n",
                        f"MAC: '{res['mac']}'\n",
                        f"Country: '{res['country']}'\n",
                        f"Region: '{res['regionName']}'\n",
                        f"City: '{res['city']}'\n",
                        f"Coordinates: '{res['lat']},{res['lon']}'\n",
                        f"Org: '{res['org']}'\n",
                        "".join(
                            [
                                f"Port: {item[0]}; service: {item[1]}\n"
                                for item in res["services"].items()
                            ]
                        ),
                    ]
                )
                for res in results
            ]
        )
    )


def parse_ints(ips: str, expand) -> set:
    ips_list = ips.split(",")
    parsed = set()

    for ip in ips_list:
        if len(ip.split("-")) != 1:
            parsed = parsed.union(expand(ip))
        else:
            parsed.add(ip)
    return parsed


def expand_ip_range(ip_range: str) -> set:
    start_ip, end_ip = map(ipaddress.IPv4Address, ip_range.split("-"))
    ip_set = set(
        str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)
    )
    return ip_set


def expand_port_range(port_range: str) -> set:
    start_port, end_port = map(int, port_range.split("-"))
    port_set = set(str(port) for port in range(start_port, end_port + 1))
    return port_set


def get_mac(ip: str) -> str:
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans = srp(
            packet,
            timeout=2,
            retry=1,
        )

        for _, received in ans:
            if received.hwsrc:
                return received.hwsrc

        return ""
    except Exception as e:
        print(f"err: {e}")
        return ""


def get_services(ip: str, ports: set) -> dict:
    open_ports = {}

    for port in ports:
        try:
            port = int(port)
            print(f"Scan port {port}")
            packet = IP(dst=ip) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=2)

            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                open_ports[port] = socket.getservbyport(port)
        except Exception as e:
            print("err: ", e)

    return open_ports


def get_ip_info(ip: str) -> IPInfo:
    return requests.get(
        f"http://ip-api.com/json/{ip}?fields=country,regionName,city,lat,lon,org"
    ).json()


def scan_network(ip_adresses: set, ports: set) -> list:
    print(ip_adresses, ports)

    ips_info = []

    for ip_address in ip_adresses:
        print(f"Scan {ip_address}")
        ip_info = get_ip_info(ip_address)
        ip_info["ip"] = ip_address
        ip_info["services"] = get_services(ip_address, ports)
        ip_info["mac"] = get_mac(ip_address)
        ips_info.append(ip_info)

    return ips_info
