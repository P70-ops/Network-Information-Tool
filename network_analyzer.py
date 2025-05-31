#!/usr/bin/env python3
"""
Complete Network Analyzer Pro
---------------------------
A comprehensive network diagnostic tool that provides:
- Interface details (IP, MAC, netmask)
- Routing tables
- ARP cache
- DNS configuration
- Gateway information
- WiFi signal strength
- Active connections
- Internet speed test
- Port scanning
- Ping testing
"""

import os
import re
import sys
import time
import socket
import platform
import subprocess
import threading
from datetime import datetime
from prettytable import PrettyTable

try:
    import netifaces
    import requests
    import speedtest
    from scapy.all import ARP, Ether, srp
except ImportError as e:
    print(f"Missing dependency: {e.name}. Install with: pip install {e.name}")
    sys.exit(1)

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class NetworkAnalyzerPro:
    def __init__(self):
        self.system = platform.system()
        self.colors = Colors()
        self.start_time = time.time()
        self.interface_details = {}
        self.routing_table = []
        self.arp_table = ""
        self.dns_info = ""
        self.gateway_info = {}
        self.external_ip = None
        self.wifi_info = {}
        self.active_connections = []
        self.speed_test_results = {}
        self.hostname = socket.gethostname()

    def collect_all_info(self):
        """Collect all network information with timing"""
        print(f"{self.colors.OKBLUE}Collecting network information...{self.colors.ENDC}")
        
        tasks = [
            ("System Info", self._get_system_info),
            ("Routing Table", self._get_routing_table),
            ("Interfaces", self._get_interface_details),
            ("ARP Table", self._get_arp_table),
            ("DNS Info", self._get_dns_info),
            ("Gateways", self._get_gateway_info),
            ("External IP", self._get_external_ip),
            ("WiFi Info", self._get_wifi_info),
            ("Active Connections", self._get_active_connections)
        ]
        
        for name, task in tasks:
            start = time.time()
            try:
                task()
                elapsed = time.time() - start
                print(f"{self.colors.OKGREEN}✓{self.colors.ENDC} {name.ljust(20)} {elapsed:.2f}s")
            except Exception as e:
                print(f"{self.colors.FAIL}✗{self.colors.ENDC} {name.ljust(20)} Error: {str(e)}")

    def _get_system_info(self):
        """Collect basic system information"""
        self.system_info = {
            "System": platform.system(),
            "Node": platform.node(),
            "Release": platform.release(),
            "Version": platform.version(),
            "Machine": platform.machine(),
            "Processor": platform.processor()
        }

    def _get_routing_table(self):
        """Get system routing table"""
        if self.system == "Windows":
            self.routing_table = self._get_windows_routing_table()
        elif self.system in ["Linux", "Darwin"]:
            self.routing_table = self._get_unix_routing_table()
        else:
            self.routing_table = {"error": "Unsupported OS"}

    def _get_windows_routing_table(self):
        """Windows-specific routing table"""
        try:
            result = subprocess.check_output("route print", shell=True).decode('utf-8', 'ignore')
            return self._parse_windows_route(result)
        except Exception as e:
            return {"error": str(e)}

    def _get_unix_routing_table(self):
        """Unix/Linux routing table"""
        try:
            result = subprocess.check_output("netstat -rn", shell=True).decode('utf-8', 'ignore')
            return self._parse_unix_route(result)
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _parse_windows_route(output):
        """Parse Windows route output"""
        routes = []
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith("0.0.0.0"):
                parts = re.split(r'\s+', line)
                if len(parts) >= 5:
                    routes.append({
                        "Destination": parts[0],
                        "Netmask": parts[1],
                        "Gateway": parts[2],
                        "Interface": parts[3],
                        "Metric": parts[4] if len(parts) > 4 else ""
                    })
        return routes

    @staticmethod
    def _parse_unix_route(output):
        """Parse Unix route output"""
        routes = []
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith("default") or line.startswith("0.0.0.0"):
                parts = re.split(r'\s+', line)
                if len(parts) >= 4:
                    routes.append({
                        "Destination": "default" if parts[0] == "default" else parts[0],
                        "Gateway": parts[1],
                        "Genmask": parts[2] if len(parts) > 2 else "",
                        "Flags": parts[3] if len(parts) > 3 else "",
                        "Interface": parts[5] if len(parts) > 5 else ""
                    })
            elif re.match(r'^\d+\.\d+\.\d+\.\d+', line):
                parts = re.split(r'\s+', line)
                if len(parts) >= 5:
                    routes.append({
                        "Destination": parts[0],
                        "Gateway": parts[1],
                        "Genmask": parts[2],
                        "Flags": parts[3],
                        "Interface": parts[5] if len(parts) > 5 else ""
                    })
        return routes

    def _get_interface_details(self):
        """Get detailed interface information"""
        self.interface_details = {}
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    self.interface_details[interface] = {
                        'IP': addrs[netifaces.AF_INET][0]['addr'],
                        'Netmask': addrs[netifaces.AF_INET][0]['netmask'],
                        'MAC': addrs[netifaces.AF_LINK][0]['addr'] if netifaces.AF_LINK in addrs else None,
                        'Broadcast': addrs[netifaces.AF_INET][0].get('broadcast', 'N/A')
                    }
            except (ValueError, KeyError):
                continue

    def _get_arp_table(self):
        """Get system ARP table"""
        try:
            if self.system == "Windows":
                self.arp_table = subprocess.check_output("arp -a", shell=True).decode('utf-8', 'ignore')
            else:
                self.arp_table = subprocess.check_output("arp -n", shell=True).decode('utf-8', 'ignore')
        except Exception as e:
            self.arp_table = f"Error getting ARP table: {str(e)}"

    def _get_dns_info(self):
        """Get DNS server information"""
        try:
            if self.system == "Windows":
                self.dns_info = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', 'ignore')
            else:
                self.dns_info = subprocess.check_output("cat /etc/resolv.conf", shell=True).decode('utf-8', 'ignore')
        except Exception as e:
            self.dns_info = f"Error getting DNS info: {str(e)}"

    def _get_gateway_info(self):
        """Get gateway information"""
        self.gateway_info = netifaces.gateways().get('default', {})

    def _get_external_ip(self):
        """Get public IP address"""
        try:
            self.external_ip = requests.get('https://api.ipify.org').text
        except:
            try:
                self.external_ip = requests.get('https://ident.me').text
            except Exception as e:
                self.external_ip = f"Error: {str(e)}"

    def _get_wifi_info(self):
        """Get WiFi signal information (Linux/macOS)"""
        if self.system == "Linux":
            try:
                result = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT).decode()
                essid = re.search(r'ESSID:"(.*?)"', result)
                quality = re.search(r'Link Quality=(\d+/\d+)', result)
                signal = re.search(r'Signal level=(-?\d+) dBm', result)
                
                self.wifi_info = {
                    'SSID': essid.group(1) if essid else 'N/A',
                    'Quality': quality.group(1) if quality else 'N/A',
                    'Signal': f"{signal.group(1)} dBm" if signal else 'N/A'
                }
            except:
                self.wifi_info = {'Error': 'Could not get WiFi info'}
        elif self.system == "Darwin":
            try:
                result = subprocess.check_output(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"]).decode()
                self.wifi_info = {
                    'SSID': re.search(r'SSID: (.+)', result).group(1).strip() if re.search(r'SSID: (.+)', result) else 'N/A',
                    'RSSI': re.search(r'agrCtlRSSI: (.+)', result).group(1).strip() if re.search(r'agrCtlRSSI: (.+)', result) else 'N/A',
                    'Noise': re.search(r'agrCtlNoise: (.+)', result).group(1).strip() if re.search(r'agrCtlNoise: (.+)', result) else 'N/A'
                }
            except:
                self.wifi_info = {'Error': 'Could not get WiFi info'}

    def _get_active_connections(self):
        """Get active network connections"""
        try:
            if self.system == "Windows":
                self.active_connections = subprocess.check_output("netstat -ano", shell=True).decode('utf-8', 'ignore')
            else:
                self.active_connections = subprocess.check_output("netstat -tulnp", shell=True).decode('utf-8', 'ignore')
        except Exception as e:
            self.active_connections = f"Error getting connections: {str(e)}"

    def run_speed_test(self):
        """Run internet speed test"""
        print(f"{self.colors.OKBLUE}Running speed test...{self.colors.ENDC}")
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            
            download_thread = threading.Thread(target=st.download)
            upload_thread = threading.Thread(target=st.upload)
            
            download_thread.start()
            upload_thread.start()
            
            print(f"{self.colors.OKBLUE}Testing download speed...{self.colors.ENDC}")
            download_thread.join()
            
            print(f"{self.colors.OKBLUE}Testing upload speed...{self.colors.ENDC}")
            upload_thread.join()
            
            self.speed_test_results = {
                'Download': f"{st.results.download / 1_000_000:.2f} Mbps",
                'Upload': f"{st.results.upload / 1_000_000:.2f} Mbps",
                'Ping': f"{st.results.ping:.2f} ms",
                'Server': st.results.server['name']
            }
        except Exception as e:
            self.speed_test_results = {'Error': str(e)}

    def port_scan(self, target, ports="1-1024", timeout=1):
        """Basic port scanner"""
        print(f"{self.colors.OKBLUE}Scanning {target} ports {ports}...{self.colors.ENDC}")
        try:
            start_port, end_port = map(int, ports.split('-'))
            open_ports = []
            
            def scan_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(timeout)
                        result = s.connect_ex((target, port))
                        if result == 0:
                            open_ports.append(port)
                except:
                    pass
            
            threads = []
            for port in range(start_port, end_port + 1):
                t = threading.Thread(target=scan_port, args=(port,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            return open_ports
        except Exception as e:
            return f"Scan error: {str(e)}"

    def ping_test(self, target, count=4):
        """Ping a network target"""
        try:
            param = "-n" if self.system == "Windows" else "-c"
            command = ["ping", param, str(count), target]
            return subprocess.call(command) == 0
        except:
            return False

    def display_all_info(self):
        """Display all collected information with sections"""
        print(f"\n{self.colors.HEADER}{'='*80}{self.colors.ENDC}")
        print(f"{self.colors.BOLD}{'NETWORK ANALYZER PRO'.center(80)}{self.colors.ENDC}")
        print(f"{self.colors.HEADER}{'='*80}{self.colors.ENDC}")
        
        sections = [
            ("SYSTEM INFORMATION", self._display_system_info),
            ("NETWORK INTERFACES", self._display_interfaces),
            ("ROUTING TABLE", self._display_routing_table),
            ("DEFAULT GATEWAYS", self._display_gateways),
            ("ARP TABLE", self._display_arp_table),
            ("DNS INFORMATION", self._display_dns_info),
            ("EXTERNAL IP", self._display_external_ip),
            ("WIFI INFORMATION", self._display_wifi_info),
            ("ACTIVE CONNECTIONS", self._display_active_connections),
            ("SPEED TEST", self._display_speed_test)
        ]
        
        for title, display_func in sections:
            print(f"\n{self.colors.OKBLUE}{'-'*80}{self.colors.ENDC}")
            print(f"{self.colors.BOLD}{title.center(80)}{self.colors.ENDC}")
            print(f"{self.colors.OKBLUE}{'-'*80}{self.colors.ENDC}")
            display_func()
        
        elapsed = time.time() - self.start_time
        print(f"\n{self.colors.OKGREEN}Scan completed in {elapsed:.2f} seconds{self.colors.ENDC}")

    def _display_system_info(self):
        """Display system information"""
        table = PrettyTable()
        table.field_names = [f"{self.colors.BOLD}Property{self.colors.ENDC}", f"{self.colors.BOLD}Value{self.colors.ENDC}"]
        table.align = "l"
        
        for key, value in self.system_info.items():
            table.add_row([
                f"{self.colors.OKBLUE}{key}{self.colors.ENDC}",
                f"{self.colors.OKGREEN}{value}{self.colors.ENDC}"
            ])
        
        print(table)

    def _display_interfaces(self):
        """Display network interfaces"""
        if not self.interface_details:
            print(f"{self.colors.WARNING}No interface information available{self.colors.ENDC}")
            return

        table = PrettyTable()
        table.field_names = [
            f"{self.colors.BOLD}Interface{self.colors.ENDC}",
            f"{self.colors.BOLD}IP Address{self.colors.ENDC}",
            f"{self.colors.BOLD}Netmask{self.colors.ENDC}",
            f"{self.colors.BOLD}MAC Address{self.colors.ENDC}",
            f"{self.colors.BOLD}Broadcast{self.colors.ENDC}"
        ]
        table.align = "l"
        
        for iface, details in self.interface_details.items():
            table.add_row([
                f"{self.colors.OKBLUE}{iface}{self.colors.ENDC}",
                details['IP'],
                details['Netmask'],
                details['MAC'] or "N/A",
                details.get('Broadcast', 'N/A')
            ])
        
        print(table)

    def _display_routing_table(self):
        """Display routing table"""
        if isinstance(self.routing_table, dict) and 'error' in self.routing_table:
            print(f"{self.colors.FAIL}{self.routing_table['error']}{self.colors.ENDC}")
            return

        table = PrettyTable()
        table.field_names = [
            f"{self.colors.BOLD}Destination{self.colors.ENDC}",
            f"{self.colors.BOLD}Gateway{self.colors.ENDC}",
            f"{self.colors.BOLD}Netmask{self.colors.ENDC}",
            f"{self.colors.BOLD}Interface{self.colors.ENDC}",
            f"{self.colors.BOLD}Metric/Flags{self.colors.ENDC}"
        ]
        table.align = "l"
        
        for route in self.routing_table:
            table.add_row([
                route.get("Destination", "N/A"),
                route.get("Gateway", "N/A"),
                route.get("Netmask", route.get("Genmask", "N/A")),
                route.get("Interface", "N/A"),
                route.get("Metric", route.get("Flags", "N/A"))
            ])
        
        print(table)

    def _display_gateways(self):
        """Display gateway information"""
        if not self.gateway_info:
            print(f"{self.colors.WARNING}No gateway information available{self.colors.ENDC}")
            return

        table = PrettyTable()
        table.field_names = [
            f"{self.colors.BOLD}Type{self.colors.ENDC}",
            f"{self.colors.BOLD}Gateway IP{self.colors.ENDC}",
            f"{self.colors.BOLD}Interface{self.colors.ENDC}"
        ]
        table.align = "l"
        
        for family, gateway_info in self.gateway_info.items():
            if len(gateway_info) >= 2:
                table.add_row([
                    f"{self.colors.OKBLUE}{'IPv4' if family == netifaces.AF_INET else 'IPv6'}{self.colors.ENDC}",
                    gateway_info[0],
                    gateway_info[1]
                ])
        
        print(table)

    def _display_arp_table(self):
        """Display ARP table"""
        print(self.arp_table)

    def _display_dns_info(self):
        """Display DNS information"""
        print(self.dns_info)

    def _display_external_ip(self):
        """Display external IP"""
        print(f"Your public IP address: {self.colors.OKGREEN}{self.external_ip}{self.colors.ENDC}")

    def _display_wifi_info(self):
        """Display WiFi information"""
        if not self.wifi_info:
            print(f"{self.colors.WARNING}No WiFi information available{self.colors.ENDC}")
            return

        table = PrettyTable()
        table.field_names = [f"{self.colors.BOLD}Property{self.colors.ENDC}", f"{self.colors.BOLD}Value{self.colors.ENDC}"]
        table.align = "l"
        
        for key, value in self.wifi_info.items():
            table.add_row([
                f"{self.colors.OKBLUE}{key}{self.colors.ENDC}",
                f"{self.colors.OKGREEN}{value}{self.colors.ENDC}"
            ])
        
        print(table)

    def _display_active_connections(self):
        """Display active connections"""
        print(self.active_connections)

    def _display_speed_test(self):
        """Display speed test results"""
        if not self.speed_test_results:
            print(f"{self.colors.WARNING}Speed test not run yet. Use run_speed_test() first.{self.colors.ENDC}")
            return
        
        if 'Error' in self.speed_test_results:
            print(f"{self.colors.FAIL}Error: {self.speed_test_results['Error']}{self.colors.ENDC}")
            return
        
        table = PrettyTable()
        table.field_names = [f"{self.colors.BOLD}Metric{self.colors.ENDC}", f"{self.colors.BOLD}Value{self.colors.ENDC}"]
        table.align = "l"
        
        for metric, value in self.speed_test_results.items():
            table.add_row([
                f"{self.colors.OKBLUE}{metric}{self.colors.ENDC}",
                f"{self.colors.OKGREEN}{value}{self.colors.ENDC}"
            ])
        
        print(table)

def main():
    analyzer = NetworkAnalyzerPro()
    
    # Collect basic info
    analyzer.collect_all_info()
    
    # Run speed test
    analyzer.run_speed_test()
    
    # Display everything
    analyzer.display_all_info()
    
    # Example of additional features
    if input("\nPerform quick port scan on your gateway? (y/n): ").lower() == 'y':
        gateway = analyzer.gateway_info.get(netifaces.AF_INET, [['']])[0]
        if gateway:
            open_ports = analyzer.port_scan(gateway, "80-443")
            print(f"\nOpen ports on {gateway}: {open_ports or 'None'}")
    
    if input("\nPing test to 8.8.8.8 (Google DNS)? (y/n): ").lower() == 'y':
        success = analyzer.ping_test("8.8.8.8")
        print(f"\nPing {'successful' if success else 'failed'}")

if __name__ == "__main__":
    main()
