
from colorama import Fore, init
import colorama
import pyfiglet
import os
import time
import subprocess
from scapy.all import *

if os.name == 'nt':
    os.system('cls')
else:
    os.system('clear')
print(colorama.Fore.RED)
pyfiglet.print_figlet("Asylum")
print(colorama.Fore.GREEN)


def scan_wifi():
    print("Scanning for WiFi networks...")
    print(colorama.Fore.RESET)    

    process = subprocess.Popen(['iwlist', 'wlan0', 'scan'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    output, error = process.communicate()
    
    
    networks = []
    current_network = {}
    for line in output.decode('utf-8').split('\n'):
        line = line.strip()
        if line.startswith('Cell'):
            if current_network:
                networks.append(current_network)
            current_network = {}
        elif line.startswith('ESSID'):
            current_network['SSID'] = line.split('"')[1]
        elif line.startswith('Protocol'):
            current_network['Protocol'] = line.split(':')[1]
        elif line.startswith('Mode'):
            current_network['Mode'] = line.split(':')[1]
        elif line.startswith('Frequency'):
            current_network['Frequency'] = line.split(':')[1].split(' ')[0]
        elif line.startswith('Encryption key'):
            current_network['Encryption'] = line.split(':')[1]
        elif line.startswith('Quality'):
            current_network['Quality'] = line.split('=')[1].split(' ')[0]
        elif line.startswith('Signal level'):
            current_network['Signal'] = line.split('=')[1]
    
    if current_network:
        networks.append(current_network)
    
    return networks

def get_mac_addresses():
    print(colorama.Fore.GREEN)
    print("Scanning for MAC addresses...")
    print(colorama.Fore.RESET)
    packets = sniff(iface="wlan0", timeout=10)
    
    mac_addresses = set()
    for packet in packets:
        if packet.haslayer(Dot11):
            mac = packet.addr2
            if mac:
                mac_addresses.add(mac)
    
    return list(mac_addresses)

if __name__ == "__main__":
    networks = scan_wifi()
    mac_addresses = get_mac_addresses()
    
    print("\nWiFi Networks:")
    for network in networks:
        print(f"SSID: {network.get('SSID', 'N/A')}")
        print(f"Protocol: {network.get('Protocol', 'N/A')}")
        print(f"Mode: {network.get('Mode', 'N/A')}")
        print(f"Frequency: {network.get('Frequency', 'N/A')}")
        print(f"Encryption: {network.get('Encryption', 'N/A')}")
        print(f"Quality: {network.get('Quality', 'N/A')}")
        print(f"Signal: {network.get('Signal', 'N/A')}")
        print("---")
    
    print("\nMAC Addresses:")
    for mac in mac_addresses:
        print(mac)
