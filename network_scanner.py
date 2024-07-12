from scapy.all import ARP, Ether, srp, conf
from getmac import get_mac_address
import ipaddress
import socket
import requests

# Function to get vendor information from MAC address
def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except Exception:
        return "Unknown Vendor"

# Function to get device name using reverse DNS lookup
def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Device"

def scan_network(ip_range):
    devices = []
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    # Create an Ethernet frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the ARP request and Ethernet frame
    arp_request_broadcast = broadcast / arp_request
    # Send the packet and capture the responses
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        device_info = {
            'ip': ip,
            'mac': mac,
            'name': get_device_name(ip),
            'vendor': get_vendor(mac)
        }
        devices.append(device_info)
    
    return devices

def generate_ip_range(subnet):
    return [str(ip) for ip in ipaddress.IPv4Network(subnet)]

def print_devices(devices):
    print("IP\t\t\tMAC Address\t\t\tDevice Name\t\t\tVendor\n------------------------------------------------------------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['name']}\t\t{device['vendor']}")

if __name__ == "__main__":
    ip_range_input = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    conf.verb = 0  # Disable verbose mode in scapy
    scanned_devices = scan_network(ip_range_input)
    print_devices(scanned_devices)
