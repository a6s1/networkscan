# Network Scanner

This Python script scans a local network to identify active devices by their IP and MAC addresses, along with device names and vendor information.

## Features

- Scans a specified IP range on the local network.
- Retrieves the IP address and MAC address of each active device.
- Performs a reverse DNS lookup to get the device name.
- Uses the MacVendors API to get the vendor information based on the MAC address.

## Requirements

- Python 3.x
- `scapy` library
- `getmac` library
- `requests` library

## Installation

1. **Clone the Repository:**
   ```sh
   git clone https://github.com/a6s1/networkscan.git
   cd network-scanner


2. **Install Required Libraries:**
   ```sh
   pip install scapy getmac requests



3. **Usage:**
   ```sh
   python network_scanner.py



3. **Example Output:**
   ```sh
   Enter the IP range to scan (e.g., 192.168.1.0/24): 192.168.1.0/24
IP                  MAC Address             Device Name             Vendor
------------------------------------------------------------------------------------------
192.168.1.1         00:1A:2B:3C:4D:5E       router.home              Cisco Systems, Inc
192.168.1.100       00:1B:2C:3D:4E:5F       desktop.home             Dell Inc.
192.168.1.101       00:1C:2D:3E:4F:5G       laptop.home              Hewlett Packard

