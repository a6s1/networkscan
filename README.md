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



4. **Example Output:**
   ```css
   Enter the IP range to scan (e.g., 192.168.1.0/24): 192.168.1.0/24


