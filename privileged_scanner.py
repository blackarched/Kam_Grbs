#!/usr/bin/env python3
"""
Privileged Scanner Service for NeonHack.

This script performs tasks that require root privileges (specifically, ARP scans)
and is designed to be called securely by the main, non-privileged web application.

It accepts command-line arguments and outputs results in JSON format to stdout.
This isolates root permissions to the smallest possible surface area.
"""

import sys
import json
import argparse
import logging
from scapy.all import ARP, Ether, srp

# Configure basic logging to stderr for debugging purposes
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - (Privileged Service) - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stderr
)

def scan_network(target_cidr, interface):
    """
    Performs an ARP scan using Scapy and returns a list of found devices.
    """
    logging.info(f"Initiating ARP scan on {target_cidr} via {interface}.")
    try:
        arp_request = ARP(pdst=target_cidr)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

        # srp returns a tuple of (sent_packets, received_answers)
        result = srp(packet, timeout=3, iface=interface, verbose=0)[0]

        devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
        logging.info(f"Scan complete. Found {len(devices)} device(s).")
        return devices
    except Exception as e:
        logging.error(f"Failed to execute ARP scan: {e}")
        # Return an empty list in case of an error
        return []

def main():
    """
    Main function to parse arguments, run the scan, and print JSON results.
    """
    parser = argparse.ArgumentParser(description="Privileged ARP Scanner Service.")
    parser.add_argument(
        '--target',
        required=True,
        help="The target network in CIDR notation (e.g., 192.168.1.0/24)."
    )
    parser.add_argument(
        '--interface',
        required=True,
        help="The network interface to use for the scan."
    )
    args = parser.parse_args()

    # Perform the scan
    devices_found = scan_network(args.target, args.interface)

    # Output the results as a JSON string to standard output.
    # The main web app will read this output.
    print(json.dumps(devices_found))

if __name__ == '__main__':
    # Ensure the script is run with root privileges
    import os
    if os.geteuid() != 0:
        logging.error("This script requires root privileges to function.")
        sys.exit(json.dumps([{"error": "Root privileges are required for ARP scans."}]))
    
    main()
