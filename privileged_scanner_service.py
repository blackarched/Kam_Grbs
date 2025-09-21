#!/usr/bin/env python3
"""
privileged_scanner_service.py

A small, privileged service that listens on a UNIX domain socket and performs
a limited ARP scan when requested.

Security model:
- Service runs as root (so it can perform ARP).
- Socket is created by systemd with group ownership set to the webserver group (e.g., www-data).
- On every accepted connection, the service checks the peer UID using SO_PEERCRED and
  only accepts requests from specific allowed UIDs (e.g., the webserver user).
- Incoming request is JSON: {"target_cidr": "192.168.1.0/24", "interface": "eth0"}
- The service validates inputs (CIDR and interface) before scanning.
- Response is a JSON array of discovered hosts or [{"error": "..."}].

NOTE: This minimal service expects 'scapy' installed for ARP scanning. If scapy is
not available the service returns an error instructing to install it.
"""

import argparse
import os
import json
import socket
import struct
import sys
import ipaddress
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Allowed caller UIDs (set at runtime or hard-coded). We'll default to allow www-data (33) and root (0).
DEFAULT_ALLOWED_UIDS = {0, 33}  # 0=root, 33=www-data (Debian/Ubuntu). Adjust for your environment.

# Timeout for a client connection (seconds)
CONN_TIMEOUT = 10


def get_peer_credentials(conn: socket.socket):
    """
    Return (pid, uid, gid) of the peer on Linux using SO_PEERCRED.
    """
    # SO_PEERCRED returns struct: pid_t pid; uid_t uid; gid_t gid;
    ucred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', ucred)
    return pid, uid, gid


def perform_arp_scan(target_cidr: str, interface: str) -> List[Dict]:
    """
    Perform ARP scan using scapy. Return list of {'ip':..., 'mac':..., 'interface':...}
    Raises ValueError on invalid inputs, or RuntimeError on operational errors.
    """
    # Validate CIDR
    try:
        network = ipaddress.ip_network(target_cidr, strict=False)
    except Exception as e:
        raise ValueError("Invalid target_cidr") from e

    # Validate interface exists (Linux)
    if not os.path.exists(f"/sys/class/net/{interface}"):
        raise ValueError("Invalid interface")

    # Try using scapy for ARP
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        # Use the string network (e.g., '192.168.1.0/24') as pdst
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        ans, _ = srp(packet, timeout=2, iface=interface, verbose=False)
        results = []
        for snd, rcv in ans:
            results.append({
                "ip": rcv.psrc,
                "mac": rcv.hwsrc,
                "interface": interface
            })
        return results
    except Exception as e:
        logging.exception("ARP scan failed (scapy may be missing or permissions issue)")
        raise RuntimeError("scapy not available or ARP scan failed") from e


def handle_client(conn: socket.socket, addr, allowed_uids):
    """
    Read JSON request from conn, validate, run scan, and send JSON response.
    """
    try:
        conn.settimeout(CONN_TIMEOUT)
        pid, uid, gid = get_peer_credentials(conn)
        logging.info("Connection from pid=%s uid=%s gid=%s", pid, uid, gid)
        if uid not in allowed_uids:
            logging.warning("Rejecting connection from unauthorized UID: %s", uid)
            resp = [{"error": "unauthorized"}]
            conn.sendall(json.dumps(resp).encode('utf-8'))
            return

        # Read data until EOF
        data = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            # very simple safety: limit request size
            if len(data) > 64 * 1024:
                conn.sendall(json.dumps([{"error": "request too large"}]).encode('utf-8'))
                return

        if not data:
            conn.sendall(json.dumps([{"error": "empty request"}]).encode('utf-8'))
            return

        try:
            req = json.loads(data.decode('utf-8'))
        except Exception:
            conn.sendall(json.dumps([{"error": "invalid json"}]).encode('utf-8'))
            return

        target_cidr = req.get('target_cidr')
        interface = req.get('interface')
        if not target_cidr or not interface:
            conn.sendall(json.dumps([{"error": "target_cidr and interface required"}]).encode('utf-8'))
            return

        # perform scan
        try:
            results = perform_arp_scan(target_cidr, interface)
            conn.sendall(json.dumps(results).encode('utf-8'))
        except ValueError as ve:
            conn.sendall(json.dumps([{"error": str(ve)}]).encode('utf-8'))
        except RuntimeError as re:
            conn.sendall(json.dumps([{"error": str(re)}]).encode('utf-8'))
        except Exception:
            conn.sendall(json.dumps([{"error": "internal error"}]).encode('utf-8'))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run_socket_server(socket_path: str, allowed_uids):
    # If systemd already created the socket, do not create; connect to the existing FD.
    # But for simplicity we'll create & bind only if socket doesn't exist.
    if os.path.exists(socket_path):
        # Ensure that if socket exists but not a socket file, we fail
        try:
            st = os.stat(socket_path)
            if not stat.S_ISSOCK(st.st_mode):
                logging.error("%s exists but is not a socket", socket_path)
                sys.exit(1)
        except Exception:
            pass

    # Create UNIX domain socket and listen
    serv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Ensure the socket file (if created) has restrictive permissions; systemd typically handles this.
    try:
        serv.bind(socket_path)
    except OSError as e:
        logging.error("Failed to bind to socket %s: %s", socket_path, e)
        sys.exit(1)

    # Set tight permissions on the socket file
    os.chmod(socket_path, 0o660)
    serv.listen(5)
    logging.info("Privileged scanner service listening on %s", socket_path)

    try:
        while True:
            conn, addr = serv.accept()
            # Handle in-process (sequential) - simple and easier to audit.
            try:
                handle_client(conn, addr, allowed_uids)
            except Exception:
                logging.exception("Error handling client")
    finally:
        try:
            serv.close()
        except Exception:
            pass
        try:
            os.remove(socket_path)
        except Exception:
            pass


def parse_args():
    parser = argparse.ArgumentParser(description="Privileged scanner service (socket)")
    parser.add_argument('--socket', required=True, help="Path to UNIX domain socket (e.g., /run/priv_scanner.sock)")
    parser.add_argument('--allow-uids', help="Comma-separated list of allowed caller UIDs (e.g., 0,33)", default="")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    allowed = set(DEFAULT_ALLOWED_UIDS)
    if args.allow_uids:
        try:
            extras = {int(x.strip()) for x in args.allow_uids.split(',') if x.strip()}
            allowed.update(extras)
        except Exception:
            logging.error("Invalid --allow-uids value, must be comma-separated ints")
            sys.exit(1)
    logging.info("Allowed caller UIDs: %s", allowed)
    run_socket_server(args.socket, allowed)