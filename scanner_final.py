"""
Refactored Scanner Tools Library for NeonHack (v5.0 - Hardened)

This module contains all non-privileged scanning and attack logic.
It provides secure wrappers for command-line tools and external services.
"""
import logging
import subprocess
import tempfile
import os
import socket
import json
from pymetasploit3.msfrpc import MsfRpcClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')

def test_connectivity(ip: str, protocol: str):
    """
    Performs a simple TCP connection test with a 3-second timeout.
    """
    PORT_MAP = {'ssh': 22, 'ftp': 21, 'http': 80}
    port = PORT_MAP.get(protocol.lower())
    if not port:
        return {"status": "error", "message": f"Unsupported protocol: {protocol}"}
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            return {"status": "success", "message": f"Connected to {ip} on port {port} ({protocol})."}
    except socket.timeout:
        return {"status": "error", "message": f"Connection to {ip} on port {port} timed out."}
    except Exception as e:
        return {"status": "error", "message": f"Failed to connect to {ip} on port {port}: {e}"}

def hydra_attack(ip, protocol, username_wordlist, password_wordlist, timeout=300):
    """
    Performs a Hydra attack with a timeout and guaranteed temp file cleanup.
    """
    user_file_path, pass_file_path = None, None
    try:
        users = [user for user in username_wordlist.splitlines() if user]
        passwords = [pw for pw in password_wordlist.splitlines() if pw]

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as user_file, \
             tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as pass_file:
            user_file.write('\n'.join(users))
            user_file_path = user_file.name
            pass_file.write('\n'.join(passwords))
            pass_file_path = pass_file.name
        
        command = ['hydra', '-L', user_file_path, '-P', pass_file_path, f'{protocol}://{ip}']
        logging.info(f"Executing command with {timeout}s timeout: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout
        )
        
        if result.returncode == 0 and result.stdout:
            return result.stdout
        elif result.stderr:
            return f"Hydra Error:\n{result.stderr}"
        else:
            return "Hydra ran successfully but found no credentials."
            
    except FileNotFoundError:
        return "Error: 'hydra' command not found. Please ensure it is installed and in your PATH."
    except subprocess.TimeoutExpired:
        logging.warning(f"Hydra attack against {ip} timed out after {timeout} seconds.")
        return f"Error: Hydra process timed out after {timeout} seconds."
    except Exception as e:
        return f"An unexpected error occurred during the Hydra attack: {e}"
    finally:
        # Guaranteed cleanup
        if user_file_path and os.path.exists(user_file_path):
            os.remove(user_file_path)
        if pass_file_path and os.path.exists(pass_file_path):
            os.remove(pass_file_path)

def execute_exploit(ip, module_name, msf_password, timeout=60):
    """
    Connects to Metasploit RPC and executes a module with a session polling timeout.
    """
    try:
        client = MsfRpcClient(msf_password, ssl=False)
        module_type, module_path = module_name.split('/', 1)
        exploit = client.modules.use(module_type, module_path)
        exploit['RHOSTS'] = ip

        logging.info(f"Executing module {exploit.fullname} on {ip}...")
        job_info = exploit.execute()

        job_id = job_info.get('job_id')
        if job_id is None:
            return {"error": "Failed to start exploit job.", "details": job_info}
            
        logging.info(f"Exploit started as job ID: {job_id}. Polling for session for {timeout}s...")
        
        for _ in range(timeout):
            sessions = client.sessions.list
            for session_id, session_data in sessions.items():
                if session_data.get('via_exploit') == exploit.fullname and session_data.get('session_host') == ip:
                    logging.info(f"SUCCESS! Session {session_id} opened.")
                    return {"status": "success", "session_id": session_id, "details": session_data}
            subprocess.run(['sleep', '1'], check=False)
        
        return {"status": "pending", "message": f"Exploit job started, but no session was created within {timeout} seconds."}

    except Exception as e:
        logging.error(f"Metasploit integration error: {e}")
        return {"error": f"Failed to connect or run exploit. Is msfrpcd running correctly? Details: {e}"}