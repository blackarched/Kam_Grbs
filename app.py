"""
Secure Flask Web Server for NeonHack (v5.0 - Hardened)

This application serves the frontend and provides a secure API for scanning tasks.
It features API key authentication, persistent job management via SQLite,
server-side secrets, and strict input validation.
"""
import os
import re
import ipaddress
import sqlite3
import logging
import socket
import secrets
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, jsonify, render_template, request, g

# Import the refactored, non-privileged scanner tools
import scanner_final as scanner

# --- 1. Configuration ---
class Config:
    # SECURITY: Generate a secure key and set it here or as an environment variable.
    # Run `python -c 'import secrets; print(secrets.token_hex(32))'` to generate one.
    SECRET_API_KEY = os.environ.get("NEONHACK_API_KEY", "change-this-insecure-default-key")
    
    # SECURITY: Set the MSF RPC password here or as an environment variable.
    # This is NEVER accepted from the client.
    MSF_PASSWORD = os.environ.get("MSF_PASSWORD", "msf_rpc_password")

    DATABASE_PATH = "jobs.db"
    PRIV_SOCKET_PATH = "/tmp/priv_scanner.sock"
    
    # SECURITY: Whitelist of allowed Metasploit modules to prevent abuse.
    WHITELISTED_MODULES = {
        "exploit/unix/ftp/vsftpd_234_backdoor",
        "auxiliary/scanner/portscan/tcp",
    }
    
    # PERFORMANCE: Set timeouts and resource limits for tasks.
    HYDRA_TIMEOUT_SECONDS = 300  # 5 minutes
    MSF_SESSION_TIMEOUT_SECONDS = 60 # 1 minute

# --- 2. Application and Database Initialization ---
app = Flask(__name__, template_folder='.')
app.config.from_object(Config)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE_PATH'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- 3. Custom Error Handling ---
class AppError(Exception):
    def __init__(self, message, status_code=400, details=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details

@app.errorhandler(AppError)
def handle_app_error(error):
    response = {"error": error.message}
    if error.details:
        response["details"] = error.details
    return jsonify(response), error.status_code

# --- 4. Authentication Decorator ---
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not secrets.compare_digest(api_key, app.config['SECRET_API_KEY']):
            raise AppError("Unauthorized: Invalid or missing API Key", 401)
        g.api_key_identifier = api_key[:8] # For logging
        return f(*args, **kwargs)
    return decorated_function

# --- 5. Input Validation ---
def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        raise AppError("Invalid IP address format")

def validate_cidr(cidr_str):
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return cidr_str
    except ValueError:
        raise AppError("Invalid CIDR network format")

def validate_interface(if_str):
    if not re.match(r'^[a-zA-Z0-9]{1,16}$', if_str):
        raise AppError("Invalid network interface name")
    return if_str

def validate_module(mod_str):
    if mod_str not in app.config['WHITELISTED_MODULES']:
        raise AppError(f"Disallowed or unknown module. Please use one of the whitelisted modules.")
    return mod_str

# --- 6. Background Task Execution ---
executor = ThreadPoolExecutor(max_workers=4)

def run_hydra_in_background(job_id, ip, protocol, user_wl, pass_wl):
    result = scanner.hydra_attack(
        ip, protocol, user_wl, pass_wl,
        timeout=app.config['HYDRA_TIMEOUT_SECONDS']
    )
    with app.app_context():
        db = sqlite3.connect(app.config['DATABASE_PATH'])
        db.execute(
            "UPDATE jobs SET status = ?, result = ?, updated_at = ? WHERE id = ?",
            ("done", result, datetime.utcnow().isoformat(), job_id)
        )
        db.commit()
        db.close()

def run_exploit_in_background(job_id, ip, module):
    result = scanner.execute_exploit(
        ip, module, app.config['MSF_PASSWORD'],
        timeout=app.config['MSF_SESSION_TIMEOUT_SECONDS']
    )
    with app.app_context():
        db = sqlite3.connect(app.config['DATABASE_PATH'])
        db.execute(
            "UPDATE jobs SET status = ?, result = ?, updated_at = ? WHERE id = ?",
            ("done", json.dumps(result), datetime.utcnow().isoformat(), job_id)
        )
        db.commit()
        db.close()

# --- 7. API Endpoints ---
@app.route('/')
def index():
    return render_template('kam_grbs5.html')

@app.route('/api/scan_network', methods=['POST'])
@require_api_key
def api_scan_network():
    data = request.get_json()
    if not data: raise AppError("Invalid request: No JSON body")
    
    target_cidr = validate_cidr(data.get('target_cidr'))
    interface = validate_interface(data.get('interface'))
    
    logging.info(f"API Key '{g.api_key_identifier}' initiated network scan for {target_cidr}")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(app.config['PRIV_SOCKET_PATH'])
            s.sendall(json.dumps({"target_cidr": target_cidr, "interface": interface}).encode('utf-8'))
            s.shutdown(socket.SHUT_WR)
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response += chunk
            return jsonify(json.loads(response.decode('utf-8')))
    except Exception as e:
        logging.error(f"Privileged service communication error: {e}")
        raise AppError("Failed to communicate with the privileged scanning service", 500)

@app.route('/api/test_credentials', methods=['POST'])
@require_api_key
def api_test_credentials():
    data = request.get_json()
    if not data: raise AppError("Invalid request: No JSON body")

    ip = validate_ip(data.get('ip'))
    protocol = data.get('protocol')
    if protocol not in ['ssh', 'ftp', 'http']:
        raise AppError("Invalid protocol for connectivity test")
    
    logging.info(f"API Key '{g.api_key_identifier}' initiated connectivity test for {ip}:{protocol}")
    return jsonify(scanner.test_connectivity(ip, protocol))

@app.route('/api/hydra_attack', methods=['POST'])
@require_api_key
def api_hydra_attack():
    data = request.get_json()
    if not data: raise AppError("Invalid request: No JSON body")

    ip = validate_ip(data.get('ip'))
    protocol = data.get('protocol')
    if protocol not in ['ssh', 'ftp', 'http-get']:
        raise AppError("Invalid protocol for Hydra attack")
        
    user_wl = data.get('username_wordlist', '')
    pass_wl = data.get('password_wordlist', '')

    job_id = secrets.token_hex(16)
    db = get_db()
    db.execute(
        "INSERT INTO jobs (id, owner_key, type, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (job_id, g.api_key_identifier, 'hydra', 'queued', datetime.utcnow().isoformat(), datetime.utcnow().isoformat())
    )
    db.commit()
    
    executor.submit(run_hydra_in_background, job_id, ip, protocol, user_wl, pass_wl)
    logging.info(f"API Key '{g.api_key_identifier}' queued Hydra job {job_id} for {ip}")
    return jsonify({"job_id": job_id}), 202

@app.route('/api/execute_exploit', methods=['POST'])
@require_api_key
def api_execute_exploit():
    data = request.get_json()
    if not data: raise AppError("Invalid request: No JSON body")
    
    ip = validate_ip(data.get('ip'))
    module = validate_module(data.get('module'))
    
    job_id = secrets.token_hex(16)
    db = get_db()
    db.execute(
        "INSERT INTO jobs (id, owner_key, type, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (job_id, g.api_key_identifier, 'metasploit', 'queued', datetime.utcnow().isoformat(), datetime.utcnow().isoformat())
    )
    db.commit()

    executor.submit(run_exploit_in_background, job_id, ip, module)
    logging.info(f"API Key '{g.api_key_identifier}' queued Metasploit job {job_id} for {ip} with module {module}")
    return jsonify({"job_id": job_id}), 202

@app.route('/api/job_status/<job_id>', methods=['GET'])
@require_api_key
def get_job_status(job_id):
    db = get_db()
    job = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    
    if not job:
        raise AppError("Job not found", 404)
    if job['owner_key'] != g.api_key_identifier:
        raise AppError("Forbidden: You do not own this job", 403)
        
    return jsonify(dict(job))

# --- 8. Main Execution Block ---
if __name__ == '__main__':
    # Initialize the database if it doesn't exist
    if not os.path.exists(app.config['DATABASE_PATH']):
        init_db()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] (WebServer) %(message)s')

    print("----------------------------------------------------------------")
    print("--- NeonHack // Secure Backend // HARDENED v5.0              ---")
    print("---                                                        ---")
    print(f"--- Server running at: http://127.0.0.1:5000              ---")
    print(f"--- API Key: {app.config['SECRET_API_KEY']}                         ---")
    print("---                                                        ---")
    print("--- IMPORTANT: A new 'jobs.db' file will be created.       ---")
    print("--- Ensure privileged_scanner_service.py is running.       ---")
    print("----------------------------------------------------------------")
    app.run(host='0.0.0.0', port=5000, debug=False)