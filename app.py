from flask import Flask, render_template, request
import socket
import whois
import requests
import datetime


app = Flask(__name__)

# Function to scan ports
from concurrent.futures import ThreadPoolExecutor

def scan_single_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # shorter timeout for speed
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except:
        pass
    return None

def scan_ports(target, ports_to_scan):
    open_ports = []
    try:
        ip = socket.gethostbyname(target)
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(lambda port: scan_single_port(ip, port), ports_to_scan)
        open_ports = [port for port in results if port is not None]
    except Exception as e:
        print(f"Error scanning ports: {e}")
    return open_ports


# Function to get whois info
def get_whois_info(domain):

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        registrar = w.registrar

        # Fix: If it's a list, take the first date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Fix: Convert datetime to readable string
        if isinstance(creation_date, datetime.datetime):
            creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')

        return f"Domain created on: {creation_date}, Registrar: {registrar}"
    except Exception as e:
        return "Could not fetch Whois info."


# Function to get HTTP header info
def get_http_headers(target):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
    }
    try:
        response = requests.get(f"http://{target}", headers=headers, timeout=5)
        if response.status_code == 403:
            # Return custom message if forbidden
            return "Site blocked HTTP requests; headers unavailable"
        else:
            return {
                "Server": response.headers.get("Server", "N/A"),
                "X-Powered-By": response.headers.get("X-Powered-By", "N/A"),
                "Status-Code": response.status_code
            }
    except Exception as e:
        return "Site blocked HTTP requests; headers unavailable"



@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        user_input = request.form.get('target')

        mode = request.form.get('mode')

        if mode == 'full':
            ports_to_scan = range(1, 65536)
        else:
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]

        open_ports = scan_ports(user_input, ports_to_scan)

        whois_info = None
        if not user_input.replace('.', '').isdigit():
            whois_info = get_whois_info(user_input)

        whois_info = None
        if not user_input.replace('.', '').isdigit():
            whois_info = get_whois_info(user_input)

        http_headers = get_http_headers(user_input)
        if isinstance(http_headers, dict):
          headers_result = f"Server: {http_headers.get('Server')}<br>X-Powered-By: {http_headers.get('X-Powered-By')}<br>Status Code: {http_headers.get('Status-Code')}"
        else:
    # If it's a string message (like error message), just show that
           headers_result = http_headers


        if open_ports:
            ports_str = ", ".join(str(p) for p in open_ports)
            port_result = f"Open ports on {user_input}: {ports_str}"
        else:
            port_result = f"No open common ports found on {user_input}."

        return render_template('index.html', result=port_result, whois=whois_info, headers=headers_result, target=user_input)

    return render_template('index.html')

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


