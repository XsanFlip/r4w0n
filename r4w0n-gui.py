#!/usr/bin/env python3
"""
RTSP Scanner Pro - Web GUI Edition v3.6 (FIXED)
Framework: Flask
UI: Tailwind CSS (Advanced Dark Mode + Collapsible Results)
Fitur: Deep URL Brute-force, Collapsible UI, Copy-to-Clipboard
Port: 5000

c0ded by xsanlahci
"""

from flask import Flask, render_template_string, jsonify, request
import socket
import subprocess
import ipaddress
import threading
import re
import time
from datetime import datetime

app = Flask(__name__)

# --- CONFIGURATION ---
RTSP_PORTS = [554, 8554, 5543, 10554, 8000]
TIMEOUT = 1.8
MAX_THREADS = 50

# Wordlist Path RTSP Standar
STANDARD_PATHS = ["", "/live", "/h264", "/ch1", "/stream1"]

# Deep Brute-force Wordlist (Nmap Style)
BRUTE_PATHS = [
    "/MediaInput/mpeg4", "/cam1/mpeg4", "/cam1/mjpeg", "/cam4/mpeg4",
    "/live/mpeg4", "/live_mpeg4.sdp", "/mjpeg.cgi", "/mjpeg/media.smp",
    "/mpeg4", "/mpeg4/media.amp", "/mpeg4/1/media.amp", "/mpeg4/media.smp",
    "/mpeg4/media.amp?resolution=640x480", "/mpeg4cif", "/mpeg4unicast",
    "/streaming/mjpeg", "/videoMain", "/videoSub", "/live.sdp", "/11", "/12",
    "/Streaming/Channels/101", "/cam/realmonitor?channel=1&subtype=0",
    "/onvif-snapshot", "/media/video1", "/media/video2"
]

scanning_state = {
    "is_scanning": False,
    "progress": 0,
    "total_hosts": 0,
    "scanned_count": 0,
    "found_devices": [],
    "logs": []
}

lock = threading.Lock()

# --- SCANNER LOGIC ---

def get_local_networks():
    networks = []
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) > 0 and "/" in parts[0] and parts[0] != "default":
                try:
                    net = ipaddress.IPv4Network(parts[0], strict=False)
                    if net.is_private:
                        if net not in networks: networks.append(str(net))
                except: continue
    except:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            base = ".".join(local_ip.split(".")[:3]) + ".0/24"
            networks.append(base)
        except: pass
    return networks

def probe_path(ip, port, path):
    """Mengecek apakah suatu path RTSP valid"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        request_data = (
            f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
            "CSeq: 2\r\n"
            "User-Agent: Lavf58.29.100\r\n"
            "Accept: application/sdp\r\n\r\n"
        )
        s.send(request_data.encode())
        response = s.recv(2048).decode(errors='ignore')
        s.close()

        if "RTSP/1.0 200" in response or "RTSP/1.0 401" in response:
            vendor = "Unknown"
            server_match = re.search(r"Server:\s*(.*)\r\n", response, re.IGNORECASE)
            auth_match = re.search(r"WWW-Authenticate:.*realm=\"(.*?)\"", response, re.IGNORECASE)
            if server_match: vendor = server_match.group(1).strip()
            elif auth_match: vendor = auth_match.group(1).strip()
            
            return True, vendor, "RTSP/1.0 401" in response
    except:
        pass
    return False, "Unknown", False

def check_host(ip_str, brute_enabled):
    for port in RTSP_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((ip_str, port))
            sock.close()
            
            if result == 0:
                valid_paths = []
                final_vendor = "Unknown"
                requires_auth = False
                
                wordlist = BRUTE_PATHS if brute_enabled else STANDARD_PATHS
                
                for path in wordlist:
                    is_valid, vendor, auth = probe_path(ip_str, port, path)
                    if is_valid:
                        valid_paths.append(path if path else "/")
                        final_vendor = vendor
                        requires_auth = auth
                
                if valid_paths:
                    device = {
                        "id": f"dev-{ip_str.replace('.', '-')}-{port}",
                        "ip": f"{ip_str}:{port}",
                        "vendor": final_vendor,
                        "paths": valid_paths,
                        "auth": requires_auth,
                        "time": datetime.now().strftime("%H:%M:%S")
                    }
                    with lock:
                        scanning_state["found_devices"].append(device)
                        scanning_state["logs"].append(f"[SUCCESS] Found {len(valid_paths)} paths on {ip_str}:{port}")
        except: pass
    
    with lock:
        scanning_state["scanned_count"] += 1
        if scanning_state["total_hosts"] > 0:
            scanning_state["progress"] = int((scanning_state["scanned_count"] / scanning_state["total_hosts"]) * 100)

def scan_thread_worker(network_cidr, brute_enabled):
    global scanning_state
    try:
        net = ipaddress.IPv4Network(network_cidr, strict=False)
        hosts = list(net.hosts())
        scanning_state["total_hosts"] = len(hosts)
        scanning_state["scanned_count"] = 0
        scanning_state["progress"] = 0
        scanning_state["found_devices"] = []
        msg = "[*] Deep Brute-force enabled" if brute_enabled else "[*] Standard scan enabled"
        scanning_state["logs"] = [f"[*] Starting scan on {network_cidr}...", msg]

        for i in range(0, len(hosts), MAX_THREADS):
            if not scanning_state["is_scanning"]: break
            chunk = hosts[i:i + MAX_THREADS]
            threads = []
            for ip in chunk:
                t = threading.Thread(target=check_host, args=(str(ip), brute_enabled))
                t.start()
                threads.append(t)
            for t in threads: t.join()
        
        scanning_state["logs"].append("[+] Network scan complete.")
    except Exception as e:
        scanning_state["logs"].append(f"[!] Critical Error: {str(e)}")
    finally:
        scanning_state["is_scanning"] = False

# --- ROUTES ---

@app.route('/')
def index():
    networks = get_local_networks()
    return render_template_string(HTML_TEMPLATE, networks=networks)

@app.route('/start_scan', methods=['POST'])
def start_scan():
    target = request.json.get('target')
    brute = request.json.get('brute', False)
    if not scanning_state["is_scanning"]:
        scanning_state["is_scanning"] = True
        threading.Thread(target=scan_thread_worker, args=(target, brute), daemon=True).start()
        return jsonify({"status": "started"})
    return jsonify({"status": "busy"})

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    scanning_state["is_scanning"] = False
    return jsonify({"status": "stopped"})

@app.route('/status')
def status():
    return jsonify(scanning_state)

# --- UI TEMPLATE ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>R4W0N | xsanlahci</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;500;700&family=Fira+Code:wght@400;500&display=swap');
        body { font-family: 'Space+Grotesk', sans-serif; background-color: #050505; color: #f0f0f0; }
        .mono { font-family: 'Fira+Code', monospace; }
        .glass { background: rgba(15, 15, 15, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.05); }
        .btn-primary { background: linear-gradient(135deg, #ef4444 0%, #991b1b 100%); box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3); }
        .btn-primary:hover { box-shadow: 0 6px 20px rgba(239, 68, 68, 0.5); }
        .pulse-red { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
        .accordion-content { max-height: 0; overflow: hidden; transition: max-height 0.4s ease-out, padding 0.3s ease; }
        .accordion-content.open { max-height: 2000px; padding-top: 1rem; }
        .chevron { transition: transform 0.3s ease; }
        .chevron.rotated { transform: rotate(180deg); }
    </style>
</head>
<body class="p-4 md:p-10">
    <div class="max-w-7xl mx-auto">
        <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 gap-4">
            <div>
                <h1 class="text-4xl font-bold tracking-tight text-white flex items-center gap-3">
                    <i class="fas fa-camera text-red-600"></i>
                    R4W0N<span class="text-red-600">.v1</span>
                </h1>
                <p class="text-gray-500 font-medium text-sm md:text-base">RTSP Analysis & Wide-area Object Networking • c0ded by xsanlahci</p>
            </div>
            <div id="status-chip" class="flex items-center gap-2 px-4 py-2 rounded-full glass text-sm font-bold text-gray-400">
                <span class="w-2 h-2 rounded-full bg-gray-500" id="status-dot"></span>
                <span id="status-text">SYSTEM READY</span>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-12 gap-8">
            <div class="lg:col-span-4 space-y-6">
                <div class="glass p-6 rounded-3xl space-y-6 shadow-2xl">
                    <h3 class="text-xl font-bold flex items-center gap-2 text-white">
                        <i class="fas fa-crosshairs text-red-500"></i> Mission Config
                    </h3>
                    <div class="space-y-4">
                        <div>
                            <label class="text-xs uppercase tracking-widest text-gray-500 mb-2 block font-bold">Network Segment</label>
                            <select id="network-select" class="w-full bg-black/40 border border-white/10 rounded-xl p-4 text-white focus:border-red-500 outline-none transition-all cursor-pointer">
                                {% for net in networks %}
                                <option value="{{ net }}">{{ net }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="flex items-center justify-between p-4 bg-white/5 rounded-xl border border-white/5">
                            <div>
                                <p class="text-sm font-bold text-white">Deep URL Brute-force</p>
                                <p class="text-[10px] text-gray-500">Enable Nmap-style path discovery</p>
                            </div>
                            <label class="relative inline-flex items-center cursor-pointer">
                                <input type="checkbox" id="brute-toggle" class="sr-only peer">
                                <div class="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-red-600"></div>
                            </label>
                        </div>
                        <button id="btn-start" onclick="startScan()" class="w-full btn-primary text-white font-bold py-4 rounded-xl transition-all flex items-center justify-center gap-2">
                            <i class="fas fa-play text-sm"></i> EXECUTE SCAN
                        </button>
                        <button id="btn-stop" onclick="stopScan()" class="w-full bg-white/5 hover:bg-white/10 text-white font-bold py-4 rounded-xl hidden transition-all border border-white/10">
                            TERMINATE PROCESS
                        </button>
                    </div>
                </div>
                <div class="glass p-6 rounded-3xl">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-sm font-bold text-gray-400 uppercase tracking-widest">Live Console</h3>
                        <i class="fas fa-terminal text-xs text-gray-600"></i>
                    </div>
                    <div id="log-container" class="h-48 overflow-y-auto mono text-[11px] space-y-1 text-red-400/80 p-3 bg-black/50 rounded-xl border border-white/5">
                        <div>> Initializing core modules...</div>
                    </div>
                </div>
            </div>

            <div class="lg:col-span-8 space-y-6">
                <div class="glass p-6 rounded-3xl flex flex-col md:flex-row items-center gap-6 border-l-4 border-red-600">
                    <div class="relative w-20 h-20 flex-shrink-0">
                        <svg class="w-full h-full transform -rotate-90">
                            <circle cx="40" cy="40" r="36" stroke="currentColor" stroke-width="4" fill="transparent" class="text-gray-800" />
                            <circle id="progress-circle" cx="40" cy="40" r="36" stroke="currentColor" stroke-width="4" fill="transparent" stroke-dasharray="226.2" stroke-dashoffset="226.2" class="text-red-500 transition-all duration-500" />
                        </svg>
                        <span id="progress-percent" class="absolute inset-0 flex items-center justify-center text-xs font-bold text-white">0%</span>
                    </div>
                    <div class="flex-1 text-center md:text-left">
                        <h4 id="progress-title" class="text-xl font-bold text-white">Standby Mode</h4>
                        <p id="progress-subtitle" class="text-sm text-gray-500">Awaiting target selection for deployment.</p>
                    </div>
                </div>

                <div class="glass rounded-3xl overflow-hidden border border-white/10 shadow-2xl">
                    <div class="p-6 border-b border-white/5 bg-white/5 flex justify-between items-center">
                        <h3 class="font-bold text-white flex items-center gap-2">
                            <i class="fas fa-satellite-dish text-red-500 text-sm"></i> Discovered Intelligence
                        </h3>
                        <span id="found-count" class="bg-red-600 text-white text-[10px] font-bold px-2 py-0.5 rounded tracking-tighter">0 DEVICES</span>
                    </div>
                    <div id="result-grid" class="p-6 space-y-4 max-h-[800px] overflow-y-auto">
                        <div id="empty-state" class="py-24 text-center space-y-4">
                            <div class="inline-block p-6 rounded-full bg-white/5 mb-4">
                                <i class="fas fa-radar fa-3x text-gray-700 pulse-red"></i>
                            </div>
                            <p class="text-gray-600 font-medium">No signals detected in this frequency range.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let pollInterval;
        let expandedCards = new Set();

        function toggleCard(cardId) {
            const content = document.getElementById(cardId + '-content');
            const chevron = document.getElementById(cardId + '-chevron');
            if (expandedCards.has(cardId)) {
                expandedCards.delete(cardId);
                content.classList.remove('open');
                chevron.classList.remove('rotated');
            } else {
                expandedCards.add(cardId);
                content.classList.add('open');
                chevron.classList.add('rotated');
            }
        }

        function startScan() {
            const target = document.getElementById('network-select').value;
            const brute = document.getElementById('brute-toggle').checked;
            expandedCards.clear();
            fetch('/start_scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: target, brute: brute})
            }).then(() => {
                setUIState(true);
                pollInterval = setInterval(updateStatus, 1000);
            });
        }

        function stopScan() {
            fetch('/stop_scan', {method: 'POST'}).then(() => resetUI());
        }

        function setUIState(scanning) {
            document.getElementById('btn-start').classList.toggle('hidden', scanning);
            document.getElementById('btn-stop').classList.toggle('hidden', !scanning);
            const chip = document.getElementById('status-chip');
            const dot = document.getElementById('status-dot');
            const text = document.getElementById('status-text');
            if (scanning) {
                chip.className = 'flex items-center gap-2 px-4 py-2 rounded-full glass text-sm font-bold text-red-500';
                dot.className = 'w-2 h-2 rounded-full bg-red-500 pulse-red';
                text.innerText = 'OPERATIONAL';
            } else {
                chip.className = 'flex items-center gap-2 px-4 py-2 rounded-full glass text-sm font-bold text-gray-400';
                dot.className = 'w-2 h-2 rounded-full bg-gray-500';
                text.innerText = 'SYSTEM READY';
            }
        }

        function resetUI() {
            clearInterval(pollInterval);
            setUIState(false);
        }

        function copyToClipboard(event, text) {
            event.stopPropagation();
            const el = document.createElement('textarea');
            el.value = text;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
        }

        function updateStatus() {
            fetch('/status').then(res => res.json()).then(data => {
                const offset = 226.2 - (226.2 * data.progress / 100);
                document.getElementById('progress-circle').style.strokeDashoffset = offset;
                document.getElementById('progress-percent').innerText = data.progress + '%';
                document.getElementById('progress-title').innerText = data.is_scanning ? 'Active Operation' : 'Mission Completed';
                document.getElementById('progress-subtitle').innerText = `Scanned ${data.scanned_count} of ${data.total_hosts} target hosts.`;
                const logContainer = document.getElementById('log-container');
                logContainer.innerHTML = data.logs.map(log => `<div><span class="text-gray-600 font-bold">[${new Date().toLocaleTimeString()}]</span> ${log}</div>`).join('');
                logContainer.scrollTop = logContainer.scrollHeight;
                const grid = document.getElementById('result-grid');
                document.getElementById('found-count').innerText = `${data.found_devices.length} DEVICES`;
                if (data.found_devices.length > 0) {
                    document.getElementById('empty-state').classList.add('hidden');
                    grid.innerHTML = data.found_devices.map(d => {
                        const isOpen = expandedCards.has(d.id);
                        return `
                            <div id="${d.id}" onclick="toggleCard('${d.id}')" class="glass rounded-2xl border border-white/5 transition-all hover:bg-white/5 cursor-pointer group overflow-hidden">
                                <div class="p-5 flex justify-between items-center">
                                    <div class="flex items-center gap-4">
                                        <div class="p-3 rounded-xl bg-red-600/10 text-red-500"><i class="fas fa-video"></i></div>
                                        <div>
                                            <h4 class="text-base font-bold text-white">${d.ip}</h4>
                                            <div class="flex items-center gap-2 mt-1">
                                                <span class="text-[10px] text-gray-500 uppercase tracking-widest font-black">${d.vendor}</span>
                                                <span class="w-1 h-1 rounded-full bg-gray-700"></span>
                                                <span class="text-[10px] text-red-500/80 font-bold uppercase tracking-tighter">${d.paths.length} PATHS</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="flex items-center gap-3">
                                        <span class="px-3 py-1 rounded-full text-[9px] font-black tracking-widest ${d.auth ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20' : 'bg-green-500/10 text-green-400 border border-green-500/20'}">
                                            ${d.auth ? 'LOCKED' : 'OPEN'}
                                        </span>
                                        <i id="${d.id}-chevron" class="fas fa-chevron-down text-gray-600 chevron ${isOpen ? 'rotated' : ''}"></i>
                                    </div>
                                </div>
                                <div id="${d.id}-content" class="accordion-content ${isOpen ? 'open' : ''} bg-black/20">
                                    <div class="px-5 pb-5 space-y-2">
                                        ${d.paths.map(p => `
                                            <div class="flex items-center justify-between gap-4 bg-white/5 p-3 rounded-xl border border-white/5 group/row hover:border-red-500/30 transition-all">
                                                <code class="text-xs text-red-400/90 truncate mono select-all">rtsp://${d.ip}${p}</code>
                                                <button onclick="copyToClipboard(event, 'rtsp://${d.ip}${p}')" class="text-gray-600 hover:text-white p-2 hover:bg-white/10 rounded-lg transition-all"><i class="fas fa-copy text-xs"></i></button>
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                            </div>
                        `;
                    }).join('');
                }
                if (!data.is_scanning && data.scanned_count > 0 && data.scanned_count === data.total_hosts) resetUI();
            });
        }
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
