import socket
import struct
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from flask import Flask, jsonify, render_template
from flask_socketio import SocketIO
from devflow.capture import CaptureEngine
from devflow.storage import StorageEngine

app = Flask(__name__)
app.config['SECRET_KEY'] = 'devflow_secret'
socketio = SocketIO(app, cors_allowed_origins="*")

storage = StorageEngine()
capture_engine = None
sniffer_started = False


def build_tls_client_hello(hostname="api.internal.devflow.io"):
    host_bytes = hostname.encode("utf-8")
    sni_payload = struct.pack("!HBH", len(host_bytes) + 3, 0, len(host_bytes)) + host_bytes
    sni_ext = struct.pack("!HH", 0x0000, len(sni_payload)) + sni_payload
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    body = (
        b"\x03\x03" + (b"\x01" * 32) + b"\x00" +
        b"\x00\x02\x00\x2f" + b"\x01\x00" + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class WaterfallHTTPHandler(BaseHTTPRequestHandler):
    """
    Simulates a real backend microservice: when an HTTP request arrives on port 8080,
    it triggers downstream Redis & SQL queries BEFORE returning the HTTP response.
    """
    def do_GET(self):
        # 1. Downstream Redis Cache Check
        time.sleep(0.004)
        redis_pkt = b"*2\r\n$3\r\nGET\r\n$17\r\ncache:users:active\r\n"
        with socket.create_connection(("127.0.0.1", 6379), timeout=1) as s:
            s.sendall(redis_pkt)

        # 2. Downstream PostgreSQL Query
        time.sleep(0.006)
        pg_query = b"SELECT id, username, role FROM users WHERE active = true;\x00"
        pg_pkt = b"Q" + (len(pg_query) + 4).to_bytes(4, 'big') + pg_query
        with socket.create_connection(("127.0.0.1", 5432), timeout=1) as s:
            s.sendall(pg_pkt)

        time.sleep(0.005)
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "service": "user-service", "count": 42}')

    def do_POST(self):
        # 1. Downstream MySQL Audit Insert
        time.sleep(0.005)
        mysql_sql = b"INSERT INTO login_audit (username, mfa_verified) VALUES ('sreedev', 1);"
        mysql_pkt = (len(mysql_sql) + 1).to_bytes(3, 'little') + b"\x00\x03" + mysql_sql
        with socket.create_connection(("127.0.0.1", 3306), timeout=1) as s:
            s.sendall(mysql_pkt)

        # 2. Downstream TLS Vault Call
        time.sleep(0.005)
        tls_pkt = build_tls_client_hello("vault.internal.devflow.local")
        with socket.create_connection(("127.0.0.1", 8443), timeout=1) as s:
            s.sendall(tls_pkt)

        time.sleep(0.006)
        self.send_response(201)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"authenticated": true, "token": "jwt_eyJhbGciOiJIUzI1NiJ9"}')

    def log_message(self, format, *args):
        pass


def start_dummy_targets():
    def run_http():
        try:
            server = HTTPServer(('127.0.0.1', 8080), WaterfallHTTPHandler)
            server.serve_forever()
        except OSError:
            pass

    def run_tcp_sink(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', port))
            s.listen(5)
            while True:
                conn, _ = s.accept()
                conn.recv(1024)
                conn.close()
        except OSError:
            pass

    threading.Thread(target=run_http, daemon=True).start()
    for port in (5432, 3306, 6379, 8443):
        threading.Thread(target=run_tcp_sink, args=(port,), daemon=True).start()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify(storage.get_recent_events(limit=120))


@app.route('/api/clear', methods=['POST'])
def clear_history():
    storage.clear_all()
    return jsonify({"status": "cleared"})


@app.route('/api/pause', methods=['POST'])
def toggle_pause():
    global capture_engine
    if capture_engine:
        capture_engine.paused = not capture_engine.paused
        return jsonify({"paused": capture_engine.paused})
    return jsonify({"paused": False})


@app.route('/api/simulate', methods=['POST'])
def simulate_traffic():
    """Fires two realistic end-to-end microservice transactions."""
    def fire_packets():
        try:
            # Trace 1: GET /api/v1/users (triggers Redis + PostgreSQL inside handler)
            urllib.request.urlopen("http://127.0.0.1:8080/api/v1/users?active=true", timeout=2).read()

            time.sleep(0.15)

            # Trace 2: POST /api/v1/auth/login (triggers MySQL + TLS Vault inside handler)
            req = urllib.request.Request(
                "http://127.0.0.1:8080/api/v1/auth/login",
                data=b'{"username": "sreedev", "role": "security_admin", "mfa": true}',
                headers={"Content-Type": "application/json"},
                method='POST'
            )
            urllib.request.urlopen(req, timeout=2).read()
        except Exception as e:
            print(f"[!] Simulation warning: {e}")

    threading.Thread(target=fire_packets, daemon=True).start()
    return jsonify({"status": "Waterfall traces generated"})


@socketio.on('connect')
def handle_connect():
    print("\n[====== FRONTEND CONNECTED ======]")


def run_sniffer():
    global capture_engine
    capture_engine = CaptureEngine(socketio=socketio, interface="lo", storage=storage)
    capture_engine.start()


if __name__ == '__main__':
    if not sniffer_started:
        start_dummy_targets()
        socketio.start_background_task(run_sniffer)
        sniffer_started = True

    print("[*] Starting DevFlow APM Server on http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)