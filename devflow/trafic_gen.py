import socket
import time
import urllib.request
import urllib.error

HTTP_TARGET = "http://127.0.0.1:8080"
PG_HOST = "127.0.0.1"
PG_PORT = 5432


def send_http_traffic():
    endpoints = [
        ("GET", "/api/v1/users?role=admin", None),
        ("POST", "/api/v1/auth/login", b'{"username": "sreedev", "password": "***"}'),
        ("DELETE", "/api/v1/sessions/98412", None),
    ]

    for method, path, body in endpoints:
        url = f"{HTTP_TARGET}{path}"
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", "DevFlow-Test-Agent/1.0")
        if body:
            req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=2) as response:
                print(f"[+] Sent HTTP {method} {path} -> Status {response.status}")
        except urllib.error.HTTPError as e:
            # Even 404/501 responses from simple servers generate valid HTTP response packets
            print(f"[+] Sent HTTP {method} {path} -> Status {e.code}")
        except Exception as e:
            print(f"[!] HTTP Target (Port 8080) unreachable: {e}")
        time.sleep(0.4)


def send_postgres_traffic():
    queries = [
        "SELECT id, username, email FROM users WHERE active = true;",
        "INSERT INTO audit_logs (event, ip_addr) VALUES ('LOGIN_SUCCESS', '127.0.0.1');",
        "UPDATE metrics SET rtt_ms = 1.24 WHERE service = 'auth-api';"
    ]

    for sql in queries:
        try:
            # Build PostgreSQL Simple Query Wire Protocol packet:
            # 1 byte ('Q') + 4-byte Big-Endian length (includes length bytes + null byte) + SQL string + \x00
            sql_bytes = sql.encode("utf-8") + b"\x00"
            packet_len = (len(sql_bytes) + 4).to_bytes(4, byteorder="big")
            pg_packet = b"Q" + packet_len + sql_bytes

            with socket.create_connection((PG_HOST, PG_PORT), timeout=2) as sock:
                sock.sendall(pg_packet)
                print(f"[+] Sent PostgreSQL Wire Query -> {sql}")
        except Exception as e:
            print(f"[!] PostgreSQL Target (Port 5432) unreachable: {e}")
        time.sleep(0.4)


if __name__ == "__main__":
    print("[*] Starting DevFlow Live Capture Test...")
    send_http_traffic()
    send_postgres_traffic()
    print("[*] Done! Check your DevFlow terminal and dashboard at http://127.0.0.1:5000")