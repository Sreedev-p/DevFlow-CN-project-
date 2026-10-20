import socket
import struct
from datetime import datetime
from devflow.dissector import Dissector
from devflow.metrics import MetricEngine
from devflow.process_mapper import ProcessMapper
from devflow.storage import StorageEngine

DASHBOARD_PORT = 5000


class CaptureEngine:
    def __init__(self, socketio=None, interface="lo", storage=None):
        self.interface = interface
        self.socketio = socketio
        self.paused = False
        self.sniffer = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(0x0003)
        )
        self.sniffer.bind((self.interface, 0))
        self.metrics = MetricEngine()
        self.proc_mapper = ProcessMapper()
        self.storage = storage or StorageEngine()

    @staticmethod
    def format_hex_dump(payload_bytes, max_bytes=128):
        """Formats up to 128 bytes into a classic Wireshark 16-byte Hex + ASCII grid."""
        chunk = payload_bytes[:max_bytes]
        lines = []
        for i in range(0, len(chunk), 16):
            sub = chunk[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in sub).ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in sub)
            lines.append(f"{i:04x}  {hex_part}  |{ascii_part}|")
        return "\n".join(lines)

    def start(self):
        print(f"[*] Sniffer running on '{self.interface}' (IPv4 + IPv6 | Ignoring Port {DASHBOARD_PORT})...")
        try:
            while True:
                raw_data, _ = self.sniffer.recvfrom(65535)
                if self.paused:
                    continue
                try:
                    self.process_packet(raw_data)
                except (struct.error, IndexError, ValueError):
                    continue
        except KeyboardInterrupt:
            print("\n[*] Stopping sniffer...")
        finally:
            self.sniffer.close()

    def emit_event(
        self,
        event_type,
        connection,
        payload,
        process_info="Unknown",
        json_body=None,
        latency=None,
        trace_id=None,
        offset_ms=0.0,
        hex_dump=None
    ):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        latency_str = f" | RTT: {latency} ms" if latency is not None else f" | +{offset_ms} ms"
        print(f"[{timestamp}] [{trace_id}] [{event_type}] {connection} ({process_info}) | {payload}{latency_str}")

        data = {
            "timestamp": timestamp,
            "type": event_type,
            "connection": connection,
            "process": process_info,
            "payload": payload,
            "json_body": json_body,
            "latency": latency,
            "trace_id": trace_id,
            "offset_ms": offset_ms,
            "hex_dump": hex_dump
        }

        if self.storage:
            self.storage.save_event(data)

        if self.socketio:
            self.socketio.emit('network_event', data)

    def process_packet(self, raw_data):
        if len(raw_data) < 34:
            return

        eth_header = raw_data[:14]
        eth_type = struct.unpack("!6s6sH", eth_header)[2]

        if eth_type == 0x0800:
            ihl = raw_data[14] & 0x0F
            ip_header_length = ihl * 4
            protocol, src_ip, dest_ip = Dissector.parse_ipv4(raw_data)
        elif eth_type == 0x86DD and len(raw_data) >= 54:
            protocol, src_ip, dest_ip, ip_header_length = Dissector.parse_ipv6(raw_data)
        else:
            return

        if protocol == 6:
            tcp_offset = 14 + ip_header_length
            if len(raw_data) < tcp_offset + 20:
                return

            src_port, dest_port, tcp_header_length = Dissector.parse_tcp(raw_data, tcp_offset)

            if src_port == DASHBOARD_PORT or dest_port == DASHBOARD_PORT:
                return

            payload_offset = tcp_offset + tcp_header_length
            if len(raw_data) <= payload_offset:
                return

            payload = raw_data[payload_offset:]
            connection_str = f"{src_ip}:{src_port} -> {dest_ip}:{dest_port}"
            hex_preview = self.format_hex_dump(payload)

            # 1. Check HTTP/1.x
            http_info = Dissector.parse_http(payload)
            if http_info:
                proc_info = self.proc_mapper.resolve(src_port, dest_port)
                json_body = Dissector.extract_http_json(payload)
                http_methods = ('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')

                if http_info.startswith(http_methods):
                    trace_id, offset_ms = self.metrics.track_request(src_port, dest_port, proc_info)
                    self.emit_event(
                        "HTTP Request", connection_str, http_info,
                        proc_info, json_body, None, trace_id, offset_ms, hex_preview
                    )
                elif http_info.startswith('HTTP/1.'):
                    latency, trace_id, offset_ms = self.metrics.track_response(src_port, dest_port)
                    self.emit_event(
                        "HTTP Response", connection_str, http_info,
                        proc_info, json_body, latency, trace_id, offset_ms, hex_preview
                    )
                return

            # 2. Check SQL (PostgreSQL 5432 & MySQL 3306)
            sql_info = Dissector.parse_sql(payload, src_port, dest_port)
            if sql_info:
                proc_info = self.proc_mapper.resolve(src_port, dest_port)
                trace_id, offset_ms = self.metrics.track_child_span(proc_info)
                self.emit_event(
                    "SQL Query", connection_str, sql_info,
                    proc_info, None, None, trace_id, offset_ms, hex_preview
                )
                return

            # 3. Check Redis RESP (6379)
            redis_info = Dissector.parse_redis(payload, src_port, dest_port)
            if redis_info:
                proc_info = self.proc_mapper.resolve(src_port, dest_port)
                trace_id, offset_ms = self.metrics.track_child_span(proc_info)
                self.emit_event(
                    "Redis Command", connection_str, redis_info,
                    proc_info, None, None, trace_id, offset_ms, hex_preview
                )
                return

            # 4. Check TLS/HTTPS Handshake SNI
            tls_info = Dissector.parse_tls_sni(payload)
            if tls_info:
                proc_info = self.proc_mapper.resolve(src_port, dest_port)
                trace_id, offset_ms = self.metrics.track_child_span(proc_info)
                self.emit_event(
                    "TLS Handshake", connection_str, tls_info,
                    proc_info, None, None, trace_id, offset_ms, hex_preview
                )


if __name__ == "__main__":
    engine = CaptureEngine(interface="lo")
    engine.start()