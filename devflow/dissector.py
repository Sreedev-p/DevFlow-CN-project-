import json
import socket
import struct


class Dissector:
    @staticmethod
    def parse_ipv4(raw_data):
        ip_header = raw_data[14:34]
        unpacked = struct.unpack('!9xB 2x 4s 4s', ip_header)
        protocol = unpacked[0]
        src_ip = socket.inet_ntoa(unpacked[1])
        dest_ip = socket.inet_ntoa(unpacked[2])
        return protocol, src_ip, dest_ip

    @staticmethod
    def parse_ipv6(raw_data):
        """
        Unpacks 40-byte fixed IPv6 header starting at byte 14.
        Byte 6 is Next Header (6 = TCP), Bytes 8..24 = Src IPv6, Bytes 24..40 = Dest IPv6.
        """
        ipv6_header = raw_data[14:54]
        next_header = ipv6_header[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[8:24])
        dest_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[24:40])
        return next_header, f"[{src_ip}]", f"[{dest_ip}]", 40

    @staticmethod
    def parse_tcp(raw_data, ip_offset):
        tcp_header = raw_data[ip_offset:ip_offset + 20]
        src_port, dest_port = struct.unpack('!HH', tcp_header[:4])
        offset_reserved = tcp_header[12]
        tcp_header_length = (offset_reserved >> 4) * 4
        return src_port, dest_port, tcp_header_length

    @staticmethod
    def parse_http(payload_bytes):
        """Returns first_line string, or None if not HTTP."""
        try:
            http_data = payload_bytes.decode('utf-8', errors='ignore')
            first_line = http_data.splitlines()[0].strip() if http_data else ""

            http_keywords = ('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'HTTP/1.')
            if first_line.startswith(http_keywords):
                return first_line
        except Exception:
            pass
        return None

    @staticmethod
    def extract_http_json(payload_bytes):
        """Extracts and pretty-prints JSON body from an HTTP packet if present."""
        try:
            text = payload_bytes.decode('utf-8', errors='ignore')
            if '\r\n\r\n' in text:
                body = text.split('\r\n\r\n', 1)[1].strip()
                if body.startswith(('{', '[')):
                    parsed = json.loads(body)
                    return json.dumps(parsed, indent=2)
        except Exception:
            pass
        return None

    @staticmethod
    def parse_sql(payload_bytes, src_port, dest_port):
        """Dissects both PostgreSQL (5432) and MySQL/MariaDB (3306) wire protocols."""
        try:
            # 1. PostgreSQL Wire Protocol (Port 5432, 'Q' == 81)
            if src_port == 5432 or dest_port == 5432:
                if len(payload_bytes) > 5 and payload_bytes[0] == 81:
                    query_text = payload_bytes[5:].rstrip(b'\x00').decode('utf-8', errors='replace').strip()
                    if query_text:
                        return f"PostgreSQL Query: {query_text}"

            # 2. MySQL Wire Protocol (Port 3306, 3-byte len + 1-byte seq + 0x03 COM_QUERY)
            if src_port == 3306 or dest_port == 3306:
                if len(payload_bytes) > 5 and payload_bytes[4] == 0x03:
                    query_text = payload_bytes[5:].decode('utf-8', errors='replace').strip()
                    if query_text:
                        return f"MySQL Query: {query_text}"
        except Exception:
            pass
        return None

    @staticmethod
    def parse_redis(payload_bytes, src_port, dest_port):
        """Dissects Redis RESP Array commands on port 6379 (e.g. *3\r\n$3\r\nSET\r\n...)."""
        try:
            if src_port == 6379 or dest_port == 6379:
                if payload_bytes.startswith(b'*'):
                    lines = payload_bytes.decode('utf-8', errors='ignore').split('\r\n')
                    # Filter out RESP length markers (*N and $N)
                    tokens = [
                        line for line in lines
                        if line and not line.startswith('*') and not line.startswith('$')
                    ]
                    if tokens:
                        return f"Redis Command: {' '.join(tokens)}"
        except Exception:
            pass
        return None

    @staticmethod
    def parse_tls_sni(payload_bytes):
        """
        Inspects TLS Handshake (0x16) ClientHello (0x01) records to extract the target
        Server Name Indication (SNI) hostname without needing private keys.
        """
        try:
            # TLS Record: ContentType 0x16 (Handshake), Version 0x0301..0x0303, HandshakeType 0x01 (ClientHello)
            if len(payload_bytes) < 43 or payload_bytes[0] != 0x16 or payload_bytes[5] != 0x01:
                return None

            # Skip fixed Record Header (5) + Handshake Header (4) + ClientVersion (2) + Random (32) = 43
            pos = 43
            session_id_len = payload_bytes[pos]
            pos += 1 + session_id_len

            if pos + 2 > len(payload_bytes):
                return None
            cipher_suites_len = struct.unpack_from('!H', payload_bytes, pos)[0]
            pos += 2 + cipher_suites_len

            if pos + 1 > len(payload_bytes):
                return None
            comp_methods_len = payload_bytes[pos]
            pos += 1 + comp_methods_len

            if pos + 2 > len(payload_bytes):
                return None
            extensions_total_len = struct.unpack_from('!H', payload_bytes, pos)[0]
            pos += 2
            end_ext = min(pos + extensions_total_len, len(payload_bytes))

            while pos + 4 <= end_ext:
                ext_type, ext_len = struct.unpack_from('!HH', payload_bytes, pos)
                pos += 4
                # Extension Type 0x0000 is Server Name Indication (SNI)
                if ext_type == 0x0000 and pos + 5 <= end_ext:
                    name_type = payload_bytes[pos + 2]
                    name_len = struct.unpack_from('!H', payload_bytes, pos + 3)[0]
                    if name_type == 0 and pos + 5 + name_len <= end_ext:
                        sni_host = payload_bytes[pos + 5:pos + 5 + name_len].decode('utf-8', errors='ignore')
                        if sni_host:
                            return f"TLS ClientHello -> SNI: {sni_host}"
                pos += ext_len
        except Exception:
            pass
        return None