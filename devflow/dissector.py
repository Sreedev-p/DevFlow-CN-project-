import struct
import socket

class Dissector:
    @staticmethod
    def parse_ipv4(raw_data):
        # We need the 20-byte base header to extract protocol and IPs
        ip_header = raw_data[14:34]
        
        # struct format: 
        # ! = Network (Big-Endian) byte order
        # B = 1 byte (unsigned char), H = 2 bytes (unsigned short), 4s = 4-byte string
        # We skip the first 9 bytes using '9x'
        # Then grab Protocol (1 byte), Header Checksum (2 bytes, ignored here with 2x), 
        # and the two IPs (4 bytes each)
        
        unpacked = struct.unpack('!9xB 2x 4s 4s', ip_header)
        protocol = unpacked[0]
        src_ip = socket.inet_ntoa(unpacked[1])
        dest_ip = socket.inet_ntoa(unpacked[2])
        
        return protocol, src_ip, dest_ip

    @staticmethod
    def parse_tcp(raw_data, ip_offset):
        # The TCP header starts immediately after the IP header
        tcp_header = raw_data[ip_offset:ip_offset + 20]
        
        # Unpack Source Port (2 bytes) and Dest Port (2 bytes)
        src_port, dest_port = struct.unpack('!HH', tcp_header[:4])
        
        # The Data Offset (Header Length) is the top 4 bits of the 12th byte
        offset_reserved = tcp_header[12]
        
        # Right-shift 4 bits to isolate the length, then multiply by 4 to get bytes
        tcp_header_length = (offset_reserved >> 4) * 4
        
        return src_port, dest_port, tcp_header_length
    
    @staticmethod
    def parse_http(payload_bytes):
        try:
            # HTTP/1.x is a plaintext protocol. We attempt to decode it.
            http_data = payload_bytes.decode('utf-8')
            
            # The first line of an HTTP packet contains the critical routing info
            # e.g., "GET /api/users HTTP/1.1" OR "HTTP/1.1 200 OK"
            first_line = http_data.split('\r\n')[0]
            
            # Filter to ensure we are actually looking at HTTP traffic
            http_keywords = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HTTP/1.']
            if any(keyword in first_line for keyword in http_keywords):
                return first_line
                
        except UnicodeDecodeError:
            # If it cannot decode to UTF-8, it is binary data (like an image or encrypted TLS)
            pass 
            
        return None