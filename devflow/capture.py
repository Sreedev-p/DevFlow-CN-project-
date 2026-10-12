import socket
import struct
from dissector import Dissector

class CaptureEngine:
    def __init__(self, interface="lo"):
        self.interface = interface
        self.sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sniffer.bind((self.interface, 0))

    def start(self):
        print(f"[*] Listening on {self.interface}...")
        try:
            while True:
                raw_data, _ = self.sniffer.recvfrom(65535)
                self.process_packet(raw_data)
        except KeyboardInterrupt:
            print("\n[*] Capture stopped.")

    def process_packet(self, raw_data):
        # 1. Parse Ethernet
        eth_header = raw_data[:14]
        eth_type = struct.unpack("!6s6sH", eth_header)[2]

        if eth_type == 0x0800:  # IPv4
            ihl = raw_data[14] & 0x0F
            ip_header_length = ihl * 4

            # 2. Parse IPv4
            protocol, src_ip, dest_ip = Dissector.parse_ipv4(raw_data)

            # Check if Protocol is TCP (6)
            if protocol == 6:
                tcp_offset = 14 + ip_header_length
                
                # 3. Parse TCP
                src_port, dest_port, tcp_header_length = Dissector.parse_tcp(raw_data, tcp_offset)
                
                payload_offset = tcp_offset + tcp_header_length
                payload_size = len(raw_data) - payload_offset
                
                if payload_size > 0:
                    payload = raw_data[payload_offset:]
                    
                    # 4. Decode Application Layer
                    http_info = Dissector.parse_http(payload)
                    
                    if http_info:
                        print(f"\n[+] HTTP Traffic Intercepted:")
                        print(f"    Connection: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
                        print(f"    Payload: {http_info}")

if __name__ == "__main__":
    engine = CaptureEngine(interface="lo")
    engine.start()