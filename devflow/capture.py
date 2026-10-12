import socket
import struct

class CaptureEngine:
    def __init__(self, interface="lo"):
        self.interface = interface
        # Initialize the raw socket
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
        # 1. Extract Ethernet Header (always 14 bytes)
        eth_header = raw_data[:14]
        eth_type = struct.unpack("!6s6sH", eth_header)[2]

        # Check if it is IPv4 (EtherType 0x0800)
        if eth_type == 0x0800:
            # 2. Dynamically calculate IPv4 header length
            # The first byte of the IP header contains Version (4 bits) and IHL (4 bits)
            ip_header_first_byte = raw_data[14]
            ihl = ip_header_first_byte & 0x0F  # Bitwise AND to isolate the lower 4 bits
            ip_header_length = ihl * 4         # Multiply by 4 to get bytes

            print(f"Captured IPv4 Packet. Header Length: {ip_header_length} bytes.")

if __name__ == "__main__":
    engine = CaptureEngine(interface="lo")
    engine.start()