import socket
import struct
import time
import unittest
from devflow.dissector import Dissector
from devflow.metrics import MetricEngine
from devflow.process_mapper import ProcessMapper


class TestDevFlowComplete(unittest.TestCase):

    def test_ipv4_and_ipv6_dissection(self):
        eth4 = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ip4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                          socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
        proto, src, dst = Dissector.parse_ipv4(eth4 + ip4)
        self.assertEqual((proto, src, dst), (6, "127.0.0.1", "127.0.0.1"))

        eth6 = b"\x00" * 12 + struct.pack("!H", 0x86DD)
        ip6 = struct.pack("!IHBB16s16s", 0x60000000, 20, 6, 64,
                          socket.inet_pton(socket.AF_INET6, "::1"),
                          socket.inet_pton(socket.AF_INET6, "::1"))
        nh, s6, d6, hdr_len = Dissector.parse_ipv6(eth6 + ip6)
        self.assertEqual((nh, s6, d6, hdr_len), (6, "[::1]", "[::1]", 40))

    def test_http_and_json_extraction(self):
        pkt = b'POST /api/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"user":"admin"}'
        self.assertEqual(Dissector.parse_http(pkt), "POST /api/login HTTP/1.1")
        self.assertIn('"user": "admin"', Dissector.extract_http_json(pkt))

    def test_postgres_and_mysql_dissection(self):
        q = b"SELECT * FROM accounts;\x00"
        pg_pkt = b"Q" + (len(q) + 4).to_bytes(4, "big") + q
        self.assertEqual(Dissector.parse_sql(pg_pkt, 52000, 5432), "PostgreSQL Query: SELECT * FROM accounts;")

        mq = b"SHOW TABLES;"
        mysql_pkt = (len(mq) + 1).to_bytes(3, "little") + b"\x00\x03" + mq
        self.assertEqual(Dissector.parse_sql(mysql_pkt, 52000, 3306), "MySQL Query: SHOW TABLES;")

    def test_redis_resp_dissection(self):
        redis_pkt = b"*3\r\n$3\r\nSET\r\n$4\r\nuser\r\n$7\r\nsreedev\r\n"
        self.assertEqual(Dissector.parse_redis(redis_pkt, 51000, 6379), "Redis Command: SET user sreedev")

    def test_tls_sni_dissection(self):
        host = b"github.com"
        sni_payload = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
        sni_ext = struct.pack("!HH", 0x0000, len(sni_payload)) + sni_payload
        exts = struct.pack("!H", len(sni_ext)) + sni_ext
        body = b"\x03\x03" + (b"\x01" * 32) + b"\x00\x00\x02\x00\x2f\x01\x00" + exts
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

        self.assertEqual(Dissector.parse_tls_sni(record), "TLS ClientHello -> SNI: github.com")

    def test_waterfall_trace_correlation(self):
        metrics = MetricEngine()
        trace_id, req_offset = metrics.track_request(54321, 8080, "python3 (PID:999)")
        self.assertEqual(req_offset, 0.0)

        time.sleep(0.005)
        child_trace, child_offset = metrics.track_child_span("python3 (PID:999)")
        self.assertEqual(child_trace, trace_id)
        self.assertGreater(child_offset, 0.0)

        time.sleep(0.005)
        rtt, res_trace, _ = metrics.track_response(8080, 54321)
        self.assertEqual(res_trace, trace_id)
        self.assertGreater(rtt, child_offset)

    def test_process_mapper_live_socket(self):
        mapper = ProcessMapper()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            proc_name = mapper.resolve(port, 80)
            self.assertIn("PID:", proc_name)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()