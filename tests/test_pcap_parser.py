import unittest
import pandas as pd
import socket
import dpkt  # type: ignore
from unittest.mock import patch, MagicMock
from modules.pcap_parser import (
    inet_to_str,
    get_protocol_name,
    extract_tls_sni,
    detect_server_ip,
    load_pcap,
    extract_ip_packet,
    get_parser_stats,
    SimpleTcpStreamReassembler
)

class TestPcapParserModule(unittest.TestCase):
    def test_inet_to_str(self):
        # IPv4
        packed_ipv4 = socket.inet_pton(socket.AF_INET, "192.168.1.1")
        self.assertEqual(inet_to_str(packed_ipv4), "192.168.1.1")
        
        # IPv6
        packed_ipv6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        self.assertEqual(inet_to_str(packed_ipv6), "2001:db8::1")
        
        # Invalid
        self.assertEqual(inet_to_str(b"bad"), "Unknown")

    def test_get_protocol_name(self):
        self.assertEqual(get_protocol_name(6), 'TCP')
        self.assertEqual(get_protocol_name(17), 'UDP')
        self.assertEqual(get_protocol_name(1), 'ICMP')
        self.assertEqual(get_protocol_name(999), 'Unknown (999)')

    def test_extract_tls_sni(self):
        # Non-TLS or truncated data
        self.assertEqual(extract_tls_sni(b""), "")
        self.assertEqual(extract_tls_sni(b"GET / HTTP/1.1\r\n\r\n"), "")
        self.assertEqual(extract_tls_sni(b"\x16\x03\x01\x00\x05\x02"), "")

    def test_detect_server_ip(self):
        # Empty df
        self.assertIsNone(detect_server_ip(pd.DataFrame()))
        
        # Server on port 80 receiving requests
        df = pd.DataFrame([
            {'Source IP': '10.0.0.2', 'Dest IP': '192.168.1.10', 'Dest Port': 80},
            {'Source IP': '10.0.0.3', 'Dest IP': '192.168.1.10', 'Dest Port': 80},
            {'Source IP': '10.0.0.4', 'Dest IP': '192.168.1.10', 'Dest Port': 80},
            {'Source IP': '192.168.1.10', 'Dest IP': '10.0.0.2', 'Dest Port': 54321},
        ])
        server_ip = detect_server_ip(df)
        self.assertEqual(server_ip, '192.168.1.10')

    def test_load_pcap_invalid_file(self):
        """Kiểm tra load_pcap trả về DataFrame rỗng khi file không hợp lệ."""
        with patch('modules.pcap_parser.st') as mock_st:
            mock_st.progress.return_value = MagicMock()
            mock_st.error = MagicMock()
            result = load_pcap(b'invalid pcap data')
            self.assertIsInstance(result, pd.DataFrame)
            self.assertTrue(result.empty)

    def test_datalink_dispatch_multi_link_layer(self):
        """[V3-06] Kiểm tra dispatch extract_ip_packet cho Ethernet, Linux SLL, Loopback, Raw IP."""
        # Tạo gói tin IPv4 ICMP chuẩn
        ip_pkt = dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.10"),
            dst=socket.inet_aton("10.0.0.1"),
            p=dpkt.ip.IP_PROTO_ICMP,
            data=dpkt.icmp.ICMP(type=8, code=0)
        )
        ip_bytes = bytes(ip_pkt)

        # 1. Ethernet (DLT_EN10MB = 1)
        eth_pkt = dpkt.ethernet.Ethernet(
            src=b'\x00' * 6, dst=b'\xff' * 6,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_bytes
        )
        parsed_ip, status = extract_ip_packet(bytes(eth_pkt), dpkt.pcap.DLT_EN10MB)
        self.assertEqual(status, 'ok')
        self.assertIsNotNone(parsed_ip)
        self.assertEqual(inet_to_str(parsed_ip.src), "192.168.1.10")

        # 2. Linux Cooked SLL (DLT_LINUX_SLL = 113)
        sll_pkt = dpkt.sll.SLL(
            ethtype=dpkt.ethernet.ETH_TYPE_IP,
            data=ip_bytes
        )
        parsed_ip, status = extract_ip_packet(bytes(sll_pkt), getattr(dpkt.pcap, 'DLT_LINUX_SLL', 113))
        self.assertEqual(status, 'ok')
        self.assertIsNotNone(parsed_ip)
        self.assertEqual(inet_to_str(parsed_ip.src), "192.168.1.10")

        # 3. Loopback (DLT_NULL = 0)
        lb_pkt = dpkt.loopback.Loopback(
            family=socket.AF_INET,
            data=ip_bytes
        )
        parsed_ip, status = extract_ip_packet(bytes(lb_pkt), getattr(dpkt.pcap, 'DLT_NULL', 0))
        self.assertEqual(status, 'ok')
        self.assertIsNotNone(parsed_ip)
        self.assertEqual(inet_to_str(parsed_ip.src), "192.168.1.10")

        # 4. Raw IP (DLT_RAW = 12)
        parsed_ip, status = extract_ip_packet(ip_bytes, getattr(dpkt.pcap, 'DLT_RAW', 12))
        self.assertEqual(status, 'ok')
        self.assertIsNotNone(parsed_ip)
        self.assertEqual(inet_to_str(parsed_ip.src), "192.168.1.10")

        # 5. Truncated frame
        parsed_ip, status = extract_ip_packet(b'\x45\x00', getattr(dpkt.pcap, 'DLT_RAW', 12))
        self.assertEqual(status, 'truncated')
        self.assertIsNone(parsed_ip)

    def test_tcp_stream_reassembly_multi_segment_http(self):
        """[V3-06] Reassemble gói tin HTTP request bị chia làm nhiều segment TCP."""
        reassembler = SimpleTcpStreamReassembler(max_streams=10, max_stream_bytes=4096)
        stream_key = ("192.168.1.10", 54321, "10.0.0.1", 80)
        
        seg1 = b"GET /vulnerable_path?id=1%27%20OR%20%271%27=%271 HTTP/1.1\r\nHost: target.local\r\n"
        seg2 = b"User-Agent: sqlmap/1.4\r\nAccept: */*\r\n\r\n"
        
        # Segment 1 gửi trước
        buf1 = reassembler.add_segment(stream_key, 1000, seg1, 100.0)
        self.assertNotIn(b"\r\n\r\n", buf1)
        
        # Segment 2 gửi tiếp
        buf2 = reassembler.add_segment(stream_key, 1000 + len(seg1), seg2, 100.1)
        self.assertIn(b"\r\n\r\n", buf2)
        
        # Parse HTTP request từ buffer sau khi ghép nối thành công
        req = dpkt.http.Request(buf2)
        self.assertEqual(req.method, "GET")
        self.assertIn("vulnerable_path", req.uri)
        self.assertEqual(req.headers['user-agent'], "sqlmap/1.4")
        
        # Dọn dẹp stream
        reassembler.remove_stream(stream_key)
        self.assertNotIn(stream_key, reassembler.streams)

    def test_get_parser_stats(self):
        """[V3-06] Lấy thống kê parser từ DataFrame."""
        df = pd.DataFrame([{'Source IP': '10.0.0.1'}])
        df.attrs['parser_stats'] = {
            'total_packets': 100,
            'parsed_packets': 95,
            'skipped_packets': 3,
            'truncated_packets': 2,
            'unsupported_packets': 0,
            'datalink_name': 'Ethernet'
        }
        stats = get_parser_stats(df)
        self.assertEqual(stats['total_packets'], 100)
        self.assertEqual(stats['skipped_packets'], 3)
        self.assertEqual(stats['truncated_packets'], 2)

    def test_regression_final_04_out_of_order_and_retransmission(self):
        """[FINAL-04] Reassembler ghép đúng out-of-order và không nhân đôi khi retransmission."""
        reassembler = SimpleTcpStreamReassembler(max_streams=10, max_stream_bytes=4096)
        stream_key = ("192.168.1.50", 12345, "10.0.0.1", 80)

        # Segment 'world' seq=105 đến trước
        buf1 = reassembler.add_segment(stream_key, 105, b"world", 100.0)
        # Segment 'hello' seq=100 đến sau
        buf2 = reassembler.add_segment(stream_key, 100, b"hello", 100.1)
        self.assertEqual(buf2, b"helloworld", "Out-of-order segment phải được sắp xếp theo seq number!")

        # Gửi lại segment 'hello' seq=100 (Retransmission)
        buf3 = reassembler.add_segment(stream_key, 100, b"hello", 100.2)
        self.assertEqual(buf3, b"helloworld", "Retransmission trùng seq không được lặp lại dữ liệu!")
        self.assertGreaterEqual(reassembler.stats['retransmissions_ignored'], 1)

    def test_regression_final_04_partial_overlap_and_gap(self):
        """[FINAL-04] Reassembler cắt phần overlap và nhận diện khoảng cách (gap) không ghép sai."""
        reassembler = SimpleTcpStreamReassembler(max_streams=10, max_stream_bytes=4096)
        stream_key = ("192.168.1.50", 12346, "10.0.0.1", 80)

        # 1. Partial overlap: 'hello' tại 100, 'loworld' tại 103 (chồng lấn 'lo' 2 bytes)
        reassembler.add_segment(stream_key, 100, b"hello", 10.0)
        buf_overlap = reassembler.add_segment(stream_key, 103, b"loworld", 10.1)
        self.assertEqual(buf_overlap, b"helloworld", "Partial overlap phải được cắt đúng để cho ra 'helloworld'!")

        # 2. Gap: Gửi segment cách xa sau gap
        stream_gap_key = ("192.168.1.50", 12347, "10.0.0.1", 80)
        reassembler.add_segment(stream_gap_key, 100, b"GET /page ", 20.0)
        # Gói tiếp theo tại 200 (thiếu đoạn 110-199)
        buf_gap = reassembler.add_segment(stream_gap_key, 200, b"HTTP/1.1\r\n\r\n", 20.1)
        self.assertEqual(buf_gap, b"GET /page ", "Khi có gap, reassembler chỉ được trả về buffer liên tục từ base sequence!")

    def test_regression_final_04_pcap_integration_fin_with_payload(self):
        """[FINAL-04] Integration test: PCAP thật chứa gói tin FIN có payload và out-of-order HTTP request."""
        import io
        import time

        pcap_io = io.BytesIO()
        writer = dpkt.pcap.Writer(pcap_io)

        src_ip = socket.inet_aton("192.168.1.10")
        dst_ip = socket.inet_aton("10.0.0.5")

        # Gói 1: TCP SYN từ client (seq=1000)
        tcp1 = dpkt.tcp.TCP(sport=54321, dport=80, seq=1000, ack=0, flags=dpkt.tcp.TH_SYN, data=b"")
        ip1 = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP, data=tcp1)
        eth1 = dpkt.ethernet.Ethernet(src=b'\x00'*6, dst=b'\xff'*6, type=dpkt.ethernet.ETH_TYPE_IP, data=bytes(ip1))
        writer.writepkt(bytes(eth1), ts=1000.0)

        # Gói 2: HTTP part 2 (seq=1028) đến trước (Out-of-order): Host và header
        seg2_data = b"Host: target.corp\r\nUser-Agent: FinalTestAgent/1.0\r\n\r\n"
        tcp2 = dpkt.tcp.TCP(sport=54321, dport=80, seq=1028, ack=1, flags=dpkt.tcp.TH_ACK, data=seg2_data)
        ip2 = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP, data=tcp2)
        eth2 = dpkt.ethernet.Ethernet(src=b'\x00'*6, dst=b'\xff'*6, type=dpkt.ethernet.ETH_TYPE_IP, data=bytes(ip2))
        writer.writepkt(bytes(eth2), ts=1000.1)

        # Gói 3: HTTP part 1 (seq=1001) đến sau, đồng thời có cờ FIN (Payload on FIN): "GET /critical_admin HTTP/1.1\r\n" (len=27)
        seg1_data = b"GET /critical_admin HTTP/1.1\r\n"
        tcp3 = dpkt.tcp.TCP(sport=54321, dport=80, seq=1001, ack=1, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_FIN, data=seg1_data)
        ip3 = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=dpkt.ip.IP_PROTO_TCP, data=tcp3)
        eth3 = dpkt.ethernet.Ethernet(src=b'\x00'*6, dst=b'\xff'*6, type=dpkt.ethernet.ETH_TYPE_IP, data=bytes(ip3))
        writer.writepkt(bytes(eth3), ts=1000.2)

        pcap_bytes = pcap_io.getvalue()
        
        # Chạy load_pcap với Bytes PCAP thật
        df = load_pcap(pcap_bytes)
        self.assertFalse(df.empty)
        
        # Tìm packet có URI /critical_admin
        http_rows = df[df['HTTP_URI'].notna() & (df['HTTP_URI'] != "")]
        self.assertEqual(len(http_rows), 1, "load_pcap phải reassemble và nhận dạng được HTTP Request dù out-of-order và có FIN!")
        self.assertEqual(http_rows.iloc[0]['HTTP_URI'], "/critical_admin")
        self.assertEqual(http_rows.iloc[0]['HTTP_Method'], "GET")
        self.assertEqual(http_rows.iloc[0]['HTTP_UA'], "FinalTestAgent/1.0")

if __name__ == '__main__':
    unittest.main()
