import unittest
import pandas as pd
import datetime
from modules.constants import Col
from modules.security import (
    PORT_SCAN_COLUMNS,
    WEB_ATTACK_COLUMNS,
    THREAT_IP_COLUMNS,
    DNS_COLUMNS,
    DOS_BRUTEFORCE_COLUMNS,
    TLS_SNI_COLUMNS,
    detect_port_scan,
    detect_dos_bruteforce,
    detect_suspicious_tls_sni,
    detect_abnormal_dns,
    detect_web_attacks,
    detect_suspicious_ips,
    calculate_entropy,
    is_public_ip
)

class TestSecurityModule(unittest.TestCase):
    def test_empty_inputs(self):
        empty_df = pd.DataFrame()
        
        # 1. Port scan on empty df
        ps_df = detect_port_scan(empty_df)
        self.assertIsInstance(ps_df, pd.DataFrame)
        self.assertEqual(list(ps_df.columns), PORT_SCAN_COLUMNS)
        self.assertTrue(ps_df.empty)
        
        # 2. DoS / Brute-force on empty df
        dos_df = detect_dos_bruteforce(empty_df)
        self.assertIsInstance(dos_df, pd.DataFrame)
        self.assertEqual(list(dos_df.columns), DOS_BRUTEFORCE_COLUMNS)
        self.assertTrue(dos_df.empty)
        
        # 3. TLS SNI on empty df
        tls_df = detect_suspicious_tls_sni(empty_df)
        self.assertIsInstance(tls_df, pd.DataFrame)
        self.assertEqual(list(tls_df.columns), TLS_SNI_COLUMNS)
        self.assertTrue(tls_df.empty)
        
        # 4. Abnormal DNS on empty df
        dns_res = detect_abnormal_dns(empty_df)
        self.assertIn('inbound_probes', dns_res)
        self.assertIn('outbound_tunneling', dns_res)
        self.assertIn('all_queries', dns_res)
        self.assertEqual(list(dns_res['all_queries'].columns), DNS_COLUMNS)
        
        # 5. Web attacks on empty df
        web_df = detect_web_attacks(empty_df)
        self.assertIsInstance(web_df, pd.DataFrame)
        self.assertEqual(list(web_df.columns), WEB_ATTACK_COLUMNS)
        self.assertTrue(web_df.empty)
        
        # 6. Suspicious IPs on empty inputs
        threat_ips = detect_suspicious_ips(empty_df)
        self.assertIsInstance(threat_ips, pd.DataFrame)
        self.assertEqual(list(threat_ips.columns), THREAT_IP_COLUMNS)
        self.assertTrue(threat_ips.empty)

    def test_entropy_calculation(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy("aaaaaa"), 0.0)
        # High entropy string
        h_entropy = calculate_entropy("v8x9a2k1m4z7q3w5")
        self.assertGreater(h_entropy, 3.5)

    def test_public_ip_helper(self):
        self.assertFalse(is_public_ip("192.168.1.1"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertFalse(is_public_ip("invalid_ip"))

    def test_port_scan_detection(self):
        now = datetime.datetime.now()
        data = []
        # Create 10 distinct SYN packets to different ports from 192.168.1.100
        for port in range(20, 30):
            data.append({
                'Timestamp': now,
                'Source IP': '192.168.1.100',
                'Dest IP': '192.168.1.1',
                'Dest Port': port,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        ps_df = detect_port_scan(df, port_threshold=7)
        self.assertEqual(len(ps_df), 1)
        self.assertEqual(ps_df.iloc[0]['Source IP'], '192.168.1.100')
        self.assertEqual(ps_df.iloc[0]['Scanned Ports Count'], 10)

    def test_web_attack_false_positive_fix(self):
        """Kiểm tra URL .php? thông thường không bị báo nhầm RCE nhưng URL độc hại vẫn bị bắt."""
        now = datetime.datetime.now()
        df = pd.DataFrame([
            # 1. URL bình thường - KHÔNG được coi là tấn công
            {'Timestamp': now, 'Source IP': '10.0.0.5', 'Dest IP': '10.0.0.1', 'HTTP_URI': '/index.php?page=home', 'HTTP_Method': 'GET', 'HTTP_UA': 'Mozilla/5.0'},
            {'Timestamp': now, 'Source IP': '10.0.0.5', 'Dest IP': '10.0.0.1', 'HTTP_URI': '/profile.php?id=123', 'HTTP_Method': 'GET', 'HTTP_UA': 'Mozilla/5.0'},
            # 2. URL tấn công thực sự - PHẢI bị phát hiện
            {'Timestamp': now, 'Source IP': '192.168.1.50', 'Dest IP': '10.0.0.1', 'HTTP_URI': '/vulnerable.php?cmd=id', 'HTTP_Method': 'GET', 'HTTP_UA': 'Mozilla/5.0'},
            {'Timestamp': now, 'Source IP': '192.168.1.51', 'Dest IP': '10.0.0.1', 'HTTP_URI': '/download.php?file=../../../../etc/passwd', 'HTTP_Method': 'GET', 'HTTP_UA': 'Mozilla/5.0'},
            {'Timestamp': now, 'Source IP': '192.168.1.52', 'Dest IP': '10.0.0.1', 'HTTP_URI': '/.env', 'HTTP_Method': 'GET', 'HTTP_UA': 'Mozilla/5.0'}
        ])
        web_df = detect_web_attacks(df)
        flagged_ips = web_df['Source IP'].tolist()
        self.assertNotIn('10.0.0.5', flagged_ips, "URL PHP thông thường không được bị gắn nhãn tấn công!")
        self.assertIn('192.168.1.50', flagged_ips)
        self.assertIn('192.168.1.51', flagged_ips)
        self.assertIn('192.168.1.52', flagged_ips)

    def test_tls_sni_classification(self):
        """Kiểm tra logic vector hóa phân loại TLS SNI."""
        now = datetime.datetime.now()
        df = pd.DataFrame([
            {'Timestamp': now, 'Source IP': '10.0.0.2', 'Dest IP': '1.1.1.1', 'TLS_SNI': 'www.google.com'},
            {'Timestamp': now, 'Source IP': '10.0.0.2', 'Dest IP': '2.2.2.2', 'TLS_SNI': 'malicious-c2.xyz'},
            {'Timestamp': now, 'Source IP': '10.0.0.2', 'Dest IP': '3.3.3.3', 'TLS_SNI': '192.168.100.1'},
            {'Timestamp': now, 'Source IP': '10.0.0.2', 'Dest IP': '4.4.4.4', 'TLS_SNI': 'a9z8y7x6w5v4u3t2s1r0.duckdns.org'}
        ])
        tls_res = detect_suspicious_tls_sni(df)
        self.assertEqual(len(tls_res), 4)
        classes = dict(zip(tls_res['TLS_SNI'], tls_res['Classification']))
        self.assertEqual(classes['www.google.com'], 'Legitimate HTTPS')
        self.assertEqual(classes['malicious-c2.xyz'], 'Suspicious Dynamic DNS')
        self.assertEqual(classes['192.168.100.1'], 'Suspicious C2 (Direct IP)')

    def test_dos_bruteforce_detection(self):
        """Kiểm tra phát hiện Brute-Force vào SSH port 22."""
        now = datetime.datetime.now()
        data = []
        for i in range(25):
            data.append({
                'Timestamp': now + datetime.timedelta(seconds=i),
                'Source IP': '192.168.1.200',
                'Dest IP': '192.168.1.1',
                'Dest Port': 22,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        dos_df = detect_dos_bruteforce(df, single_port_syn_threshold=15)
        self.assertEqual(len(dos_df), 1)
        self.assertEqual(dos_df.iloc[0]['Source IP'], '192.168.1.200')
        self.assertEqual(dos_df.iloc[0]['Target Service'], 'SSH')

    def test_web_attack_info_based_parsing(self):
        """Kiểm tra nhánh fallback khi dữ liệu HTTP nằm trong cột Info."""
        now = datetime.datetime.now()
        df = pd.DataFrame([
            {'Timestamp': now, 'Source IP': '10.0.0.5', 'Dest IP': '10.0.0.1', 'Info': 'HTTP GET /.env'},
            {'Timestamp': now, 'Source IP': '10.0.0.6', 'Dest IP': '10.0.0.1', 'Info': 'HTTP GET /index.html'},
            {'Timestamp': now, 'Source IP': '10.0.0.7', 'Dest IP': '10.0.0.1', 'Info': 'HTTP POST /vulnerable.php?cmd=whoami'}
        ])
        web_df = detect_web_attacks(df)
        flagged_ips = web_df['Source IP'].tolist()
        self.assertIn('10.0.0.5', flagged_ips)
        self.assertNotIn('10.0.0.6', flagged_ips)
        self.assertIn('10.0.0.7', flagged_ips)

    def test_abnormal_dns_vectorized(self):
        """Kiểm tra logic phân loại DNS vectorized (Probes vs Outbound Tunneling)."""
        now = datetime.datetime.now()
        df = pd.DataFrame([
            {'Timestamp': now, 'Source IP': '1.1.1.1', 'Dest IP': '10.0.0.1', 'Dest Port': 53, 'Info': 'DNS Query: version.bind'},
            {'Timestamp': now, 'Source IP': '10.0.0.1', 'Dest IP': '8.8.8.8', 'Dest Port': 53, 'Info': 'DNS Query: google.com'},
            {'Timestamp': now, 'Source IP': '10.0.0.1', 'Dest IP': '8.8.8.8', 'Dest Port': 53, 'Info': 'DNS Query: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.tunnel.com'}
        ])
        dns_res = detect_abnormal_dns(df, server_ip='10.0.0.1')
        self.assertEqual(dns_res['summary']['inbound_count'], 1)
        self.assertEqual(dns_res['summary']['suspicious_tunneling_count'], 1)

    def test_suspicious_ips_multi_vector(self):
        """Kiểm tra IP xuất hiện ở cả Port Scan và Web Attack được gắn Multi-vector."""
        port_scans = pd.DataFrame([{
            'Source IP': '10.0.0.99', 'Scanned Ports Count': 15,
            'Total Packets': 30, 'Targeted Ports': '22, 80, 443',
            'Scan Type': 'TCP SYN Scan', 'First Seen': None, 'Last Seen': None
        }])
        web_attacks = pd.DataFrame([{
            'Timestamp': datetime.datetime.now(), 'Source IP': '10.0.0.99',
            'Dest IP': '10.0.0.1', 'Method': 'GET', 'URI': '/.env',
            'Attack Category': 'Sensitive File', 'User-Agent': ''
        }])
        result = detect_suspicious_ips(
            pd.DataFrame(), port_scans_df=port_scans, web_attacks_df=web_attacks
        )
        self.assertEqual(len(result), 1)
        self.assertIn('Multi-vector', result.iloc[0]['Threat Category'])
        self.assertEqual(result.iloc[0]['Risk Level'], 'Cao')

    def test_web_attack_double_url_decode(self):
        """Kiểm tra phát hiện tấn công bị mã hóa URL (Double URL Encoding)."""
        now = datetime.datetime.now()
        df = pd.DataFrame([
            # Double encoded ../../../../etc/passwd -> %252e%252e%252f...
            {
                'Timestamp': now,
                'Source IP': '192.168.1.77',
                'Dest IP': '10.0.0.1',
                'HTTP_URI': '/download.php?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd',
                'HTTP_Method': 'GET',
                'HTTP_UA': 'Mozilla/5.0'
            }
        ])
        web_df = detect_web_attacks(df)
        self.assertEqual(len(web_df), 1)
        self.assertEqual(web_df.iloc[0]['Source IP'], '192.168.1.77')
        self.assertIn('Path Traversal', web_df.iloc[0]['Attack Category'])

    def test_web_attack_http_body_sqli(self):
        """Kiểm tra phát hiện SQL Injection nằm trong HTTP Body (POST request)."""
        now = datetime.datetime.now()
        df = pd.DataFrame([
            {
                'Timestamp': now,
                'Source IP': '192.168.1.88',
                'Dest IP': '10.0.0.1',
                'HTTP_URI': '/api/v1/login',
                'HTTP_Body': '{"username": "admin\' OR \'1\'=\'1", "password": "123"}',
                'HTTP_Method': 'POST',
                'HTTP_UA': 'Mozilla/5.0'
            }
        ])
        web_df = detect_web_attacks(df)
        self.assertEqual(len(web_df), 1)
        self.assertEqual(web_df.iloc[0]['Source IP'], '192.168.1.88')
        self.assertIn('SQL Injection', web_df.iloc[0]['Attack Category'])

    def test_udp_port_scan_detection(self):
        """Kiểm tra phát hiện hành vi quét cổng UDP (nmap -sU)."""
        now = datetime.datetime.now()
        data = []
        for port in range(50, 60):
            data.append({
                'Timestamp': now,
                'Source IP': '192.168.1.150',
                'Dest IP': '192.168.1.1',
                'Dest Port': port,
                'Protocol': 'UDP'
            })
        df = pd.DataFrame(data)
        ps_df = detect_port_scan(df, port_threshold=7)
        self.assertEqual(len(ps_df), 1)
        self.assertEqual(ps_df.iloc[0]['Source IP'], '192.168.1.150')
        self.assertEqual(ps_df.iloc[0]['Scan Type'], 'UDP Port Scan')

    def test_dos_rate_limiting_prevents_false_positive(self):
        """Kiểm tra: Gói tin chậm 1 gói/giây KHÔNG bị gắn nhãn DoS; Gói tin dồn dập BỊ gắn nhãn DoS."""
        now = datetime.datetime.now()
        
        # 1. Lưu lượng bình thường: 50 gói ICMP rải đều trong 50 giây (rate = 1.0 pps < min_pps_threshold 3.0)
        slow_data = []
        for i in range(50):
            slow_data.append({
                'Timestamp': now + datetime.timedelta(seconds=i),
                'Source IP': '192.168.1.10',
                'Dest IP': '10.0.0.1',
                'Protocol': 'ICMP'
            })
        slow_df = pd.DataFrame(slow_data)
        slow_res = detect_dos_bruteforce(slow_df, flood_threshold=40, min_pps_threshold=3.0)
        self.assertTrue(slow_res.empty, "Lưu lượng ping chậm (1 PPS) không được bị coi là ICMP Flood!")

        # 2. Tấn công DoS thật sự: 50 gói ICMP dồn trong 1 giây (rate = 50.0 pps > min_pps_threshold 3.0)
        flood_data = []
        for i in range(50):
            flood_data.append({
                'Timestamp': now,
                'Source IP': '192.168.1.99',
                'Dest IP': '10.0.0.1',
                'Protocol': 'ICMP'
            })
        flood_df = pd.DataFrame(flood_data)
        flood_res = detect_dos_bruteforce(flood_df, flood_threshold=40, min_pps_threshold=3.0)
        self.assertEqual(len(flood_res), 1)
        self.assertEqual(flood_res.iloc[0]['Attack Type'], 'ICMP Flood')
        self.assertEqual(flood_res.iloc[0]['Source IP'], '192.168.1.99')

    def test_regression_p0_01_threat_ip_category_zero_counts(self):
        """[P0-01] Kiểm tra pandas category value_counts với count=0 không bị thêm vào threat_map."""
        now = datetime.datetime.now()
        categories = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '10.0.0.99']
        web_df = pd.DataFrame({
            'Timestamp': [now],
            'Source IP': pd.Categorical(['10.0.0.99'], categories=categories),
            'Dest IP': ['192.168.1.1'],
            'Method': ['GET'],
            'URI': ['/.env'],
            'Attack Category': ['Khai Thác Tệp Nhạy Cảm'],
            'User-Agent': ['curl/7.68.0']
        })
        threat_ips = detect_suspicious_ips(pd.DataFrame(), server_ip='192.168.1.1', web_attacks_df=web_df)
        self.assertEqual(len(threat_ips), 1)
        self.assertEqual(threat_ips.iloc[0]['IP'], '10.0.0.99')
        self.assertEqual(threat_ips.iloc[0]['Hit Count'], 1)
        self.assertTrue((threat_ips['Hit Count'] > 0).all())

    def test_regression_p0_02_server_scope_isolation(self):
        """[P0-02] Kiểm tra lưu lượng transit giữa 2 IP khác không bị gán cho server_ip đã chọn."""
        now = datetime.datetime.now()
        data = []
        for port in range(20, 30):
            data.append({
                'Timestamp': now + datetime.timedelta(seconds=port),
                'Source IP': '203.0.113.5',
                'Dest IP': '203.0.113.10',
                'Dest Port': port,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        
        # Khi server_ip là 203.0.113.99 (khác 203.0.113.10)
        ps_df = detect_port_scan(df, server_ip='203.0.113.99', port_threshold=7)
        self.assertTrue(ps_df.empty, "Lưu lượng đến 203.0.113.10 không được báo là scan server 203.0.113.99")
        
        # Khi server_ip chính xác là 203.0.113.10 thì phải bắt được
        ps_df_target = detect_port_scan(df, server_ip='203.0.113.10', port_threshold=7)
        self.assertEqual(len(ps_df_target), 1)
        self.assertEqual(ps_df_target.iloc[0]['Source IP'], '203.0.113.5')

    def test_regression_p0_03_port_scan_sliding_time_window(self):
        """[P0-03] Kiểm tra cửa sổ thời gian: 7 gói rải 7 ngày không bị báo; 7 gói trong 30s bị bắt."""
        base_time = datetime.datetime(2026, 9, 1, 12, 0, 0)
        
        # 1. 7 gói SYN gửi rải rác mỗi ngày 1 cổng trong 7 ngày
        slow_data = []
        for day in range(7):
            slow_data.append({
                'Timestamp': base_time + datetime.timedelta(days=day),
                'Source IP': '192.168.1.200',
                'Dest IP': '192.168.1.1',
                'Dest Port': 80 + day,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        slow_df = pd.DataFrame(slow_data)
        slow_res = detect_port_scan(slow_df, time_window='60s', port_threshold=7)
        self.assertTrue(slow_res.empty, "7 gói SYN rải trong 7 ngày không được bị coi là Port Scan trong cửa sổ 60s!")

        # 2. 7 gói SYN gửi trong 30s qua biên phút (12:00:45 đến 12:01:15)
        fast_data = []
        start_ts = datetime.datetime(2026, 9, 1, 12, 0, 45)
        for i in range(7):
            fast_data.append({
                'Timestamp': start_ts + datetime.timedelta(seconds=i * 5),
                'Source IP': '192.168.1.200',
                'Dest IP': '192.168.1.1',
                'Dest Port': 80 + i,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        fast_df = pd.DataFrame(fast_data)
        fast_res = detect_port_scan(fast_df, time_window='60s', port_threshold=7)
        self.assertEqual(len(fast_res), 1)
        self.assertEqual(fast_res.iloc[0]['Source IP'], '192.168.1.200')
        self.assertEqual(fast_res.iloc[0]['Scanned Ports Count'], 7)

    def test_regression_p0_04_dns_outbound_query_not_probe(self):
        """[P0-04] Truy vấn bình thường 10.0.0.5 -> 8.8.8.8:53 không bị gắn DNS Probe."""
        now = datetime.datetime.now()
        df = pd.DataFrame([{
            'Timestamp': now,
            'Source IP': '10.0.0.5',
            'Dest IP': '8.8.8.8',
            'Source Port': 54321,
            'Dest Port': 53,
            'Protocol': 'UDP',
            'Info': 'DNS Query: google.com'
        }])
        
        # Khi server_ip là web server 203.161.44.208
        dns_res = detect_abnormal_dns(df, server_ip='203.161.44.208')
        self.assertTrue(dns_res['inbound_probes'].empty, "Truy vấn ra ngoài 8.8.8.8 không được gắn Inbound Probe!")
        
        # Khi không chỉ định server_ip
        dns_res_no_srv = detect_abnormal_dns(df)
        self.assertTrue(dns_res_no_srv['inbound_probes'].empty, "Truy vấn chuẩn google.com không được gắn Inbound Probe!")
        all_q = dns_res_no_srv['all_queries']
        self.assertEqual(all_q.iloc[0]['Classification'], 'Legitimate Outbound DNS')

    def test_regression_p0_05_tls_monitored_server_not_threat_actor(self):
        """[P0-05] Máy chủ giám sát không bao giờ bị đưa vào Threat IP do chính SNI của nó."""
        now = datetime.datetime.now()
        server_ip = '203.161.44.208'
        attacker_ip = '198.51.100.22'
        
        df = pd.DataFrame([{
            'Timestamp': now,
            'Source IP': attacker_ip,
            'Dest IP': server_ip,
            'Protocol': 'TCP',
            'TLS_SNI': '192.168.1.1'
        }])
        
        tls_df = detect_suspicious_tls_sni(df, server_ip=server_ip)
        self.assertEqual(len(tls_df), 1)
        
        threat_ips = detect_suspicious_ips(df, server_ip=server_ip, tls_df=tls_df)
        self.assertNotIn(server_ip, threat_ips['IP'].tolist())
        self.assertIn(attacker_ip, threat_ips['IP'].tolist())

    def test_regression_r0_01_inbound_normal_query_not_probe_and_resolver_not_c2(self):
        """[R0-01] Query example.com không nằm trong probe table; Resolver 8.8.8.8 không bao giờ bị gắn C2."""
        now = datetime.datetime.now()
        df = pd.DataFrame([
            # 1. Client hỏi example.com vào DNS server giám sát 10.0.0.1:53 -> Inbound Query, không phải Probe
            {'Timestamp': now, 'Source IP': '198.51.100.30', 'Dest IP': '10.0.0.1', 'Source Port': 51000, 'Dest Port': 53, 'Protocol': 'UDP', 'Info': 'DNS Query: example.com'},
            # 2. Scanner gửi version.bind vào DNS server -> Probe thực sự
            {'Timestamp': now, 'Source IP': '198.51.100.31', 'Dest IP': '10.0.0.1', 'Source Port': 51001, 'Dest Port': 53, 'Protocol': 'UDP', 'Info': 'DNS Query: version.bind'},
            # 3. Client nội bộ 10.0.0.5 gửi truy vấn DNS tunneling qua Google DNS 8.8.8.8:53
            {'Timestamp': now, 'Source IP': '10.0.0.5', 'Dest IP': '8.8.8.8', 'Source Port': 52000, 'Dest Port': 53, 'Protocol': 'UDP', 'Info': 'DNS Query: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.tunnel.com'}
        ])
        
        dns_res = detect_abnormal_dns(df, server_ip='10.0.0.1')
        self.assertEqual(len(dns_res['inbound_probes']), 1)
        self.assertEqual(dns_res['inbound_probes'].iloc[0]['Domain'], 'version.bind')
        self.assertEqual(len(dns_res['inbound_queries']), 1)
        self.assertEqual(dns_res['inbound_queries'].iloc[0]['Domain'], 'example.com')
        
        threat_ips = detect_suspicious_ips(df, server_ip='10.0.0.1', dns_results=dns_res)
        flagged = threat_ips['IP'].tolist()
        self.assertNotIn('198.51.100.30', flagged, "Client gửi query example.com không được bị gán Threat IP!")
        self.assertNotIn('8.8.8.8', flagged, "Public DNS resolver 8.8.8.8 không bao giờ được bị gán C2!")
        self.assertIn('198.51.100.31', flagged, "Host gửi version.bind phải bị gắn nhãn DNS Resolver Scan")
        self.assertIn('10.0.0.5', flagged, "Host nội bộ gửi tunneling query phải bị quy trách nhiệm")

    def test_regression_r0_02_dos_burst_with_late_packet(self):
        """[R0-02] Burst DoS 50 ICMP trong 0.5s vẫn bị bắt dù có 1 packet đến muộn sau 24 giờ."""
        now = datetime.datetime.now()
        data = []
        for i in range(50):
            data.append({
                'Timestamp': now + datetime.timedelta(milliseconds=i * 10),
                'Source IP': '192.168.1.99',
                'Dest IP': '10.0.0.1',
                'Protocol': 'ICMP'
            })
        # Gói tin lạc đến sau 24 giờ
        data.append({
            'Timestamp': now + datetime.timedelta(hours=24),
            'Source IP': '192.168.1.99',
            'Dest IP': '10.0.0.1',
            'Protocol': 'ICMP'
        })
        df = pd.DataFrame(data)
        dos_df = detect_dos_bruteforce(df, flood_threshold=40, min_pps_threshold=3.0)
        self.assertEqual(len(dos_df), 1)
        self.assertEqual(dos_df.iloc[0]['Attack Type'], 'ICMP Flood')
        self.assertEqual(dos_df.iloc[0]['Packet Count'], 50)
        self.assertGreaterEqual(dos_df.iloc[0]['Peak (pkts/s)'], 25.0)

    def test_regression_r0_02_slow_syn_auth_not_bruteforce(self):
        """[R0-02] 15 SYN SSH rải trong 56 phút không bị khẳng định là brute-force."""
        now = datetime.datetime.now()
        data = []
        for i in range(15):
            data.append({
                'Timestamp': now + datetime.timedelta(seconds=i * 224),
                'Source IP': '192.168.1.200',
                'Dest IP': '192.168.1.1',
                'Dest Port': 22,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        dos_df = detect_dos_bruteforce(df, single_port_syn_threshold=15)
        self.assertTrue(dos_df.empty, "15 SYN SSH rải rác 56 phút không được coi là tấn công!")

    def test_regression_r0_02_high_rate_syn_flood_on_auth_port(self):
        """[R0-02] Tốc độ cao trên port 22 được ưu tiên phân loại Flood thay vì Brute-force."""
        now = datetime.datetime.now()
        data = []
        for i in range(100):
            data.append({
                'Timestamp': now + datetime.timedelta(milliseconds=i * 20),
                'Source IP': '192.168.1.88',
                'Dest IP': '192.168.1.1',
                'Dest Port': 22,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        dos_df = detect_dos_bruteforce(df, single_port_syn_threshold=15, flood_threshold=40)
        self.assertEqual(len(dos_df), 1)
        self.assertIn('Flood', dos_df.iloc[0]['Attack Type'], "SYN tốc độ cao trên port 22 phải được phân loại Flood!")
        self.assertGreaterEqual(dos_df.iloc[0]['Peak (pkts/s)'], 25.0)

    def test_regression_r0_03_port_scan_active_window_event_packet_count(self):
        """[R0-03] Scan 7 cổng trong 7s + 100 SYN sau 1 ngày: Event Packet Count = 7, không phải 107."""
        now = datetime.datetime.now()
        data = []
        for i in range(7):
            data.append({
                'Timestamp': now + datetime.timedelta(seconds=i),
                'Source IP': '192.168.1.50',
                'Dest IP': '192.168.1.1',
                'Dest Port': 80 + i,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        next_day = now + datetime.timedelta(days=1)
        for i in range(100):
            data.append({
                'Timestamp': next_day + datetime.timedelta(seconds=i),
                'Source IP': '192.168.1.50',
                'Dest IP': '192.168.1.1',
                'Dest Port': 80,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        ps_df = detect_port_scan(df, time_window='60s', port_threshold=7)
        self.assertEqual(len(ps_df), 1)
        self.assertEqual(ps_df.iloc[0]['Scanned Ports Count'], 7)
        self.assertEqual(ps_df.iloc[0]['Total Packets'], 7, "Total Packets phải là số gói trong scan event, không phải 107!")

    def test_regression_r0_03_port_scan_multiple_targets_preserved(self):
        """[R0-03] Quét 2 server khác nhau tạo 2 sự kiện riêng biệt, không bị gộp làm mất Target IP."""
        now = datetime.datetime.now()
        data = []
        for i in range(10):
            data.append({
                'Timestamp': now + datetime.timedelta(seconds=i),
                'Source IP': '192.168.1.70',
                'Dest IP': '10.0.0.10',
                'Dest Port': 20 + i,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        for i in range(10):
            data.append({
                'Timestamp': now + datetime.timedelta(seconds=i),
                'Source IP': '192.168.1.70',
                'Dest IP': '10.0.0.20',
                'Dest Port': 30 + i,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        ps_df = detect_port_scan(df, port_threshold=7)
        self.assertEqual(len(ps_df), 2, "Quét 2 target khác nhau phải tạo 2 records riêng biệt!")
        dest_ips = set(ps_df['Dest IP'].tolist())
        self.assertEqual(dest_ips, {'10.0.0.10', '10.0.0.20'})

    def test_regression_r1_03_sni_invalid_ip_not_direct_ip(self):
        """[R1-03] SNI '999.999.999.999' không hợp lệ không được gắn Direct IP C2."""
        now = datetime.datetime.now()
        df = pd.DataFrame([
            {'Timestamp': now, 'Source IP': '10.0.0.2', 'Dest IP': '1.1.1.1', 'TLS_SNI': '999.999.999.999'},
            {'Timestamp': now, 'Source IP': '10.0.0.2', 'Dest IP': '2.2.2.2', 'TLS_SNI': '192.168.1.1'}
        ])
        tls_res = detect_suspicious_tls_sni(df)
        classes = dict(zip(tls_res['TLS_SNI'], tls_res['Classification']))
        self.assertNotEqual(classes['999.999.999.999'], 'Suspicious C2 (Direct IP)', "999.999.999.999 không phải IPv4 hợp lệ!")
        self.assertEqual(classes['192.168.1.1'], 'Suspicious C2 (Direct IP)')

    def test_regression_v3_01_dos_consistent_evidence_window_prevents_cross_day_false_positive(self):
        """[V3-01] Ngày 1 có 40 ICMP chậm (1.5s/gói, rate 0.68 pps); Ngày 2 có 3 ICMP nhanh (0.8s) -> KHÔNG được báo DoS."""
        t_day1 = datetime.datetime(2026, 9, 10, 8, 0, 0)
        t_day2 = datetime.datetime(2026, 9, 11, 8, 0, 0)
        data = []
        # Ngày 1: 40 gói trong 58.5 giây, cách nhau 1.5 giây (không có khoảng 1s nào đạt >= 3 pps)
        for i in range(40):
            data.append({
                'Timestamp': t_day1 + datetime.timedelta(seconds=i * 1.5),
                'Source IP': '192.168.1.55',
                'Dest IP': '10.0.0.1',
                'Protocol': 'ICMP'
            })
        # Ngày 2: 3 gói trong 0.8 giây (peak cao ~3.75 pps nhưng count=3 < 40)
        for i in range(3):
            data.append({
                'Timestamp': t_day2 + datetime.timedelta(seconds=i * 0.4),
                'Source IP': '192.168.1.55',
                'Dest IP': '10.0.0.1',
                'Protocol': 'ICMP'
            })
        df = pd.DataFrame(data)
        dos_df = detect_dos_bruteforce(df, flood_threshold=40, min_pps_threshold=3.0)
        self.assertTrue(dos_df.empty, "Không được ghép count của ngày 1 với peak của ngày 2 để báo động giả ICMP Flood!")

    def test_regression_v3_01_valid_burst_with_noise_evidence_isolated(self):
        """[V3-01] Một burst flood thật ngày 1 và cụm nhiễu nhanh ngày 2 -> bằng chứng trả về nằm hoàn toàn ở ngày 1."""
        t_day1 = datetime.datetime(2026, 9, 10, 8, 0, 0)
        t_day2 = datetime.datetime(2026, 9, 11, 8, 0, 0)
        data = []
        # Ngày 1: 50 gói ICMP trong 1.0 giây (Flood thật: count 50 >= 40, peak 50 >= 3.0)
        for i in range(50):
            data.append({
                'Timestamp': t_day1 + datetime.timedelta(seconds=i * 0.02),
                'Source IP': '192.168.1.66',
                'Dest IP': '10.0.0.1',
                'Protocol': 'ICMP'
            })
        # Ngày 2: 3 gói ICMP nhanh trong 0.1 giây (nhiễu)
        for i in range(3):
            data.append({
                'Timestamp': t_day2 + datetime.timedelta(seconds=i * 0.05),
                'Source IP': '192.168.1.66',
                'Dest IP': '10.0.0.1',
                'Protocol': 'ICMP'
            })
        df = pd.DataFrame(data)
        dos_df = detect_dos_bruteforce(df, flood_threshold=40, min_pps_threshold=3.0)
        self.assertEqual(len(dos_df), 1)
        record = dos_df.iloc[0]
        self.assertEqual(record['Attack Type'], 'ICMP Flood')
        self.assertEqual(record['Packet Count'], 50)
        self.assertEqual(record['First Seen'], t_day1)
        self.assertLess(record['Last Seen'], t_day1 + datetime.timedelta(seconds=2))
        self.assertGreaterEqual(record['Peak (pkts/s)'], 20.0)

    def test_regression_v3_02_dos_performance_many_singletons(self):
        """[V3-02] Xử lý hàng chục nghìn nhóm singleton siêu tốc và phát hiện chính xác nhóm attack."""
        import time
        now = datetime.datetime(2026, 9, 14, 10, 0, 0)
        data = []
        # 30,000 group singleton (1 gói tin/group)
        for i in range(30000):
            data.append({
                'Timestamp': now + datetime.timedelta(milliseconds=i),
                'Source IP': f"10.1.{i // 256}.{i % 256}",
                'Dest IP': '192.168.1.1',
                'Source Port': 40000,
                'Dest Port': 80,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        # 1 nhóm tấn công thật: 60 gói SYN trong 0.5 giây
        for i in range(60):
            data.append({
                'Timestamp': now + datetime.timedelta(milliseconds=i * 8),
                'Source IP': '192.168.99.99',
                'Dest IP': '192.168.1.1',
                'Source Port': 50000 + i,
                'Dest Port': 80,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        
        start_time = time.time()
        dos_df = detect_dos_bruteforce(df, single_port_syn_threshold=15, flood_threshold=40)
        elapsed = time.time() - start_time
        
        self.assertLess(elapsed, 2.0, f"detect_dos_bruteforce mất {elapsed:.2f}s, phải hoàn tất < 2.0s!")
        self.assertEqual(len(dos_df), 1)
        self.assertEqual(dos_df.iloc[0]['Source IP'], '192.168.99.99')

    def test_regression_v3_03_port_scan_session_split_across_days(self):
        """[V3-03] Hai đợt port scan giống nhau cách nhau 1 ngày phải trả về đúng 2 record độc lập."""
        t_day1 = datetime.datetime(2026, 9, 10, 8, 0, 0)
        t_day2 = datetime.datetime(2026, 9, 11, 8, 0, 0)
        data = []
        # Ngày 1: Quét 7 port trong 7 giây
        for i in range(7):
            data.append({
                'Timestamp': t_day1 + datetime.timedelta(seconds=i),
                'Source IP': '192.168.1.88',
                'Dest IP': '10.0.0.5',
                'Dest Port': 100 + i,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        # Ngày 2: Lặp lại quét 7 port trong 7 giây
        for i in range(7):
            data.append({
                'Timestamp': t_day2 + datetime.timedelta(seconds=i),
                'Source IP': '192.168.1.88',
                'Dest IP': '10.0.0.5',
                'Dest Port': 100 + i,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        ps_df = detect_port_scan(df, port_threshold=7)
        self.assertEqual(len(ps_df), 2, "Hai đợt scan cách nhau 1 ngày phải tạo đúng 2 record riêng biệt!")
        # Kiểm tra record 1 (Ngày 1)
        self.assertEqual(ps_df.iloc[0]['Total Packets'], 7)
        self.assertEqual(ps_df.iloc[0]['Scanned Ports Count'], 7)
        self.assertEqual(ps_df.iloc[0]['First Seen'], t_day1)
        self.assertEqual(ps_df.iloc[0]['Last Seen'], t_day1 + datetime.timedelta(seconds=6))
        # Kiểm tra record 2 (Ngày 2)
        self.assertEqual(ps_df.iloc[1]['Total Packets'], 7)
        self.assertEqual(ps_df.iloc[1]['Scanned Ports Count'], 7)
        self.assertEqual(ps_df.iloc[1]['First Seen'], t_day2)
        self.assertEqual(ps_df.iloc[1]['Last Seen'], t_day2 + datetime.timedelta(seconds=6))

    def test_regression_v3_03_port_scan_burst_overlapping_windows_merged(self):
        """[V3-03] Các cửa sổ trượt chồng lấn trong cùng 1 burst liên tục không bị nhân đôi thành nhiều record."""
        now = datetime.datetime(2026, 9, 14, 11, 0, 0)
        data = []
        # Quét 10 port liên tục trong 5 giây (mỗi 0.5s một gói)
        for i in range(10):
            data.append({
                'Timestamp': now + datetime.timedelta(seconds=i * 0.5),
                'Source IP': '192.168.1.77',
                'Dest IP': '10.0.0.5',
                'Dest Port': 200 + i,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        ps_df = detect_port_scan(df, port_threshold=7)
        self.assertEqual(len(ps_df), 1, "Burst quét liên tục chỉ được tạo 1 record duy nhất!")
        self.assertEqual(ps_df.iloc[0]['Total Packets'], 10)
        self.assertEqual(ps_df.iloc[0]['Scanned Ports Count'], 10)

    def test_regression_final_01_threat_ip_accumulation(self):
        """[FINAL-01] Threat IP không bị ghi đè khi cùng IP có nhiều scan session và tích lũy đủ hit từ nhiều vector."""
        t1 = datetime.datetime(2026, 9, 10, 8, 0, 0)
        t2 = datetime.datetime(2026, 9, 11, 8, 0, 0)

        # 1. Hai scan session cùng Source & Dest IP
        port_scans_same_dst = pd.DataFrame([
            {
                Col.SOURCE_IP: '192.168.1.88',
                Col.DEST_IP: '10.0.0.5',
                Col.SCANNED_PORTS_COUNT: 7,
                Col.TOTAL_PACKETS: 7,
                Col.TARGETED_PORTS: '80, 81, 82, 83, 84, 85, 86',
                Col.SCAN_TYPE: 'TCP SYN Scan',
                Col.FIRST_SEEN: t1,
                Col.LAST_SEEN: t1 + datetime.timedelta(seconds=6)
            },
            {
                Col.SOURCE_IP: '192.168.1.88',
                Col.DEST_IP: '10.0.0.5',
                Col.SCANNED_PORTS_COUNT: 7,
                Col.TOTAL_PACKETS: 7,
                Col.TARGETED_PORTS: '90, 91, 92, 93, 94, 95, 96',
                Col.SCAN_TYPE: 'TCP SYN Scan',
                Col.FIRST_SEEN: t2,
                Col.LAST_SEEN: t2 + datetime.timedelta(seconds=6)
            }
        ])
        threats_1 = detect_suspicious_ips(pd.DataFrame(), server_ip='10.0.0.5', port_scans_df=port_scans_same_dst)
        self.assertEqual(len(threats_1), 1)
        row_1 = threats_1.iloc[0]
        self.assertEqual(row_1[Col.IP], '192.168.1.88')
        self.assertEqual(row_1[Col.HIT_COUNT], 14, "Hit Count phải cộng dồn từ cả 2 scan session (7 + 7 = 14)!")
        self.assertIn('Target: 10.0.0.5 (Ports: 80, 81, 82, 83, 84, 85, 86)', row_1[Col.TARGETED_VECTORS])
        self.assertIn('Target: 10.0.0.5 (Ports: 90, 91, 92, 93, 94, 95, 96)', row_1[Col.TARGETED_VECTORS])

        # 2. Hai scan session cùng Source nhưng KHÁC Dest IP
        port_scans_diff_dst = pd.DataFrame([
            {
                Col.SOURCE_IP: '192.168.1.88',
                Col.DEST_IP: '10.0.0.5',
                Col.SCANNED_PORTS_COUNT: 7,
                Col.TOTAL_PACKETS: 7,
                Col.TARGETED_PORTS: '80, 81, 82, 83, 84, 85, 86',
                Col.SCAN_TYPE: 'TCP SYN Scan',
                Col.FIRST_SEEN: t1,
                Col.LAST_SEEN: t1 + datetime.timedelta(seconds=6)
            },
            {
                Col.SOURCE_IP: '192.168.1.88',
                Col.DEST_IP: '10.0.0.6',
                Col.SCANNED_PORTS_COUNT: 7,
                Col.TOTAL_PACKETS: 7,
                Col.TARGETED_PORTS: '21, 22, 23, 25, 53, 80, 443',
                Col.SCAN_TYPE: 'TCP SYN Scan',
                Col.FIRST_SEEN: t2,
                Col.LAST_SEEN: t2 + datetime.timedelta(seconds=6)
            }
        ])
        threats_2 = detect_suspicious_ips(pd.DataFrame(), server_ip='10.0.0.1', port_scans_df=port_scans_diff_dst)
        self.assertEqual(len(threats_2), 1)
        row_2 = threats_2.iloc[0]
        self.assertEqual(row_2[Col.HIT_COUNT], 14)
        self.assertIn('Target: 10.0.0.5', row_2[Col.TARGETED_VECTORS])
        self.assertIn('Target: 10.0.0.6', row_2[Col.TARGETED_VECTORS])

        # 3. Một IP vừa Port Scan vừa Web Attack -> Multi-vector và Hit Count đúng
        web_attacks_sample = pd.DataFrame([
            {Col.TIMESTAMP: t1, Col.SOURCE_IP: '192.168.1.88', Col.DEST_IP: '10.0.0.5', 'URI': '/sqli', Col.ATTACK_CATEGORY: 'SQL Injection'},
            {Col.TIMESTAMP: t1, Col.SOURCE_IP: '192.168.1.88', Col.DEST_IP: '10.0.0.5', 'URI': '/xss', Col.ATTACK_CATEGORY: 'XSS'},
            {Col.TIMESTAMP: t1, Col.SOURCE_IP: '192.168.1.88', Col.DEST_IP: '10.0.0.5', 'URI': '/cmd', Col.ATTACK_CATEGORY: 'Command Injection'}
        ])
        threats_3 = detect_suspicious_ips(pd.DataFrame(), server_ip='10.0.0.5', port_scans_df=port_scans_same_dst, web_attacks_df=web_attacks_sample)
        self.assertEqual(len(threats_3), 1)
        row_3 = threats_3.iloc[0]
        self.assertEqual(row_3[Col.HIT_COUNT], 17, "Hit count = 14 (scan) + 3 (web) = 17")
        self.assertIn('Multi-vector (Port Scan, Web Attack)', row_3[Col.THREAT_CATEGORY])

    def test_regression_final_02_flood_thresholds_and_rate(self):
        """[FINAL-02] Ngưỡng peak ICMP/UDP phải dùng DEFAULT_FLOOD_PPS_THRESHOLD=50 và tính đúng Rate."""
        t0 = datetime.datetime(2026, 9, 14, 10, 0, 0)

        # 1. 10 gói ICMP trong 0.36s: Peak = 9 / 0.36 = 25 - 33.33 PPS (< 50 PPS), Count 10 < flood_threshold 40
        # -> KHÔNG được báo flood
        icmp_sub_50_data = []
        for i in range(10):
            icmp_sub_50_data.append({
                Col.TIMESTAMP: t0 + datetime.timedelta(seconds=i * 0.04), # 0.0s đến 0.36s: 9 khoảng x 0.04 = 0.36s
                Col.SOURCE_IP: '192.168.1.99',
                Col.DEST_IP: '10.0.0.1',
                Col.PROTOCOL: 'ICMP',
                Col.DEST_PORT: 0,
                Col.TCP_FLAGS: ''
            })
        df_sub = pd.DataFrame(icmp_sub_50_data)
        dos_sub = detect_dos_bruteforce(df_sub, flood_threshold=40, server_ip='10.0.0.1')
        self.assertTrue(dos_sub.empty, "ICMP với peak ~25-33.33 PPS (< 50 PPS) và count 10 không được báo flood!")

        # 2. 10 gói ICMP với burst >= 50 PPS (ví dụ 10 gói trong 0.15s: Peak ~ 60 PPS >= 50 PPS)
        # -> Phải được phát hiện
        icmp_over_50_data = []
        for i in range(10):
            icmp_over_50_data.append({
                Col.TIMESTAMP: t0 + datetime.timedelta(seconds=i * 0.015), # 9 * 0.015 = 0.135s -> Peak > 50 PPS
                Col.SOURCE_IP: '192.168.1.99',
                Col.DEST_IP: '10.0.0.1',
                Col.PROTOCOL: 'ICMP',
                Col.DEST_PORT: 0,
                Col.TCP_FLAGS: ''
            })
        df_over = pd.DataFrame(icmp_over_50_data)
        dos_over = detect_dos_bruteforce(df_over, flood_threshold=40, server_ip='10.0.0.1')
        self.assertEqual(len(dos_over), 1, "ICMP với peak >= 50 PPS và count 10 phải được phát hiện!")
        self.assertEqual(dos_over.iloc[0][Col.ATTACK_TYPE], 'ICMP Flood')

        # 3. Kiểm tra tính Rate: 50 packets trong 0.49 giây
        # Rate phải bằng round(50 / 0.49, 2) = 102.04 PPS (không bị kẹp ở max(dur, 1.0) = 50.0 PPS)
        burst_data = []
        for i in range(50):
            burst_data.append({
                Col.TIMESTAMP: t0 + datetime.timedelta(seconds=i * (0.49 / 49.0)),
                Col.SOURCE_IP: '192.168.1.111',
                Col.DEST_IP: '10.0.0.1',
                Col.PROTOCOL: 'TCP',
                Col.DEST_PORT: 80,
                Col.TCP_FLAGS: 'SYN'
            })
        df_rate = pd.DataFrame(burst_data)
        dos_rate = detect_dos_bruteforce(df_rate, flood_threshold=30, server_ip='10.0.0.1')
        self.assertEqual(len(dos_rate), 1)
        actual_rate = dos_rate.iloc[0][Col.AVG_RATE]
        expected_rate = round(50 / 0.49, 2)
        self.assertEqual(actual_rate, expected_rate, f"Average Rate phải là {expected_rate} PPS, nhưng nhận {actual_rate} PPS!")

        # 4. Kiểm tra tương tự cho UDP
        # 20 gói UDP trong 0.70s (Peak ~ 28.57 PPS < 50 PPS, count 20 < flood_threshold 80) -> Không flood
        udp_sub_data = []
        for i in range(20):
            udp_sub_data.append({
                Col.TIMESTAMP: t0 + datetime.timedelta(seconds=i * 0.035),
                Col.SOURCE_IP: '192.168.1.222',
                Col.DEST_IP: '10.0.0.1',
                Col.PROTOCOL: 'UDP',
                Col.DEST_PORT: 53,
                Col.TCP_FLAGS: ''
            })
        df_udp_sub = pd.DataFrame(udp_sub_data)
        dos_udp_sub = detect_dos_bruteforce(df_udp_sub, flood_threshold=40, server_ip='10.0.0.1')
        self.assertTrue(dos_udp_sub.empty, "UDP với peak < 50 PPS không được báo flood!")

        # 20 gói UDP trong 0.30s (Peak >= 50 PPS) -> Phải phát hiện UDP Flood
        udp_over_data = []
        for i in range(20):
            udp_over_data.append({
                Col.TIMESTAMP: t0 + datetime.timedelta(seconds=i * 0.015),
                Col.SOURCE_IP: '192.168.1.222',
                Col.DEST_IP: '10.0.0.1',
                Col.PROTOCOL: 'UDP',
                Col.DEST_PORT: 53,
                Col.TCP_FLAGS: ''
            })
        df_udp_over = pd.DataFrame(udp_over_data)
        dos_udp_over = detect_dos_bruteforce(df_udp_over, flood_threshold=40, server_ip='10.0.0.1')
        self.assertEqual(len(dos_udp_over), 1, "UDP với peak >= 50 PPS và count 20 phải được phát hiện!")
        self.assertEqual(dos_udp_over.iloc[0][Col.ATTACK_TYPE], 'UDP Flood')

    def test_regression_final_05_dos_single_large_group_performance(self):
        """[FINAL-05] DoS helper xử lý 500,000 packet trong cùng 1 group flood trong <= 5.0 giây (O(n))."""
        import time
        import numpy as np
        
        n_packets = 500_000
        t0 = pd.Timestamp("2026-09-14 12:00:00")
        # Sinh 500,000 timestamps cách đều nhau trong 50 giây (10,000 pps)
        ts_array = t0 + pd.to_timedelta(np.linspace(0, 50, n_packets), unit='s')
        
        df_large = pd.DataFrame({
            Col.TIMESTAMP: ts_array,
            Col.SOURCE_IP: '192.168.100.50',
            Col.DEST_IP: '10.0.0.1',
            Col.PROTOCOL: 'TCP',
            Col.DEST_PORT: 80,
            Col.TCP_FLAGS: 'SYN'
        })
        
        start_t = time.time()
        dos_res = detect_dos_bruteforce(df_large, flood_threshold=40, server_ip='10.0.0.1')
        elapsed = time.time() - start_t
        
        self.assertEqual(len(dos_res), 1)
        self.assertLess(elapsed, 5.0, f"500k packet trong 1 group mất {elapsed:.2f}s, phải <= 5.0s!")

    def test_regression_final_10_port_evidence_retention(self):
        """[FINAL-10] Bằng chứng cổng quét giữ nhiều hơn 5 cổng (hỗ trợ tối đa 50 cổng)."""
        now = datetime.datetime.now()
        data = []
        for port in range(100, 120): # 20 cổng khác nhau
            data.append({
                'Timestamp': now,
                'Source IP': '192.168.1.105',
                'Dest IP': '10.0.0.1',
                'Dest Port': port,
                'Protocol': 'TCP',
                'TCP_Flags': 'SYN'
            })
        df = pd.DataFrame(data)
        ps_df = detect_port_scan(df, port_threshold=7)
        self.assertEqual(len(ps_df), 1)
        targeted_ports_str = ps_df.iloc[0]['Targeted Ports']
        ports_list = [p.strip() for p in targeted_ports_str.split(',') if p.strip()]
        self.assertEqual(len(ports_list), 20, "Targeted Ports phải giữ đủ 20 cổng quét, không bị cắt còn 5!")

if __name__ == '__main__':
    unittest.main()

