import unittest
import pandas as pd
import datetime
from modules.constants import Col, EXTERNAL_CONNECTION_COLUMNS
from modules.security import (
    is_external_ip,
    parse_ip_or_network_list,
    ip_matches_network_list,
    build_external_connection_summary,
    classify_external_connections,
    enrich_external_connections_geoip,
    detect_external_connections,
    detect_port_scan,
    detect_dos_bruteforce,
    detect_suspicious_ips
)

class TestExternalConnections(unittest.TestCase):
    def setUp(self):
        self.now = datetime.datetime(2026, 9, 21, 10, 0, 0)

    # 1. Private -> Public: Outbound đến cổng dịch vụ bên ngoài
    def test_01_private_to_public(self):
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '192.168.1.10',
            Col.DEST_IP: '93.184.216.34',
            Col.SOURCE_PORT: 54321,
            Col.DEST_PORT: 443,
            Col.PROTOCOL: 'TCP',
            Col.LENGTH: 120,
            Col.TCP_FLAGS: 'SYN'
        }])
        res = detect_external_connections(df, allowlist=[])
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.EXTERNAL_IP], '93.184.216.34')
        self.assertEqual(row[Col.DIRECTION], 'Outbound')
        self.assertEqual(row[Col.TARGETED_PORTS], '443')
        self.assertNotIn('54321', row[Col.TARGETED_PORTS])
        self.assertEqual(row[Col.STATUS], 'Chưa xác minh')
        self.assertEqual(row[Col.RISK_LEVEL], 'Thấp')
        self.assertIn('chưa ghi nhận dấu hiệu bất thường', row[Col.FLAG_REASON])

    # 2. Public -> Private: Inbound từ IP bên ngoài vào cổng dịch vụ máy nội bộ
    def test_02_public_to_private(self):
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '45.33.32.156',
            Col.DEST_IP: '10.0.0.2',
            Col.SOURCE_PORT: 44444,
            Col.DEST_PORT: 80,
            Col.PROTOCOL: 'TCP',
            Col.LENGTH: 60,
            Col.TCP_FLAGS: 'SYN'
        }])
        res = detect_external_connections(df, allowlist=[])
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.EXTERNAL_IP], '45.33.32.156')
        self.assertEqual(row[Col.DIRECTION], 'Inbound')
        self.assertEqual(row[Col.TARGETED_PORTS], '80')
        self.assertNotIn('44444', row[Col.TARGETED_PORTS])
        self.assertEqual(row[Col.STATUS], 'Chưa xác minh')
        self.assertEqual(row[Col.RISK_LEVEL], 'Thấp')

    # 3. Public -> Public có server_ip: Coi đầu còn lại là External IP
    def test_03_public_to_public_with_server_ip(self):
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '8.8.8.8',
            Col.DEST_IP: '1.1.1.1',
            Col.SOURCE_PORT: 53000,
            Col.DEST_PORT: 53,
            Col.PROTOCOL: 'UDP',
            Col.LENGTH: 70
        }])
        res = detect_external_connections(df, server_ip='8.8.8.8')
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.EXTERNAL_IP], '1.1.1.1')
        self.assertEqual(row[Col.DIRECTION], 'Outbound')
        self.assertEqual(row[Col.TARGETED_PORTS], '53')

    # 4. Private -> Public và IP public trùng server_ip: Vẫn ghi nhận External IP bình thường
    def test_04_private_to_public_with_public_server_ip(self):
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '192.168.1.10',
            Col.DEST_IP: '8.8.8.8',
            Col.SOURCE_PORT: 54321,
            Col.DEST_PORT: 53,
            Col.PROTOCOL: 'UDP',
            Col.LENGTH: 64
        }])
        res = detect_external_connections(df, server_ip='8.8.8.8')
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.EXTERNAL_IP], '8.8.8.8')
        self.assertEqual(row[Col.DIRECTION], 'Outbound')
        self.assertEqual(row[Col.TARGETED_PORTS], '53')
        self.assertEqual(row[Col.STATUS], 'Tin cậy')
        self.assertEqual(row[Col.RISK_LEVEL], 'An toàn')

    # 5. Lưu lượng chỉ có mạng nội bộ: Kết quả rỗng
    def test_05_internal_only_traffic(self):
        df = pd.DataFrame([
            {Col.TIMESTAMP: self.now, Col.SOURCE_IP: '192.168.1.10', Col.DEST_IP: '192.168.1.1', Col.PROTOCOL: 'TCP', Col.LENGTH: 60},
            {Col.TIMESTAMP: self.now, Col.SOURCE_IP: '10.0.0.5', Col.DEST_IP: '10.0.0.1', Col.PROTOCOL: 'UDP', Col.LENGTH: 100},
            {Col.TIMESTAMP: self.now, Col.SOURCE_IP: '172.16.0.2', Col.DEST_IP: '172.16.0.1', Col.PROTOCOL: 'TCP', Col.LENGTH: 54},
            {Col.TIMESTAMP: self.now, Col.SOURCE_IP: '127.0.0.1', Col.DEST_IP: '127.0.0.1', Col.PROTOCOL: 'TCP', Col.LENGTH: 40}
        ])
        res = detect_external_connections(df)
        self.assertTrue(res.empty)
        self.assertEqual(list(res.columns), EXTERNAL_CONNECTION_COLUMNS)

    # 6. IPv4 và IPv6
    def test_06_ipv4_and_ipv6(self):
        df = pd.DataFrame([
            {
                Col.TIMESTAMP: self.now,
                Col.SOURCE_IP: '192.168.1.10',
                Col.DEST_IP: '93.184.216.34',
                Col.SOURCE_PORT: 52000,
                Col.DEST_PORT: 443,
                Col.PROTOCOL: 'TCP',
                Col.LENGTH: 60
            },
            {
                Col.TIMESTAMP: self.now,
                Col.SOURCE_IP: 'fd12:3456:789a:1::10',
                Col.DEST_IP: '2001:4860:4860::8888',
                Col.SOURCE_PORT: 53000,
                Col.DEST_PORT: 53,
                Col.PROTOCOL: 'UDP',
                Col.LENGTH: 70
            }
        ])
        res = detect_external_connections(df)
        self.assertEqual(len(res), 2)
        ext_ips = set(res[Col.EXTERNAL_IP].tolist())
        self.assertIn('93.184.216.34', ext_ips)
        self.assertIn('2001:4860:4860::8888', ext_ips)

    # 7. Source port 4444 -> Destination port 443: Không được cảnh báo Metasploit
    def test_07_source_port_4444_to_dest_port_443(self):
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '192.168.1.10',
            Col.DEST_IP: '93.184.216.34',
            Col.SOURCE_PORT: 4444,
            Col.DEST_PORT: 443,
            Col.PROTOCOL: 'TCP',
            Col.LENGTH: 128,
            Col.TCP_FLAGS: 'SYN'
        }])
        res = detect_external_connections(df, allowlist=[])
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.EXTERNAL_IP], '93.184.216.34')
        self.assertEqual(row[Col.TARGETED_PORTS], '443')
        self.assertIn(row[Col.STATUS], ('Chưa xác minh', 'Tin cậy'))
        self.assertNotEqual(row[Col.STATUS], 'Đáng ngờ')
        self.assertNotIn('4444', str(row[Col.FLAG_REASON]))

    # 8. Destination port 4444 thực sự: Phải đánh dấu Đáng ngờ
    def test_08_destination_port_4444_actual(self):
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '192.168.1.10',
            Col.DEST_IP: '93.184.216.34',
            Col.SOURCE_PORT: 54321,
            Col.DEST_PORT: 4444,
            Col.PROTOCOL: 'TCP',
            Col.LENGTH: 128,
            Col.TCP_FLAGS: 'SYN'
        }])
        res = detect_external_connections(df, allowlist=[])
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.EXTERNAL_IP], '93.184.216.34')
        self.assertEqual(row[Col.TARGETED_PORTS], '4444')
        self.assertEqual(row[Col.STATUS], 'Đáng ngờ')
        self.assertIn('4444', str(row[Col.FLAG_REASON]))

    # 9. IP đồng thời thuộc Allowlist và Blocklist: Ưu tiên Blocklist
    def test_09_ip_in_both_allowlist_and_blocklist(self):
        ext_ip = '45.33.32.156'
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '192.168.1.10',
            Col.DEST_IP: ext_ip,
            Col.SOURCE_PORT: 50000,
            Col.DEST_PORT: 80,
            Col.PROTOCOL: 'TCP',
            Col.LENGTH: 60
        }])
        res = detect_external_connections(
            df,
            allowlist=[ext_ip],
            blocklist=['45.33.32.0/24']
        )
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.STATUS], 'Đáng ngờ')
        self.assertEqual(row[Col.RISK_LEVEL], 'Cao')
        self.assertIn('Ưu tiên Blocklist', row[Col.FLAG_REASON])

    # 10. IP Allowlist nhưng có bằng chứng tấn công rõ ràng: Ưu tiên bằng chứng đe dọa
    def test_10_allowlist_overridden_by_clear_attack_evidence(self):
        ext_ip = '45.33.32.156'
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: ext_ip,
            Col.DEST_IP: '192.168.1.10',
            Col.SOURCE_PORT: 50000,
            Col.DEST_PORT: 80,
            Col.PROTOCOL: 'TCP',
            Col.LENGTH: 60
        }])
        threat_df = pd.DataFrame([{
            Col.IP: ext_ip,
            Col.THREAT_CATEGORY: 'Port Scan',
            Col.HIT_COUNT: 25,
            Col.TARGETED_VECTORS: 'Ports: 21, 22, 80',
            Col.RISK_LEVEL: 'Cao'
        }])
        res = detect_external_connections(
            df,
            allowlist=[ext_ip],
            threat_ips_df=threat_df
        )
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.STATUS], 'Đáng ngờ')
        self.assertEqual(row[Col.RISK_LEVEL], 'Cao')
        self.assertIn('Port Scan', row[Col.FLAG_REASON])

    # 11. SYN retransmission không làm tăng số lượng kết nối ảo
    def test_11_syn_retransmission_does_not_inflate_connection_count(self):
        ext_ip = '45.33.32.156'
        packets = []
        for i in range(4):
            packets.append({
                Col.TIMESTAMP: self.now + datetime.timedelta(seconds=i),
                Col.SOURCE_IP: ext_ip,
                Col.DEST_IP: '192.168.1.10',
                Col.SOURCE_PORT: 44444,
                Col.DEST_PORT: 80,
                Col.PROTOCOL: 'TCP',
                Col.LENGTH: 60,
                Col.TCP_FLAGS: 'SYN'
            })
        df = pd.DataFrame(packets)
        res = detect_external_connections(df)
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.CONNECTION_COUNT], 1)
        self.assertEqual(row[Col.SYN_COUNT], 4)
        self.assertEqual(row[Col.TOTAL_PACKETS], 4)

    # 12. Nhiều flow tới cùng IP được gom nhóm chính xác
    def test_12_multiple_flows_to_same_ip(self):
        ext_ip = '93.184.216.34'
        packets = [
            {
                Col.TIMESTAMP: self.now,
                Col.SOURCE_IP: '192.168.1.10',
                Col.DEST_IP: ext_ip,
                Col.SOURCE_PORT: 50001,
                Col.DEST_PORT: 443,
                Col.PROTOCOL: 'TCP',
                Col.LENGTH: 60,
                Col.TCP_FLAGS: 'SYN'
            },
            {
                Col.TIMESTAMP: self.now + datetime.timedelta(seconds=1),
                Col.SOURCE_IP: '192.168.1.10',
                Col.DEST_IP: ext_ip,
                Col.SOURCE_PORT: 50002,
                Col.DEST_PORT: 80,
                Col.PROTOCOL: 'TCP',
                Col.LENGTH: 60,
                Col.TCP_FLAGS: 'SYN'
            },
            {
                Col.TIMESTAMP: self.now + datetime.timedelta(seconds=2),
                Col.SOURCE_IP: '192.168.1.20',
                Col.DEST_IP: ext_ip,
                Col.SOURCE_PORT: 50003,
                Col.DEST_PORT: 443,
                Col.PROTOCOL: 'TCP',
                Col.LENGTH: 60,
                Col.TCP_FLAGS: 'SYN'
            }
        ]
        df = pd.DataFrame(packets)
        res = detect_external_connections(df)
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.CONNECTION_COUNT], 3)
        self.assertEqual(row[Col.SYN_COUNT], 3)
        self.assertEqual(row[Col.TOTAL_PACKETS], 3)
        self.assertIn('192.168.1.10', row[Col.INTERNAL_IP])
        self.assertIn('192.168.1.20', row[Col.INTERNAL_IP])
        self.assertIn('443', row[Col.TARGETED_PORTS])
        self.assertIn('80', row[Col.TARGETED_PORTS])

    # 13. DataFrame rỗng hoặc thiếu cột: Hoạt động an toàn, không crash
    def test_13_empty_dataframe_and_missing_columns(self):
        res1 = detect_external_connections(pd.DataFrame())
        self.assertTrue(res1.empty)
        self.assertEqual(list(res1.columns), EXTERNAL_CONNECTION_COLUMNS)

        res2 = detect_external_connections(None)
        self.assertTrue(res2.empty)
        self.assertEqual(list(res2.columns), EXTERNAL_CONNECTION_COLUMNS)

        res3 = detect_external_connections(pd.DataFrame([{'Other_Col': 123}]))
        self.assertTrue(res3.empty)
        self.assertEqual(list(res3.columns), EXTERNAL_CONNECTION_COLUMNS)

    # 14. PCAP không có TCP flags: Không crash, SYN_COUNT = 0, nhận diện hướng theo luồng
    def test_14_pcap_without_tcp_flags(self):
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '192.168.1.10',
            Col.DEST_IP: '8.8.8.8',
            Col.SOURCE_PORT: 53000,
            Col.DEST_PORT: 53,
            Col.PROTOCOL: 'UDP',
            Col.LENGTH: 80
            # Không có Col.TCP_FLAGS
        }])
        res = detect_external_connections(df)
        self.assertEqual(len(res), 1)
        row = res.iloc[0]
        self.assertEqual(row[Col.EXTERNAL_IP], '8.8.8.8')
        self.assertEqual(row[Col.SYN_COUNT], 0)
        self.assertEqual(row[Col.DIRECTION], 'Outbound')
        self.assertEqual(row[Col.TARGETED_PORTS], '53')

    # 15. Thay đổi Allowlist không làm chạy lại parser
    def test_15_changing_allowlist_does_not_reparse(self):
        df = pd.DataFrame([{
            Col.TIMESTAMP: self.now,
            Col.SOURCE_IP: '192.168.1.10',
            Col.DEST_IP: '93.184.216.34',
            Col.SOURCE_PORT: 50000,
            Col.DEST_PORT: 443,
            Col.PROTOCOL: 'TCP',
            Col.LENGTH: 60
        }])
        summary_df = build_external_connection_summary(df)
        self.assertFalse(summary_df.empty)

        res_unverified = classify_external_connections(summary_df, allowlist=[])
        self.assertEqual(res_unverified.iloc[0][Col.STATUS], 'Chưa xác minh')

        res_trusted = classify_external_connections(summary_df, allowlist=['93.184.216.34'])
        self.assertEqual(res_trusted.iloc[0][Col.STATUS], 'Tin cậy')

    # 16. Kiểm tra các module phát hiện khác không bị ảnh hưởng (Regression test)
    def test_16_regression_existing_modules(self):
        ps_data = []
        for port in range(20, 30):
            ps_data.append({
                Col.TIMESTAMP: self.now,
                Col.SOURCE_IP: '192.168.1.200',
                Col.DEST_IP: '192.168.1.1',
                Col.DEST_PORT: port,
                Col.PROTOCOL: 'TCP',
                Col.TCP_FLAGS: 'SYN'
            })
        ps_df = detect_port_scan(pd.DataFrame(ps_data), port_threshold=7)
        self.assertEqual(len(ps_df), 1)

        dos_data = []
        for _ in range(35):
            dos_data.append({
                Col.TIMESTAMP: self.now,
                Col.SOURCE_IP: '192.168.1.200',
                Col.DEST_IP: '192.168.1.1',
                Col.DEST_PORT: 80,
                Col.PROTOCOL: 'TCP',
                Col.TCP_FLAGS: 'SYN',
                Col.LENGTH: 60
            })
        dos_df = detect_dos_bruteforce(pd.DataFrame(dos_data))
        self.assertFalse(dos_df.empty)

        threat_ips = detect_suspicious_ips(
            pd.DataFrame(),
            port_scans_df=ps_df,
            dos_df=dos_df
        )
        self.assertFalse(threat_ips.empty)

if __name__ == '__main__':
    unittest.main()
