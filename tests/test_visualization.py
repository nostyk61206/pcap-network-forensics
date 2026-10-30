import unittest
import pandas as pd
import datetime
from unittest.mock import patch, MagicMock
from modules.constants import Col
from modules.visualization import (
    plot_protocol_stats,
    plot_time_flow,
    plot_top_ips,
    plot_web_attacks_stats,
    plot_web_attack_uris,
    plot_tls_sni_stats,
    plot_tls_classification,
    plot_dos_bruteforce_stats,
    plot_scanned_ports_stats,
    plot_threat_categories,
    plot_dns_distribution,
    plot_geoip_map
)

class TestVisualizationModule(unittest.TestCase):
    def test_empty_dataframe_handling(self):
        empty_df = pd.DataFrame()
        self.assertIsNone(plot_protocol_stats(empty_df))
        self.assertIsNone(plot_time_flow(empty_df))
        
        src_fig, dst_fig = plot_top_ips(empty_df)
        self.assertIsNone(src_fig)
        self.assertIsNone(dst_fig)
        
        self.assertIsNone(plot_web_attacks_stats(empty_df))
        self.assertIsNone(plot_web_attack_uris(empty_df))
        self.assertIsNone(plot_tls_sni_stats(empty_df))
        self.assertIsNone(plot_tls_classification(empty_df))
        self.assertIsNone(plot_dos_bruteforce_stats(empty_df))
        self.assertIsNone(plot_scanned_ports_stats(empty_df))
        self.assertIsNone(plot_threat_categories(empty_df))
        self.assertIsNone(plot_dns_distribution({}))

    def test_valid_charts_rendering(self):
        now = datetime.datetime.now()
        df = pd.DataFrame([
            {'Timestamp': now, 'Source IP': '10.0.0.1', 'Dest IP': '10.0.0.2', 'Protocol': 'TCP'},
            {'Timestamp': now + datetime.timedelta(seconds=1), 'Source IP': '10.0.0.1', 'Dest IP': '10.0.0.2', 'Protocol': 'UDP'},
        ])
        
        fig_proto = plot_protocol_stats(df)
        self.assertIsNotNone(fig_proto)
        
        fig_time = plot_time_flow(df)
        self.assertIsNotNone(fig_time)
        
        fig_src, fig_dst = plot_top_ips(df)
        self.assertIsNotNone(fig_src)
        self.assertIsNotNone(fig_dst)

    def test_specialized_charts(self):
        """Kiểm tra chart TLS, DoS, DNS, Threat trả về figure hợp lệ khi có dữ liệu."""
        # TLS classification chart
        tls_df = pd.DataFrame([
            {'TLS_SNI': 'google.com', 'Classification': 'Legitimate HTTPS'},
            {'TLS_SNI': 'evil.xyz', 'Classification': 'Suspicious Dynamic DNS'}
        ])
        self.assertIsNotNone(plot_tls_classification(tls_df))
        self.assertIsNotNone(plot_tls_sni_stats(tls_df))

        # DoS chart
        dos_df = pd.DataFrame([
            {'Attack Type': 'Brute-Force (SSH)', 'Packet Count': 100}
        ])
        self.assertIsNotNone(plot_dos_bruteforce_stats(dos_df))

        # DNS distribution
        dns_res = {'all_queries': pd.DataFrame([
            {'Classification': 'DNS Probe (Internet Noise)'},
            {'Classification': 'Legitimate Outbound DNS'}
        ])}
        self.assertIsNotNone(plot_dns_distribution(dns_res))

        # Threat categories
        threat_df = pd.DataFrame([
            {'Threat Category': 'Port Scan'},
            {'Threat Category': 'Web Attack'}
        ])
        self.assertIsNotNone(plot_threat_categories(threat_df))

        # Web attacks chart
        web_df = pd.DataFrame([
            {'Attack Category': 'SQL Injection', 'URI': '/login.php'}
        ])
        self.assertIsNotNone(plot_web_attacks_stats(web_df))
        self.assertIsNotNone(plot_web_attack_uris(web_df))

    def test_plot_geoip_map_empty_and_invalid_schema(self):
        """[FINAL-03] plot_geoip_map với schema rỗng, thiếu db, hoặc schema lạ không raise exception mà trả về None."""
        # 1. DataFrame rỗng
        self.assertIsNone(plot_geoip_map(pd.DataFrame()))
        # 2. None input
        self.assertIsNone(plot_geoip_map(None))
        # 3. Database không tồn tại
        df = pd.DataFrame([{Col.IP: '8.8.8.8', Col.HIT_COUNT: 10}])
        self.assertIsNone(plot_geoip_map(df, db_path='data/non_existent_db.mmdb'))
        # 4. DataFrame với cột lạ (không có IP, Source IP, Dest IP)
        import os
        orig_exists = os.path.exists
        def selective_exists(p):
            if str(p).endswith('dummy.mmdb'):
                return True
            return orig_exists(p)

        with patch('os.path.exists', side_effect=selective_exists):
            strange_df = pd.DataFrame([{'random_col_1': 'val1', 'random_col_2': 'val2'}])
            self.assertIsNone(plot_geoip_map(strange_df, db_path='dummy.mmdb'))

    def test_plot_geoip_map_threat_ip_schema(self):
        """[FINAL-03] plot_geoip_map với bảng Threat IP (chỉ có 'IP', 'Hit Count') vẽ bản đồ bình thường không raise KeyError."""
        import os
        orig_exists = os.path.exists
        def selective_exists(p):
            if str(p).endswith('dummy.mmdb'):
                return True
            return orig_exists(p)

        threat_df = pd.DataFrame([
            {
                Col.IP: '1.1.1.1',
                Col.HIT_COUNT: 25,
                Col.THREAT_CATEGORY: 'Port Scan',
                Col.RISK_LEVEL: 'Cao'
            },
            {
                Col.IP: '8.8.8.8',
                Col.HIT_COUNT: 10,
                Col.THREAT_CATEGORY: 'DNS Tunneling',
                Col.RISK_LEVEL: 'Cao'
            }
        ])

        # Mock reader của geoip2
        mock_reader = MagicMock()
        
        mock_response_1 = MagicMock()
        mock_response_1.location.latitude = 37.751
        mock_response_1.location.longitude = -122.42
        mock_response_1.city.name = 'San Francisco'
        mock_response_1.country.name = 'United States'

        mock_response_2 = MagicMock()
        mock_response_2.location.latitude = 39.0438
        mock_response_2.location.longitude = -77.4874
        mock_response_2.city.name = 'Ashburn'
        mock_response_2.country.name = 'United States'

        def mock_city_lookup(ip):
            if ip == '1.1.1.1':
                return mock_response_1
            return mock_response_2

        mock_reader.city.side_effect = mock_city_lookup
        mock_reader.__enter__.return_value = mock_reader

        with patch('os.path.exists', side_effect=selective_exists), \
             patch('geoip2.database.Reader', return_value=mock_reader):
            fig = plot_geoip_map(threat_df, db_path='dummy.mmdb')
            self.assertIsNotNone(fig, "Bản đồ Threat Actors phải vẽ thành công từ bảng Threat IP!")

    def test_plot_geoip_map_packet_schema_and_private_ips(self):
        """[FINAL-03] plot_geoip_map với schema gói tin ('Source IP') và xử lý private IP / IP không tìm thấy."""
        import os
        orig_exists = os.path.exists
        def selective_exists(p):
            if str(p).endswith('dummy.mmdb'):
                return True
            return orig_exists(p)

        packet_df = pd.DataFrame([
            {Col.SOURCE_IP: '192.168.1.100', Col.DEST_IP: '10.0.0.1'}, # Private IPs
            {Col.SOURCE_IP: '1.1.1.1', Col.DEST_IP: '10.0.0.1'}         # Public IP
        ])

        import geoip2.errors
        mock_reader = MagicMock()

        def mock_city_lookup(ip):
            if ip == '1.1.1.1':
                res = MagicMock()
                res.location.latitude = -33.494
                res.location.longitude = 143.21
                res.city.name = 'Sydney'
                res.country.name = 'Australia'
                return res
            raise geoip2.errors.AddressNotFoundError(f"Address {ip} not found")

        mock_reader.city.side_effect = mock_city_lookup
        mock_reader.__enter__.return_value = mock_reader

        with patch('os.path.exists', side_effect=selective_exists), \
             patch('geoip2.database.Reader', return_value=mock_reader):
            fig = plot_geoip_map(packet_df, db_path='dummy.mmdb')
            self.assertIsNotNone(fig)

    def test_plot_web_attack_uris_comprehensive(self):
        """Kiểm tra toàn diện plot_web_attack_uris với None, rỗng, thiếu cột, toàn NaN và hợp lệ."""
        # 1. Đầu vào None
        self.assertIsNone(plot_web_attack_uris(None))

        # 2. Đầu vào DataFrame rỗng
        self.assertIsNone(plot_web_attack_uris(pd.DataFrame()))

        # 3. Đầu vào không phải DataFrame
        self.assertIsNone(plot_web_attack_uris("not_a_dataframe"))
        self.assertIsNone(plot_web_attack_uris(12345))

        # 4. DataFrame thiếu cột URI / Col.HTTP_URI
        missing_uri_df = pd.DataFrame([
            {'Source IP': '10.0.0.1', 'Attack Category': 'SQLi'},
            {'Source IP': '10.0.0.2', 'Attack Category': 'XSS'}
        ])
        self.assertIsNone(plot_web_attack_uris(missing_uri_df))

        # 5. DataFrame có cột URI nhưng toàn NaN / rỗng
        nan_uri_df = pd.DataFrame([
            {'URI': None},
            {'URI': None}
        ])
        self.assertIsNone(plot_web_attack_uris(nan_uri_df))

        # 6. DataFrame hợp lệ với cột 'URI'
        valid_df_uri = pd.DataFrame([
            {'URI': '/login.php', 'Attack Category': 'SQLi'},
            {'URI': '/login.php', 'Attack Category': 'SQLi'},
            {'URI': '/admin.php', 'Attack Category': 'Brute Force'}
        ])
        fig_uri = plot_web_attack_uris(valid_df_uri)
        self.assertIsNotNone(fig_uri)

        # 7. DataFrame hợp lệ với cột Col.HTTP_URI ('HTTP URI')
        valid_df_http_uri = pd.DataFrame([
            {Col.HTTP_URI: '/etc/passwd', 'Attack Category': 'LFI'},
            {Col.HTTP_URI: '/etc/shadow', 'Attack Category': 'LFI'}
        ])
        fig_http_uri = plot_web_attack_uris(valid_df_http_uri)
        self.assertIsNotNone(fig_http_uri)

if __name__ == '__main__':
    unittest.main()
