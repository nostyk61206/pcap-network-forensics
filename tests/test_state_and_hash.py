import unittest
import pandas as pd
import datetime
import os
from modules.state_utils import (
    compute_file_id,
    make_server_ip_widget_key,
    reset_file_scoped_state,
    reset_report_state_if_context_changed,
    compute_analysis_context_id,
    validate_ip_address
)
from modules.report_gen import generate_html_report

class TestStateAndHashModule(unittest.TestCase):
    def test_file_hash_production_helper(self):
        """[V3-05] compute_file_id trả về SHA-256 duy nhất cho hai file cùng size nhưng khác nội dung."""
        content_a = b"A" * 1024
        content_b = b"B" * 1024
        self.assertEqual(len(content_a), len(content_b))
        
        hash_a = compute_file_id(content_a)
        hash_b = compute_file_id(content_b)
        self.assertNotEqual(hash_a, hash_b)
        self.assertEqual(len(hash_a), 16)
        self.assertEqual(len(hash_b), 16)
        
        with self.assertRaises(TypeError):
            compute_file_id("not_bytes_string")  # type: ignore

    def test_widget_key_production_helper(self):
        """[V3-05] make_server_ip_widget_key tạo key riêng biệt gắn với file ID."""
        file_hash_1 = "a1b2c3d4e5f60718"
        file_hash_2 = "9f8e7d6c5b4a3210"
        
        key_1 = make_server_ip_widget_key(file_hash_1)
        key_2 = make_server_ip_widget_key(file_hash_2)
        self.assertNotEqual(key_1, key_2)
        self.assertEqual(key_1, "server_ip_input_a1b2c3d4e5f60718")

    def test_state_transitions_a_to_b_to_a(self):
        """[V3-05] Chu trình chuyển file A -> B -> A: Dọn sạch state file cũ, không rò rỉ artifact sang file sau."""
        hash_a = "aaaaaaaaaaaaaaaa"
        hash_b = "bbbbbbbbbbbbbbbb"
        session_state = {}

        # 1. Tải file A, sinh báo cáo PDF
        reset_res = reset_file_scoped_state(session_state, hash_a)
        self.assertTrue(reset_res)
        session_state['generated_pdf'] = b'%PDF-1.4 File A'
        session_state['generated_pdf_name'] = 'file_a.pdf'

        # 2. Chuyển sang file B: Toàn bộ artifact của A phải bị dọn sạch
        reset_res = reset_file_scoped_state(session_state, hash_b)
        self.assertTrue(reset_res)
        self.assertNotIn('generated_pdf', session_state)
        self.assertNotIn('generated_pdf_name', session_state)
        self.assertEqual(session_state.get('current_file_hash'), hash_b)
        self.assertEqual(session_state.get('report_current_file_id'), hash_b)

        # 3. File B sinh báo cáo HTML
        session_state['generated_html'] = b'<html>File B</html>'
        session_state['generated_html_name'] = 'file_b.html'

        # 4. Chuyển ngược lại file A: Toàn bộ artifact của B phải bị dọn sạch
        reset_res = reset_file_scoped_state(session_state, hash_a)
        self.assertTrue(reset_res)
        self.assertNotIn('generated_html', session_state)
        self.assertNotIn('generated_html_name', session_state)
        self.assertEqual(session_state.get('current_file_hash'), hash_a)
        self.assertEqual(session_state.get('report_current_file_id'), hash_a)

        # 5. Re-run trên cùng file A (không đổi file): không thực hiện reset
        reset_res = reset_file_scoped_state(session_state, hash_a)
        self.assertFalse(reset_res)

    def test_regression_final_06_server_ip_change_clears_reports(self):
        """[FINAL-06] Cùng file PCAP nhưng đổi Server IP phải xóa bỏ báo cáo cũ và reset artifact trước khi tải."""
        file_hash = "constant_pcap_12"
        session_state = {}

        # 1. Khởi tạo phân tích với Server IP A
        reset_file_scoped_state(session_state, file_hash, server_ip="192.168.1.100")
        session_state['generated_pdf'] = b'%PDF-1.4 Server A'
        session_state['generated_pdf_name'] = 'report_server_a.pdf'
        session_state['generated_html'] = b'<html>Server A</html>'
        session_state['generated_html_name'] = 'report_server_a.html'

        # 2. Người dùng đổi sang Server IP B trên cùng file PCAP
        # reset_file_scoped_state phải phát hiện đổi context và dọn sạch báo cáo của Server A
        changed = reset_file_scoped_state(session_state, file_hash, server_ip="10.0.0.5")
        self.assertTrue(changed, "Đổi Server IP trên cùng file phải kích hoạt reset artifact báo cáo!")
        self.assertNotIn('generated_pdf', session_state, "Báo cáo PDF cũ của Server A phải bị xóa!")
        self.assertNotIn('generated_pdf_name', session_state)
        self.assertNotIn('generated_html', session_state, "Báo cáo HTML cũ của Server A phải bị xóa!")
        self.assertNotIn('generated_html_name', session_state)

        # 3. Re-run với cùng Server IP B: không reset tiếp
        re_run_same = reset_file_scoped_state(session_state, file_hash, server_ip="10.0.0.5")
        self.assertFalse(re_run_same, "Chạy lại với cùng Server IP không được reset!")

    def test_ip_validation_production_helper(self):
        """[V3-05] validate_ip_address kiểm tra chặt chẽ IPv4/IPv6 qua production helper."""
        # Hợp lệ
        self.assertTrue(validate_ip_address("192.168.1.1"))
        self.assertTrue(validate_ip_address("  10.0.0.1  "))
        self.assertTrue(validate_ip_address("2001:db8::1"))
        
        # Không hợp lệ
        invalid_ips = ["999.999.999.999", "192.168.1.300", "not_an_ip", "10.0.0.1/24", "", None, "   "]
        for bad_ip in invalid_ips:
            self.assertFalse(validate_ip_address(bad_ip))

    def test_html_report_fallback_generation(self):
        """Fallback sinh báo cáo HTML độc lập khi không có engine PDF."""
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'templates', 'report_template.html'
        )
        report_data = {
            'filename': 'capture_test.pcap',
            'server_ip': '192.168.1.100',
            'report_date': '14/09/2026 12:00:00',
            'total_packets': 500,
            'port_scans': pd.DataFrame(),
            'web_attacks': pd.DataFrame(),
            'dos_bruteforce': pd.DataFrame(),
            'tls_sni': pd.DataFrame(),
            'dns_probes': pd.DataFrame(),
            'dns_tunneling': pd.DataFrame(),
            'threat_ips': pd.DataFrame()
        }
        figures = {}
        html_str = generate_html_report(template_path, report_data, figures)
        self.assertIsInstance(html_str, str)
        self.assertIn("capture_test.pcap", html_str)
        self.assertIn("192.168.1.100", html_str)

if __name__ == '__main__':
    unittest.main()
