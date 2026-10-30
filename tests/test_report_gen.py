import unittest
import os
import datetime
import pandas as pd
from modules.report_gen import find_pdf_engine, _find_all_pdf_engines, fig_to_base64, render_report_html

class TestReportGenModule(unittest.TestCase):
    def test_find_pdf_engine_returns_tuple(self):
        result = find_pdf_engine()
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        engine_type, engine_path = result
        self.assertIn(engine_type, (None, 'browser', 'wkhtmltopdf'))
    
    def test_find_all_pdf_engines_returns_list(self):
        result = _find_all_pdf_engines()
        self.assertIsInstance(result, list)
        for item in result:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)

    def test_fig_to_base64_none_input(self):
        self.assertEqual(fig_to_base64(None), "")
    
    def test_fig_to_base64_invalid_input(self):
        self.assertEqual(fig_to_base64("not a figure"), "")

    def test_render_report_html_integration(self):
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'templates', 'report_template.html'
        )
        data = {
            'filename': 'test_sample.pcap',
            'server_ip': '10.0.0.1',
            'report_date': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            'total_packets': 1000,
            'port_scans': pd.DataFrame(),
            'web_attacks': pd.DataFrame(),
            'dos_bruteforce': pd.DataFrame(),
            'tls_sni': pd.DataFrame(),
            'dns_probes': pd.DataFrame(),
            'threat_ips': pd.DataFrame()
        }
        figures = {}
        html = render_report_html(template_path, data, figures)
        self.assertIn('test_sample.pcap', html)
        self.assertIn('10.0.0.1', html)
        self.assertIn('1,000', html)
        self.assertIn('<!DOCTYPE html>', html)

    def test_regression_p0_06_html_report_autoescape_xss(self):
        """[P0-06] Kiểm tra chống HTML/JS Injection qua metadata và nội dung bảng."""
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'templates', 'report_template.html'
        )
        xss_filename = '<img src=x onerror=alert(1)>.pcap'
        xss_server_ip = '<script>alert("hacked")</script>'
        
        web_df = pd.DataFrame([{
            'Timestamp': datetime.datetime.now(),
            'Source IP': '10.0.0.99',
            'Method': 'GET',
            'URI': '/<script>alert(3)</script>',
            'Attack Category': '<b>XSS Injection</b>'
        }])
        
        data = {
            'filename': xss_filename,
            'server_ip': xss_server_ip,
            'report_date': '14/09/2026',
            'total_packets': 100,
            'port_scans': pd.DataFrame(),
            'web_attacks': web_df,
            'dos_bruteforce': pd.DataFrame(),
            'tls_sni': pd.DataFrame(),
            'dns_probes': pd.DataFrame(),
            'dns_tunneling': pd.DataFrame(),
            'threat_ips': pd.DataFrame()
        }
        html = render_report_html(template_path, data, {})
        
        # Đảm bảo KHÔNG có thẻ script hay img độc hại nguyên dạng trong mã HTML
        self.assertNotIn('<img src=x onerror=alert(1)>', html)
        self.assertNotIn('<script>alert("hacked")</script>', html)
        self.assertNotIn('/<script>alert(3)</script>', html)
        self.assertNotIn('<b>XSS Injection</b>', html)
        
        # Đảm bảo đã được mã hóa an toàn thành HTML entities
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html)
        self.assertIn('&lt;script&gt;alert(&#34;hacked&#34;)&lt;/script&gt;', html)
        self.assertIn('&lt;script&gt;alert(3)&lt;/script&gt;', html)
        self.assertIn('&lt;b&gt;XSS Injection&lt;/b&gt;', html)

if __name__ == '__main__':
    unittest.main()
