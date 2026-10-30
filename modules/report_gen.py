import os
import tempfile
import base64
import subprocess
import shutil
import logging
from jinja2 import Environment, FileSystemLoader, select_autoescape  # type: ignore

logger = logging.getLogger(__name__)

def _find_all_pdf_engines():
    """Trả về danh sách tất cả các công cụ xuất PDF khả dụng trên hệ thống theo thứ tự ưu tiên."""
    engines = []
    # 1. Tìm Microsoft Edge, Google Chrome, Brave hoặc Chromium
    possible_browsers = [
        # Windows
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        # Linux
        "/usr/bin/google-chrome",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        # macOS
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        shutil.which("msedge"),
        shutil.which("chrome"),
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("brave")
    ]
    for b in possible_browsers:
        if b and os.path.exists(b):
            engines.append(('browser', b))
            break  # Chỉ lấy 1 browser engine tốt nhất
            
    # 2. Tìm wkhtmltopdf nếu đã cài
    possible_wk = [
        r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe",
        r"C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe",
        "/usr/bin/wkhtmltopdf",
        "/usr/local/bin/wkhtmltopdf",
        shutil.which("wkhtmltopdf")
    ]
    for w in possible_wk:
        if w and os.path.exists(w):
            engines.append(('wkhtmltopdf', w))
            break

    return engines

def find_pdf_engine():
    """Tự động tìm kiếm công cụ xuất PDF có sẵn trên hệ điều hành (Edge/Chrome/wkhtmltopdf)."""
    engines = _find_all_pdf_engines()
    if engines:
        return engines[0]
    return (None, None)

def fig_to_base64(fig):
    """Chuyển đổi biểu đồ Plotly sang base64 data URI để nhúng trực tiếp vào file HTML/PDF."""
    if fig is None:
        return ""
    try:
        if hasattr(fig, 'update_layout') and hasattr(fig, 'to_image'):
            fig.update_layout(template='plotly_white')
            img_bytes = fig.to_image(format="png", width=800, height=420)
            b64_str = base64.b64encode(img_bytes).decode('utf-8')
            return f"data:image/png;base64,{b64_str}"
        return ""
    except Exception:
        return ""

def render_report_html(template_path, data, figures):
    """
    Render toàn bộ nội dung báo cáo HTML từ template Jinja2.
    """
    # 1. Chuyển đổi biểu đồ thành base64 nhúng trực tiếp
    chart_b64 = {}
    for name, fig in figures.items():
        chart_b64[name] = fig_to_base64(fig) if fig is not None else ""
        
    # 2. Đọc và cấu hình Jinja2 template với autoescape bật sẵn chống XSS
    template_dir = os.path.dirname(template_path)
    template_name = os.path.basename(template_path)
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"])
    )
    template = env.get_template(template_name)
    
    # 3. Chuyển đổi DataFrame thành HTML table với tiêu đề Tiếng Việt và escape=True an toàn
    df_port_scans = data.get('port_scans')
    df_web_attacks = data.get('web_attacks')
    df_dos = data.get('dos_bruteforce')
    df_tls = data.get('tls_sni')
    df_dns_probes = data.get('dns_probes')
    df_dns_tunneling = data.get('dns_tunneling')
    df_threat_ips = data.get('threat_ips')
    df_external = data.get('external_connections')
    
    port_scans_html = ""
    if df_port_scans is not None and not df_port_scans.empty:
        port_cols = [c for c in ['Source IP', 'Dest IP', 'Scanned Ports Count', 'Total Packets', 'Targeted Ports'] if c in df_port_scans.columns]
        display_port_df = df_port_scans[port_cols].head(15).copy()
        col_name_map = {
            'Source IP': 'IP Nguồn',
            'Dest IP': 'IP Đích',
            'Scanned Ports Count': 'Số Cổng Bị Quét',
            'Total Packets': 'Gói Tin Sự Kiện',
            'Targeted Ports': 'Các Cổng Nhắm Tới'
        }
        display_port_df.columns = [col_name_map.get(c, c) for c in port_cols]
        port_scans_html = display_port_df.to_html(classes="table", index=False, escape=True)
        
    web_attacks_html = ""
    if df_web_attacks is not None and not df_web_attacks.empty:
        display_web_df = df_web_attacks[['Timestamp', 'Source IP', 'Method', 'URI', 'Attack Category']].head(15).copy()
        display_web_df.columns = ['Thời Gian', 'IP Nguồn', 'Phương Thức', 'Đường Dẫn URI', 'Phân Loại Tấn Công']
        web_attacks_html = display_web_df.to_html(classes="table", index=False, escape=True)
        
    dos_html = ""
    if df_dos is not None and not df_dos.empty:
        dos_cols = [c for c in ['Source IP', 'Target Port', 'Target Service', 'Attack Type', 'Packet Count', 'Rate (pkts/s)', 'Peak (pkts/s)', 'Risk Level'] if c in df_dos.columns]
        display_dos_df = df_dos[dos_cols].head(15).copy()
        dos_name_map = {
            'Source IP': 'IP Nguồn',
            'Target Port': 'Cổng Đích',
            'Target Service': 'Dịch Vụ',
            'Attack Type': 'Loại Tấn Công',
            'Packet Count': 'Số Gói Tin',
            'Rate (pkts/s)': 'Tốc Độ (gói/s)',
            'Peak (pkts/s)': 'Đỉnh (gói/s)',
            'Risk Level': 'Mức Rủi Ro'
        }
        display_dos_df.columns = [dos_name_map.get(c, c) for c in dos_cols]
        dos_html = display_dos_df.to_html(classes="table", index=False, escape=True)
        
    tls_html = ""
    if df_tls is not None and not df_tls.empty:
        display_tls_df = df_tls[['Timestamp', 'Source IP', 'Dest IP', 'TLS_SNI', 'Entropy', 'Classification']].head(15).copy()
        display_tls_df.columns = ['Thời Gian', 'IP Nguồn', 'IP Đích', 'Tên Miền HTTPS (SNI)', 'Entropy', 'Đánh Giá An Ninh']
        tls_html = display_tls_df.to_html(classes="table", index=False, escape=True)
        
    dns_probes_html = ""
    if df_dns_probes is not None and not df_dns_probes.empty:
        display_dns_df = df_dns_probes[['Timestamp', 'Source IP', 'Domain', 'Classification']].head(15).copy()
        display_dns_df.columns = ['Thời Gian', 'IP Nguồn', 'Tên Miền Truy Vấn', 'Phân Loại']
        dns_probes_html = display_dns_df.to_html(classes="table", index=False, escape=True)

    dns_tunneling_html = ""
    if df_dns_tunneling is not None and not df_dns_tunneling.empty:
        display_dns_tunnel_df = df_dns_tunneling[['Timestamp', 'Source IP', 'Dest IP', 'Domain', 'Entropy', 'Classification']].head(15).copy()
        display_dns_tunnel_df.columns = ['Thời Gian', 'IP Nguồn', 'IP Đích', 'Tên Miền DNS', 'Entropy', 'Phân Loại']
        dns_tunneling_html = display_dns_tunnel_df.to_html(classes="table", index=False, escape=True)
        
    top_threat_ips_html = ""
    if df_threat_ips is not None and not df_threat_ips.empty:
        threat_cols = [c for c in ['IP', 'Threat Category', 'Hit Count', 'Targeted Vectors'] if c in df_threat_ips.columns]
        display_threat_df = df_threat_ips[threat_cols].head(25).copy()
        display_threat_df.columns = ['Địa Chỉ IP', 'Nhóm Đe Dọa', 'Số Lần Vi Phạm', 'Mục Tiêu Tấn Công'][:len(threat_cols)]
        top_threat_ips_html = display_threat_df.to_html(classes="table", index=False, escape=True)

    external_connections_html = ""
    if df_external is not None and not df_external.empty:
        ext_cols = [c for c in ['External IP', 'Internal IP', 'Direction', 'Protocols', 'Targeted Ports', 'Total Packets', 'Connection Count', 'SYN Count', 'First Seen', 'Last Seen', 'Status', 'Risk Level', 'Flag Reason'] if c in df_external.columns]
        display_ext_df = df_external[ext_cols].head(25).copy()
        col_ext_map = {
            'External IP': 'IP Bên Ngoài',
            'Internal IP': 'Máy Nội Bộ',
            'Direction': 'Hướng',
            'Protocols': 'Giao Thức',
            'Targeted Ports': 'Cổng Đích',
            'Total Packets': 'Số Gói',
            'Connection Count': 'Số Kết Nối',
            'SYN Count': 'Số SYN',
            'First Seen': 'Xuất Hiện Đầu',
            'Last Seen': 'Xuất Hiện Cuối',
            'Status': 'Trạng Thái',
            'Risk Level': 'Mức Rủi Ro',
            'Flag Reason': 'Lý Do Đánh Dấu'
        }
        display_ext_df.columns = [col_ext_map.get(c, c) for c in ext_cols]
        external_connections_html = display_ext_df.to_html(classes="table", index=False, escape=True)
    
    # 4. Render HTML với dữ liệu
    html_content = template.render(
        filename=data.get('filename', 'Không rõ'),
        server_ip=data.get('server_ip', 'Chưa xác định'),
        report_date=data.get('report_date', ''),
        total_packets=f"{data.get('total_packets', 0):,}",
        port_scan_count=f"{len(df_port_scans):,}" if df_port_scans is not None and not df_port_scans.empty else 0,
        web_attack_count=f"{len(df_web_attacks):,}" if df_web_attacks is not None and not df_web_attacks.empty else 0,
        dos_count=f"{len(df_dos):,}" if df_dos is not None and not df_dos.empty else 0,
        tls_count=f"{len(df_tls):,}" if df_tls is not None and not df_tls.empty else 0,
        dns_inbound_count=f"{len(df_dns_probes):,}" if df_dns_probes is not None and not df_dns_probes.empty else 0,
        dns_tunneling_count=f"{len(df_dns_tunneling):,}" if df_dns_tunneling is not None and not df_dns_tunneling.empty else 0,
        external_ip_count=f"{len(df_external):,}" if df_external is not None and not df_external.empty else 0,
        suspicious_external_count=f"{len(df_external[df_external['Status'] == 'Đáng ngờ']):,}" if df_external is not None and not df_external.empty and 'Status' in df_external.columns else 0,
        port_scans_html=port_scans_html,
        web_attacks_html=web_attacks_html,
        dos_html=dos_html,
        tls_html=tls_html,
        dns_probes_html=dns_probes_html,
        dns_tunneling_html=dns_tunneling_html,
        top_threat_ips_html=top_threat_ips_html,
        external_connections_html=external_connections_html,
        has_external_connections=bool(df_external is not None and not df_external.empty),
        chart_protocol=chart_b64.get('protocol', ''),
        chart_time=chart_b64.get('time', ''),
        chart_web_attacks=chart_b64.get('web_attacks', ''),
        chart_dos=chart_b64.get('dos', ''),
        chart_external=chart_b64.get('external_connections', '')
    )
    return html_content

def generate_html_report(template_path, data, figures):
    """
    Sinh file HTML báo cáo độc lập (Standalone HTML Report) - Xem được ngay trên mọi trình duyệt.
    """
    return render_report_html(template_path, data, figures)

def generate_pdf_report(template_path, data, figures):
    """
    Sinh nội dung PDF báo cáo (dạng bytes) từ template HTML và dữ liệu Pandas/Plotly.
    Tự động sử dụng Chromium/Edge Engine có sẵn hoặc wkhtmltopdf.
    Đảm bảo tự động dọn dẹp các tệp tạm thời sau khi hoàn tất.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        html_content = render_report_html(template_path, data, figures)
        
        html_path = os.path.join(temp_dir, "report.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        pdf_path = os.path.join(temp_dir, "report.pdf")
        
        engines = _find_all_pdf_engines()
        
        # Thử qua danh sách engine khả dụng theo thứ tự ưu tiên
        for engine_type, engine_path in engines:
            # 1. Sử dụng Chromium/Edge Headless Engine (Sẵn có trên 100% máy tính Windows / Linux / macOS)
            if engine_type == 'browser' and engine_path:
                cmd = [
                    engine_path,
                    "--headless=new",
                    "--disable-gpu",
                    "--no-pdf-header-footer",
                    f"--print-to-pdf={pdf_path}",
                    html_path
                ]
                try:
                    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
                    if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                        with open(pdf_path, "rb") as pf:
                            return pf.read()
                except Exception as e:
                    logger.warning("Browser PDF rendering failed: %s", e)
                    continue  # Thử engine tiếp theo
                    
            # 2. Sử dụng wkhtmltopdf nếu có cấu hình
            elif engine_type == 'wkhtmltopdf' and engine_path:
                try:
                    import pdfkit  # type: ignore
                    options = {
                        'enable-local-file-access': None,
                        'encoding': "UTF-8",
                        'margin-top': '0.6in',
                        'margin-right': '0.6in',
                        'margin-bottom': '0.6in',
                        'margin-left': '0.6in'
                    }
                    config = pdfkit.configuration(wkhtmltopdf=engine_path)
                    pdfkit.from_file(html_path, pdf_path, options=options, configuration=config)
                    if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                        with open(pdf_path, "rb") as pf:
                            return pf.read()
                except Exception as e:
                    logger.warning("wkhtmltopdf rendering failed: %s", e)
                    continue
            
        # 3. Thử qua pdfkit mặc định
        try:
            import pdfkit  # type: ignore
            pdfkit.from_file(html_path, pdf_path)
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                with open(pdf_path, "rb") as pf:
                    return pf.read()
        except Exception:
            pass
            
        raise OSError("Không thể sinh file PDF bằng các công cụ khả dụng trên hệ thống.")
