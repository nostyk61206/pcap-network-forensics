import os
import sys
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=80, bottom=80, left=120, right=120):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'''
        <w:tcMar {nsdecls("w")}>
            <w:top w:w="{top}" w:type="dxa"/>
            <w:bottom w:w="{bottom}" w:type="dxa"/>
            <w:left w:w="{left}" w:type="dxa"/>
            <w:right w:w="{right}" w:type="dxa"/>
        </w:tcMar>
    ''')
    tcPr.append(tcMar)

def create_guide_docx(output_path):
    doc = Document()
    
    # Canh lề trang
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Style chuẩn
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(12)
    normal_style.font.color.rgb = RGBColor(0x1F, 0x29, 0x37)
    normal_style.paragraph_format.line_spacing = 1.25
    normal_style.paragraph_format.space_after = Pt(4)

    def add_title(text):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run(text)
        run.bold = True
        run.font.name = 'Times New Roman'
        run.font.size = Pt(16)
        run.font.color.rgb = RGBColor(0x02, 0x84, 0xC7)
        return p

    def add_subtitle(text):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(12)
        run = p.add_run(text)
        run.bold = True
        run.font.name = 'Times New Roman'
        run.font.size = Pt(12.5)
        run.font.color.rgb = RGBColor(0x47, 0x55, 0x69)
        return p

    def add_h1(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(12)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.bold = True
        run.font.name = 'Times New Roman'
        run.font.size = Pt(13.5)
        run.font.color.rgb = RGBColor(0x02, 0x84, 0xC7)
        return p

    def add_h2(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.bold = True
        run.font.name = 'Times New Roman'
        run.font.size = Pt(12)
        run.font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)
        return p

    def add_bullet(text, bold_prefix=""):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(2.5)
        p.paragraph_format.line_spacing = 1.15
        if bold_prefix:
            r_b = p.add_run(bold_prefix)
            r_b.bold = True
        p.add_run(text)
        return p

    def add_code_block(code_text):
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = tbl.cell(0, 0)
        cell.width = Inches(6.5)
        set_cell_background(cell, "F1F5F9")
        set_cell_margins(cell, top=60, bottom=60, left=100, right=100)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.1
        r = p.add_run(code_text)
        r.font.name = 'Consolas'
        r.font.size = Pt(10.5)
        r.font.color.rgb = RGBColor(0x0F, 0x17, 0x2A)
        doc.add_paragraph()

    # Header tài liệu
    add_title("HƯỚNG DẪN CÀI ĐẶT VÀ SỬ DỤNG MÃ NGUỒN\nCÔNG CỤ PCAP ANALYZER")
    add_subtitle("PCAP Threat Visualizer & Automated SOC Investigation Tool")

    # 1. Giới thiệu
    add_h1("1. Giới thiệu tổng quan")
    doc.add_paragraph(
        "PCAP Analyzer là công cụ chuyên nghiệp phục vụ phân tích điều tra số và giám sát an ninh mạng (SOC). Hệ thống tự động bóc tách các tệp bắt gói tin (.pcap / .pcapng), phát hiện các cuộc tấn công mạng nguy hiểm (Port Scan, Flood & DoS, Dò quét mật khẩu qua lưu lượng, Web Attacks SQLi/RCE, DNS Tunneling, TLS C2), trực quan hóa dữ liệu trên Dashboard Dark SOC và xuất báo cáo an ninh định dạng PDF tự động."
    )

    # 2. Yêu cầu hệ thống
    add_h1("2. Yêu cầu hệ thống")
    add_bullet(" Windows 10/11, Linux (Ubuntu/Debian/CentOS) hoặc macOS.", "• Hệ điều hành:")
    add_bullet(" Khuyến nghị Python phiên bản 3.10, 3.11 hoặc 3.12+ (đã tích hợp sẵn pip).", "• Môi trường Python:")
    add_bullet(" Tối thiểu 4GB RAM, ổ cứng trống từ 500MB trở lên.", "• Bộ nhớ & Lưu trữ:")
    add_bullet(" Google Chrome, Microsoft Edge, Firefox, Brave...", "• Trình duyệt Web:")

    # 3. Cài đặt từng bước
    add_h1("3. Hướng dẫn cài đặt từng bước")
    
    add_h2("Bước 1: Giải nén mã nguồn")
    doc.add_paragraph("Giải nén tệp PCAP_Analyzer_Project.zip vào một thư mục trên máy tính (ví dụ: D:\\PCAP_Analyzer hoặc /home/user/pcap_analyzer).")

    add_h2("Bước 2: Cài đặt các thư viện cần thiết")
    doc.add_paragraph("Mở Terminal / Command Prompt (CMD) hoặc PowerShell tại thư mục dự án vừa giải nén và chạy lệnh sau:")
    add_code_block("pip install -r requirements.txt")
    doc.add_paragraph("Quá trình này sẽ tự động cài đặt các thư viện: streamlit, dpkt, pandas, plotly, geoip2, jinja2...")

    add_h2("Bước 3: Cơ sở dữ liệu định vị địa lý GeoIP (Tùy chọn)")
    doc.add_paragraph("Để sử dụng tính năng Bản đồ Địa lý, người dùng có thể tải tệp GeoLite2-City.mmdb miễn phí từ MaxMind và đặt vào thư mục data/GeoLite2-City.mmdb theo hướng dẫn trong README.md. Nếu chưa có tệp này, các tính năng phân tích an ninh còn lại vẫn hoạt động bình thường.")

    # 4. Khởi chạy ứng dụng
    add_h1("4. Cách khởi chạy ứng dụng")

    add_h2("Cách 1: Khởi chạy nhanh bằng file Batch (Dành cho Windows - Khuyên Dùng)")
    doc.add_paragraph("Nhấp đúp chuột (Double click) trực tiếp vào tệp run_app.bat trong thư mục dự án. Hệ thống sẽ tự động bật ứng dụng và mở trình duyệt.")

    add_h2("Cách 2: Khởi chạy bằng dòng lệnh Terminal / CMD / PowerShell")
    doc.add_paragraph("Tại thư mục dự án, chạy lệnh sau:")
    add_code_block("streamlit run app.py")
    doc.add_paragraph("Hoặc nếu máy tính có nhiều phiên bản Python:")
    add_code_block("python -m streamlit run app.py")
    doc.add_paragraph("Sau khi chạy, mở trình duyệt web và truy cập địa chỉ: http://localhost:8501")

    # 5. Hướng dẫn sử dụng
    add_h1("5. Hướng dẫn sử dụng các chức năng trên giao diện")

    add_bullet(" Tại thanh bên trái (Sidebar), nhấn 'Browse files' hoặc kéo thả tệp .pcap / .pcapng từ máy tính vào. Công cụ sẽ tự động bóc tách gói tin và phân tích đa luồng.", "• 1. Tải lên tệp PCAP:")
    add_bullet(" Công cụ tự động nhận diện IP máy chủ nhận nhiều lưu lượng nhất. Bạn cũng có thể tự nhập IP máy chủ mục tiêu vào ô 'Địa Chỉ IP Máy Chủ Mục Tiêu' để lọc chính xác.", "• 2. Nhận diện Server IP:")
    add_bullet(" Hiển thị tổng số gói tin, thời lượng phân tích, biểu đồ giao thức mạng, lưu lượng theo thời gian và tỷ lệ các nhóm tấn công.", "• 3. Tab Tổng Quan:")
    add_bullet(" Thống kê Top 10 cổng bị quét, Top IP kẻ quét, phân loại quét TCP SYN/UDP và bảng chi tiết thời gian quét.", "• 4. Tab Port Scan:")
    add_bullet(" Bắt trọn các request SQLi, RCE, Path Traversal, dò file .env/.git; Sub-tab TLS SNI phân loại kết nối HTTPS C2 bất thường.", "• 5. Tab Web Attack & HTTPS:")
    add_bullet(" Tính toán tốc độ dòng gói tin Rate (pkts/s) để phát hiện HTTP/SYN/ICMP/UDP Flood và tần suất kết nối bất thường tới các cổng dịch vụ xác thực (SSH/MongoDB/RDP).", "• 6. Tab Flood & DoS:")
    add_bullet(" Phân tích độ hỗn loạn Shannon Entropy và độ dài domain để phát hiện rò rỉ dữ liệu hoặc kênh điều khiển ngầm qua DNS.", "• 7. Tab DNS Tunneling:")
    add_bullet(" Tổng hợp hồ sơ các IP tấn công nguy hiểm, tự động gán nhãn Multi-vector cho các IP vi phạm nhiều hình thức.", "• 8. Tab Threat IP:")
    add_bullet(" Tra cứu toạ độ IP tấn công và hiển thị trực quan các điểm đỏ xuất phát tấn công trên bản đồ thế giới.", "• 9. Tab Bản Đồ Địa Lý:")
    add_bullet(" Cho phép duyệt từng gói tin thô và bấm nút 'Xuất Bảng CSV' hoặc 'Xuất Tệp JSON' để phục vụ lưu trữ.", "• 10. Tab Raw Data:")
    add_bullet(" Nhấn nút 'Tạo Báo Cáo PDF' để tự động kết xuất toàn bộ kết quả phân tích thành file PDF chuyên nghiệp.", "• 11. Tab Báo Cáo PDF:")

    # 6. Kiểm thử
    add_h1("6. Hướng dẫn chạy kiểm thử tự động (Unit Tests)")
    doc.add_paragraph("Để kiểm tra tính toàn vẹn và độ chính xác của toàn bộ mã nguồn thuật toán, chạy lệnh sau tại thư mục dự án:")
    add_code_block("python -m unittest discover -s tests -p \"test_*.py\"")
    doc.add_paragraph("Kết quả chuẩn: toàn bộ bài kiểm thử được phát hiện đều đạt (OK).")

    # 7. Khắc phục lỗi thường gặp
    add_h1("7. Khắc phục các lỗi thường gặp (Troubleshooting)")

    t_faq = doc.add_table(rows=4, cols=2)
    t_faq.alignment = WD_TABLE_ALIGNMENT.CENTER
    faq_headers = ["Hiện tượng / Thông báo lỗi", "Cách khắc phục"]
    for c_idx, h_text in enumerate(faq_headers):
        c = t_faq.cell(0, c_idx)
        set_cell_background(c, "E2E8F0")
        set_cell_margins(c)
        p = c.paragraphs[0]
        r = p.add_run(h_text)
        r.bold = True
        r.font.size = Pt(11.5)

    faq_data = [
        ("Lỗi: 'streamlit' is not recognized", "Môi trường chưa cài thư viện. Chạy lệnh: pip install -r requirements.txt"),
        ("Lỗi: Cổng 8501 bị xung đột (Port 8501 is already in use)", "Chạy Streamlit trên cổng khác bằng lệnh:\nstreamlit run app.py --server.port 8502"),
        ("Giao diện giữ kết quả của file PCAP cũ", "Nhấn nút '🔄 Làm Mới Bộ Nhớ Đệm' ở Sidebar hoặc tải lại trang trình duyệt (F5).")
    ]

    for r_idx, (col1, col2) in enumerate(faq_data, start=1):
        for c_idx, text in enumerate([col1, col2]):
            cell = t_faq.cell(r_idx, c_idx)
            set_cell_margins(cell)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            r = p.add_run(text)
            if c_idx == 0:
                r.bold = True

    # Lưu file
    doc.save(output_path)
    print(f"Guide document saved successfully at: {output_path}")

def convert_docx_to_pdf(docx_path, pdf_path):
    """Chuyển đổi file DOCX sang PDF bằng Microsoft Word COM Automation."""
    try:
        import win32com.client
        word = win32com.client.Dispatch("Word.Application")
        word.Visible = False
        in_file = os.path.abspath(docx_path)
        out_file = os.path.abspath(pdf_path)
        doc = word.Documents.Open(in_file)
        doc.SaveAs(out_file, FileFormat=17) # 17 = wdFormatPDF
        doc.Close()
        word.Quit()
        print(f"Guide PDF saved successfully at: {pdf_path}")
        return True
    except Exception as e:
        print(f"Warning: Không thể tự động convert DOCX sang PDF: {e}")
        return False

if __name__ == '__main__':
    pcap_dir = os.path.dirname(os.path.abspath(__file__))
    guide_docx = os.path.join(pcap_dir, 'Huong_Dan_Cai_Dat_Va_Su_Dung_PCAP_Analyzer.docx')
    guide_pdf = os.path.join(pcap_dir, 'Huong_Dan_Cai_Dat_Va_Su_Dung_PCAP_Analyzer.pdf')
    create_guide_docx(guide_docx)
    convert_docx_to_pdf(guide_docx, guide_pdf)
