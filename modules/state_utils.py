import hashlib
import ipaddress
from typing import Dict, Any, Optional

def compute_file_id(file_bytes: bytes) -> str:
    """
    Tính mã định danh băm an toàn SHA-256 từ nội dung byte của tệp tin.
    Đảm bảo 2 tệp có cùng tên/kích thước nhưng khác nội dung sẽ có mã khác nhau.
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("file_bytes phải là kiểu bytes hoặc bytearray")
    return hashlib.sha256(file_bytes).hexdigest()[:16]


def make_server_ip_widget_key(file_id: str) -> str:
    """
    Tạo widget key riêng biệt cho input Server IP gắn liền với file ID,
    tránh rò rỉ giá trị IP giữa các tệp PCAP khác nhau.
    """
    return f"server_ip_input_{file_id}"


def compute_analysis_context_id(file_id: str, server_ip: Optional[str] = None) -> str:
    """
    Tạo mã định danh ngữ cảnh phân tích kết hợp giữa file_id và server_ip.
    Đảm bảo khi người dùng đổi Server IP trên cùng một tệp PCAP, context ID sẽ đổi và báo cáo cũ bị xóa.
    """
    clean_ip = str(server_ip).strip() if server_ip else "auto"
    raw_key = f"{file_id}_{clean_ip}"
    return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:16]


def reset_report_state_if_context_changed(session_state: Dict[str, Any], context_id: str) -> bool:
    """
    Xóa các artifact báo cáo (PDF, HTML) khi ngữ cảnh phân tích (file hoặc server_ip) thay đổi.
    Trả về True nếu context bị thay đổi và đã dọn sạch báo cáo cũ.
    """
    current_context = session_state.get('report_context_id')
    if current_context != context_id:
        session_state['report_context_id'] = context_id
        session_state['report_current_file_id'] = context_id
        session_state.pop('generated_pdf', None)
        session_state.pop('generated_pdf_name', None)
        session_state.pop('generated_html', None)
        session_state.pop('generated_html_name', None)
        return True
    return False


def reset_file_scoped_state(session_state: Dict[str, Any], new_file_id: str, server_ip: Optional[str] = None) -> bool:
    """
    Reset toàn bộ trạng thái gắn liền với tệp cũ khi người dùng đổi tệp PCAP hoặc đổi Server IP.
    Trả về True nếu có sự chuyển đổi tệp/server_ip (reset được thực hiện), False nếu không đổi.
    """
    context_id = compute_analysis_context_id(new_file_id, server_ip)
    file_changed = session_state.get('current_file_hash') != new_file_id
    context_changed = session_state.get('report_context_id') != context_id
    
    if file_changed or context_changed:
        session_state['current_file_hash'] = new_file_id
        session_state['report_context_id'] = context_id
        session_state['report_current_file_id'] = new_file_id
        
        # Xóa các artifact báo cáo của tệp hoặc Server IP cũ
        session_state.pop('generated_pdf', None)
        session_state.pop('generated_pdf_name', None)
        session_state.pop('generated_html', None)
        session_state.pop('generated_html_name', None)
        return True
    return False


def validate_ip_address(ip_str: Optional[str]) -> bool:
    """
    Kiểm tra tính hợp lệ nghiêm ngặt của địa chỉ IP (IPv4 hoặc IPv6).
    Trả về True nếu hợp lệ, False nếu chuỗi rỗng hoặc không đúng định dạng.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean_ip = ip_str.strip()
    if not clean_ip:
        return False
    try:
        ipaddress.ip_address(clean_ip)
        return True
    except ValueError:
        return False
