import io
import socket
import datetime
import dpkt  # type: ignore
import pandas as pd  # type: ignore
import streamlit as st  # type: ignore
from modules.constants import Col

def inet_to_str(inet):
    """
    Chuyển đổi địa chỉ IP dạng byte sang chuỗi string.
    Hỗ trợ cả IPv4 và IPv6.
    """
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except ValueError:
            return "Unknown"

def get_protocol_name(proto):
    """Lấy tên giao thức cơ bản từ số protocol của IP."""
    mapping = {
        1: 'ICMP', 
        2: 'IGMP',
        4: 'IPv4',
        6: 'TCP', 
        7: 'CBT',
        8: 'EGP',
        9: 'IGP',
        17: 'UDP',
        29: 'IPv6',
        30: 'IPv6-Route',
        31: 'IPv6-Frag',
        32: 'GRE',
        33: 'ESP',
        34: 'AH',
        58: 'ICMPv6',
        59: 'IPv6-NoNxt',
        60: 'IPv6-Opts',
        89: 'OSPF',
        112: 'VRRP',
        132: 'SCTP'
    }
    return mapping.get(proto, f'Unknown ({proto})')

def extract_tls_sni(payload):
    """
    Trích xuất Server Name Indication (SNI) từ gói tin TLS ClientHello.
    Hỗ trợ phân tích cả TLS 1.0, 1.1, 1.2, 1.3 và an toàn tuyệt đối trước packet lỗi.
    """
    if not payload or len(payload) < 44:
        return ""
    try:
        # TLS Record Header: Byte 0 = 0x16 (Handshake), Byte 5 = 0x01 (ClientHello)
        if payload[0] == 0x16 and len(payload) > 5 and payload[5] == 0x01:
            pos = 43  # Bỏ qua 5 byte record header + 4 byte handshake header + 2 byte version + 32 byte random
            if pos >= len(payload):
                return ""
            # Bỏ qua Session ID
            session_id_len = payload[pos]
            pos += 1 + session_id_len
            if pos + 2 > len(payload):
                return ""
            # Bỏ qua Cipher Suites
            cipher_suites_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2 + cipher_suites_len
            if pos + 1 > len(payload):
                return ""
            # Bỏ qua Compression Methods
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload):
                return ""
            # Extensions List
            exts_len = int.from_bytes(payload[pos:pos+2], 'big')
            pos += 2
            end_exts = min(pos + exts_len, len(payload))
            while pos + 4 <= end_exts:
                ext_type = int.from_bytes(payload[pos:pos+2], 'big')
                ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
                pos += 4
                if ext_type == 0:  # Server Name Extension (SNI)
                    if pos + 5 <= end_exts:
                        name_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                        if pos + 5 + name_len <= end_exts:
                            return payload[pos+5:pos+5+name_len].decode('utf-8', errors='ignore')
                pos += ext_len
    except Exception:
        pass
    return ""

class SimpleTcpStreamReassembler:
    """
    Tái tạo luồng TCP có nhận biết Sequence Number:
    - Quản lý phân đoạn theo dải [seq, seq + len).
    - Xử lý out-of-order, trùng lặp retransmission, và byte chồng lấn (partial overlap).
    - Nhận biết gap (lỗ hổng gói tin) và chỉ trả về buffer liên tục từ sequence bắt đầu.
    - Giới hạn bộ nhớ và dọn dẹp theo LRU.
    """
    def __init__(self, max_streams=1000, max_stream_bytes=32768):
        self.streams = {}
        self.max_streams = max_streams
        self.max_stream_bytes = max_stream_bytes
        self.stats = {
            'streams_created': 0,
            'streams_evicted': 0,
            'segments_added': 0,
            'retransmissions_ignored': 0
        }

    def add_segment(self, stream_key, seq, data, ts):
        if not data:
            return b""
        self.stats['segments_added'] += 1
        
        if stream_key not in self.streams:
            if len(self.streams) >= self.max_streams:
                oldest_key = min(self.streams, key=lambda k: self.streams[k]['last_ts'])
                del self.streams[oldest_key]
                self.stats['streams_evicted'] += 1
            self.streams[stream_key] = {
                'segments': [(seq, bytes(data))],
                'last_ts': ts
            }
            self.stats['streams_created'] += 1
            return bytes(data)
            
        st = self.streams[stream_key]
        st['last_ts'] = ts
        
        # Kiểm tra trùng lặp hoàn toàn (retransmission)
        data_len = len(data)
        for s_seq, s_data in st['segments']:
            if s_seq == seq and len(s_data) == data_len:
                self.stats['retransmissions_ignored'] += 1
                return self._assemble_stream(st)
                
        # Thêm segment mới
        st['segments'].append((seq, bytes(data)))
        
        # Giới hạn số segment tối đa trong một stream để chống tràn RAM
        if len(st['segments']) > 64:
            st['segments'] = st['segments'][-64:]
            
        return self._assemble_stream(st)

    def _assemble_stream(self, st):
        segments = st['segments']
        if not segments:
            return b""
            
        # Xác định base_seq: ưu tiên segment bắt đầu bằng HTTP Method hoặc TLS Handshake
        http_prefixes = (b'GET ', b'POST', b'HEAD', b'PUT ', b'DELE', b'OPTI', b'PATC', b'CONN', b'TRAC', b'\x16\x03')
        base_seq = None
        for s_seq, s_data in segments:
            if any(s_data.startswith(p) for p in http_prefixes):
                base_seq = s_seq
                break
                
        if base_seq is None:
            base_seq = min(s[0] for s in segments)
            
        # Sắp xếp các segment theo độ lệch modulo 2^32 so với base_seq (xử lý wrap-around 32-bit)
        sorted_segs = sorted(segments, key=lambda s: (s[0] - base_seq) % (1 << 32))
        
        # Ghép nối tuần tự các byte liên tục không bị đứt đoạn (gap)
        assembled = bytearray()
        for s_seq, s_data in sorted_segs:
            rel_start = (s_seq - base_seq) % (1 << 32)
            rel_end = rel_start + len(s_data)
            
            if len(assembled) >= self.max_stream_bytes:
                break
                
            if rel_start > len(assembled):
                # Phát hiện khoảng cách (gap) -> dừng ghép nối tại đây
                break
            elif rel_end <= len(assembled):
                # Segment này đã nằm trọn trong phần đã ghép (retransmission/overlap hoàn toàn)
                continue
            elif rel_start < len(assembled):
                # Trùng lặp một phần (partial overlap) -> chỉ lấy các byte mới phía sau
                offset = len(assembled) - rel_start
                chunk_to_add = s_data[offset : offset + (self.max_stream_bytes - len(assembled))]
                assembled.extend(chunk_to_add)
            else:
                # rel_start == len(assembled) -> liên tục hoàn hảo
                chunk_to_add = s_data[: self.max_stream_bytes - len(assembled)]
                assembled.extend(chunk_to_add)
                
        return bytes(assembled)

    def remove_stream(self, stream_key):
        self.streams.pop(stream_key, None)


def extract_ip_packet(buf, datalink_type):
    """
    Trích xuất đối tượng IP/IPv6 dựa trên datalink_type của PCAP.
    Hỗ trợ Ethernet (DLT_EN10MB), Linux Cooked SLL, Loopback (NULL/LOOP), và Raw IP.
    Trả về tuple: (ip_obj, status)
    status: 'ok', 'not_ip', 'truncated', 'unsupported'
    """
    if not buf:
        return None, 'truncated'
        
    try:
        if datalink_type == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return eth.data, 'ok'
            return None, 'not_ip'
            
        elif datalink_type == getattr(dpkt.pcap, 'DLT_LINUX_SLL', 113):
            sll = dpkt.sll.SLL(buf)
            if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return sll.data, 'ok'
            return None, 'not_ip'
            
        elif datalink_type in (getattr(dpkt.pcap, 'DLT_NULL', 0), getattr(dpkt.pcap, 'DLT_LOOP', 108)):
            lb = dpkt.loopback.Loopback(buf)
            if isinstance(lb.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return lb.data, 'ok'
            return None, 'not_ip'
            
        elif datalink_type in (getattr(dpkt.pcap, 'DLT_RAW', 12), 101, 228, 229):
            v = buf[0] >> 4
            if v == 4:
                return dpkt.ip.IP(buf), 'ok'
            elif v == 6:
                return dpkt.ip6.IP6(buf), 'ok'
            return None, 'not_ip'
            
        else:
            # Fallback heuristic: Thử Ethernet trước, sau đó thử Raw IP
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    return eth.data, 'ok'
            except (dpkt.NeedData, dpkt.UnpackError):
                return None, 'truncated'
            except Exception:
                pass
                
            try:
                v = buf[0] >> 4
                if v == 4:
                    return dpkt.ip.IP(buf), 'ok'
                elif v == 6:
                    return dpkt.ip6.IP6(buf), 'ok'
            except (dpkt.NeedData, dpkt.UnpackError):
                return None, 'truncated'
            except Exception:
                pass
                
            return None, 'unsupported'
            
    except (dpkt.NeedData, dpkt.UnpackError):
        return None, 'truncated'
    except Exception:
        return None, 'malformed'


def get_parser_stats(df):
    """Trích xuất từ điển thống kê quá trình phân tích gói tin từ thuộc tính DataFrame."""
    if hasattr(df, 'attrs') and 'parser_stats' in df.attrs:
        return df.attrs['parser_stats']
    return {
        'total_packets': len(df) if not df.empty else 0,
        'parsed_packets': len(df) if not df.empty else 0,
        'skipped_packets': 0,
        'truncated_packets': 0,
        'unsupported_packets': 0,
        'datalink_name': 'Unknown'
    }


def detect_server_ip(df):
    """
    Tự động nhận diện địa chỉ IP máy chủ (Server IP) chính trong file PCAP.
    Thuật toán:
    1. Máy chủ thường là IP xuất hiện nhiều nhất ở vai trò Dest IP khi nhận kết nối dịch vụ (cổng 80, 443, 53, 22...).
    2. Hoặc là IP có tổng số gói tin (Gửi + Nhận) lớn nhất trong phiên bắt gói.
    """
    if df.empty or Col.DEST_IP not in df.columns or Col.SOURCE_IP not in df.columns:
        return None
        
    # Lấy IP nhận nhiều kết nối nhất trên các cổng dịch vụ tiêu chuẩn
    service_ports = [80, 443, 53, 22, 8080, 8443, 3306, 5432, 21, 25]
    if Col.DEST_PORT in df.columns:
        service_packets = df[df[Col.DEST_PORT].isin(service_ports)]
        if not service_packets.empty:
            top_dest = service_packets[Col.DEST_IP].value_counts()
            if not top_dest.empty and top_dest.iloc[0] > 0:
                return str(top_dest.index[0])
            
    # Dự phòng: Lấy IP có tổng số gói tin xuất hiện nhiều nhất
    ip_counts = pd.concat([df[Col.SOURCE_IP].astype(str), df[Col.DEST_IP].astype(str)]).value_counts()
    if not ip_counts.empty:
        return str(ip_counts.index[0])
    return None

@st.cache_data(show_spinner=False)
def load_pcap(file_content, max_packets=2_000_000):
    """
    Đọc và phân tích file PCAP từ bộ đệm byte với hiệu năng tối ưu (Columnar Buffering & Vectorized Timestamps).
    Sử dụng chunk-based generator của dpkt để tiết kiệm bộ nhớ và không block giao diện.
    Hỗ trợ dispatch đa link-layer (Ethernet, Linux Cooked SLL, Loopback, Raw IP),
    reassemble TCP stream cho HTTP nhiều segment, và thu thập thống kê parsing.
    """
    f = io.BytesIO(file_content)
    total_size = len(file_content)
    
    try:
        # Thử đọc định dạng .pcap truyền thống
        pcap = dpkt.pcap.Reader(f)
    except Exception:
        # Nếu lỗi, quay lại đầu file và thử đọc định dạng .pcapng
        f.seek(0)
        try:
            pcap = dpkt.pcapng.Reader(f)
        except Exception:
            st.error("Không thể phân tích định dạng file. Vui lòng đảm bảo file là .pcap hoặc .pcapng hợp lệ.")
            return pd.DataFrame()

    # Xác định datalink type
    datalink_type = dpkt.pcap.DLT_EN10MB
    if hasattr(pcap, 'datalink'):
        try:
            datalink_type = pcap.datalink()
        except Exception:
            datalink_type = dpkt.pcap.DLT_EN10MB

    datalink_names = {
        dpkt.pcap.DLT_EN10MB: "Ethernet",
        getattr(dpkt.pcap, 'DLT_LINUX_SLL', 113): "Linux Cooked (SLL)",
        getattr(dpkt.pcap, 'DLT_NULL', 0): "Loopback (NULL)",
        getattr(dpkt.pcap, 'DLT_LOOP', 108): "Loopback (LOOP)",
        getattr(dpkt.pcap, 'DLT_RAW', 12): "Raw IP"
    }
    datalink_name = datalink_names.get(datalink_type, f"Datalink Type {datalink_type}")

    # Columnar Buffers giúp tăng tốc cấp phát bộ nhớ lên 2x
    timestamps = []
    src_ips = []
    dst_ips = []
    src_ports = []
    dst_ports = []
    protocols = []
    lengths = []
    infos = []
    tcp_flags_list = []
    http_methods_list = []
    http_uris_list = []
    http_bodies_list = []
    http_uas_list = []
    http_hosts_list = []
    tls_snis_list = []
    
    progress_text = "Đang phân tích gói tin..."
    progress_bar = st.progress(0, text=progress_text)
    
    packet_count = 0
    parsed_count = 0
    skipped_count = 0
    truncated_count = 0
    unsupported_count = 0
    
    chunk_size = 15000  # Cập nhật UI sau mỗi 15,000 gói tin
    http_methods = (b'GET ', b'POST', b'HEAD', b'PUT ', b'DELE', b'OPTI', b'PATC', b'CONN', b'TRAC')
    reassembler = SimpleTcpStreamReassembler(max_streams=1000, max_stream_bytes=32768)
    
    # Generator pcap tự động đọc từng gói, không load toàn bộ vào RAM
    for timestamp, buf in pcap:
        packet_count += 1
        
        if max_packets and packet_count > max_packets:
            st.warning(f"⚠️ File vượt quá giới hạn an toàn. Đã phân tích {max_packets:,} gói tin đầu tiên.")
            break
            
        # Cập nhật thanh tiến trình theo tỷ lệ byte đã đọc
        if packet_count % chunk_size == 0:
            current_pos = f.tell()
            progress = min(current_pos / total_size, 1.0)
            progress_bar.progress(progress, text=f"Đã phân tích {packet_count:,} gói tin...")
            
        # Dispatch đa dạng link-layer
        ip, status = extract_ip_packet(buf, datalink_type)
        if status == 'not_ip':
            skipped_count += 1
            continue
        elif status == 'truncated':
            truncated_count += 1
            continue
        elif status == 'unsupported':
            unsupported_count += 1
            continue
        elif ip is None:
            skipped_count += 1
            continue
            
        parsed_count += 1
        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)
        proto = get_protocol_name(ip.p)
        length = len(buf)
        
        src_port = None
        dst_port = None
        info = ""
        tcp_flags = ""
        http_method = ""
        http_uri = ""
        http_body = ""
        http_ua = ""
        http_host = ""
        tls_sni = ""
        
        # Phân tích sâu hơn với TCP
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            src_port = tcp.sport
            dst_port = tcp.dport
            
            # Trích xuất các cờ TCP
            flags = []
            if tcp.flags & dpkt.tcp.TH_FIN: flags.append('FIN')
            if tcp.flags & dpkt.tcp.TH_SYN: flags.append('SYN')
            if tcp.flags & dpkt.tcp.TH_RST: flags.append('RST')
            if tcp.flags & dpkt.tcp.TH_PUSH: flags.append('PSH')
            if tcp.flags & dpkt.tcp.TH_ACK: flags.append('ACK')
            if tcp.flags & dpkt.tcp.TH_URG: flags.append('URG')
            tcp_flags = ','.join(flags)
            info = f"TCP Flags: {tcp_flags}" if tcp_flags else "TCP"
            
            # Trích xuất TLS SNI nếu là HTTPS / TLS Handshake
            if len(tcp.data) > 0 and (dst_port in (443, 8443, 4433, 9443) or src_port in (443, 8443, 4433, 9443) or tcp.data.startswith(b'\x16\x03')):
                tls_sni = extract_tls_sni(tcp.data)
                if tls_sni:
                    info = f"TLS SNI: {tls_sni}"
            
            # Trích xuất HTTP Request và HTTP Body có hỗ trợ TCP stream reassembly
            stream_key = (src_ip, src_port, dst_ip, dst_port)

            web_ports = (80, 8080, 8000, 8888, 3000, 5000, 9090)
            is_candidate_web = (dst_port in web_ports or src_port in web_ports or 
                                (len(tcp.data) >= 4 and tcp.data[:4] in http_methods) or 
                                stream_key in reassembler.streams)

            if not tls_sni and len(tcp.data) > 0 and is_candidate_web:
                parsed_req = None
                # Thử parse direct nếu gói tin đã có đủ header kết thúc bằng CRLF CRLF
                if tcp.data[:4] in http_methods and b'\r\n\r\n' in tcp.data:
                    try:
                        parsed_req = dpkt.http.Request(tcp.data)
                        reassembler.remove_stream(stream_key)
                    except Exception:
                        parsed_req = None
                
                # Nếu không parse direct được hoặc đang có stream, tích lũy qua reassembler
                if parsed_req is None:
                    accumulated = reassembler.add_segment(stream_key, tcp.seq, tcp.data, timestamp)
                    if accumulated and any(accumulated.startswith(m) for m in http_methods):
                        if b'\r\n\r\n' in accumulated:
                            try:
                                parsed_req = dpkt.http.Request(accumulated)
                                reassembler.remove_stream(stream_key)
                            except Exception:
                                pass
                                
                if parsed_req is not None:
                    try:
                        req = parsed_req
                        http_method = req.method if isinstance(req.method, str) else str(req.method)
                        http_uri = req.uri if isinstance(req.uri, str) else str(req.uri)
                        
                        # Trích xuất HTTP Body (giới hạn 1024 bytes chống tràn RAM)
                        if hasattr(req, 'body') and req.body:
                            if isinstance(req.body, bytes):
                                http_body = req.body[:1024].decode('utf-8', errors='ignore')
                            else:
                                http_body = str(req.body)[:1024]
                                
                        raw_h = req.headers.get('host', '')
                        if isinstance(raw_h, bytes):
                            http_host = raw_h.decode('utf-8', errors='ignore')
                        elif isinstance(raw_h, list):
                            http_host = ", ".join(str(x) for x in raw_h)
                        else:
                            http_host = str(raw_h)
                            
                        raw_ua = req.headers.get('user-agent', '')
                        if isinstance(raw_ua, bytes):
                            http_ua = raw_ua.decode('utf-8', errors='ignore')
                        elif isinstance(raw_ua, list):
                            http_ua = ", ".join(str(x) for x in raw_ua)
                        else:
                            http_ua = str(raw_ua)
                        info = f"HTTP {http_method} {http_uri}"
                    except Exception:
                        pass

            # Đóng luồng nếu gói tin có cờ kết thúc (FIN hoặc RST) sau khi đã xử lý payload
            if tcp.flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
                reassembler.remove_stream(stream_key)
            
        # Phân tích UDP và DNS
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            src_port = udp.sport
            dst_port = udp.dport
            info = "UDP"
            
            # Nếu cổng 53, khả năng cao là DNS
            if src_port == 53 or dst_port == 53:
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.qr == dpkt.dns.DNS_Q: # Truy vấn DNS
                        if len(dns.qd) > 0:
                            info = f"DNS Query: {dns.qd[0].name}"
                    elif dns.qr == dpkt.dns.DNS_R: # Phản hồi DNS
                        info = "DNS Response"
                except Exception:
                    pass
                    
        # Phân tích ICMP
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            info = f"ICMP Type: {icmp.type} Code: {icmp.code}"
            
        timestamps.append(timestamp)
        src_ips.append(src_ip)
        dst_ips.append(dst_ip)
        src_ports.append(src_port)
        dst_ports.append(dst_port)
        protocols.append(proto)
        lengths.append(length)
        infos.append(info)
        tcp_flags_list.append(tcp_flags)
        http_methods_list.append(http_method)
        http_uris_list.append(http_uri)
        http_bodies_list.append(http_body)
        http_uas_list.append(http_ua)
        http_hosts_list.append(http_host)
        tls_snis_list.append(tls_sni)
        
    # Xoá thanh tiến trình sau khi hoàn thành
    progress_bar.empty()
    
    if not timestamps:
        empty_df = pd.DataFrame()
        empty_df.attrs['parser_stats'] = {
            'total_packets': packet_count,
            'parsed_packets': 0,
            'skipped_packets': skipped_count,
            'truncated_packets': truncated_count,
            'unsupported_packets': unsupported_count,
            'datalink_name': datalink_name
        }
        return empty_df
        
    # Tạo DataFrame trực tiếp từ Columnar Buffers
    df = pd.DataFrame({
        Col.TIMESTAMP: timestamps,
        Col.SOURCE_IP: src_ips,
        Col.DEST_IP: dst_ips,
        Col.SOURCE_PORT: src_ports,
        Col.DEST_PORT: dst_ports,
        Col.PROTOCOL: protocols,
        Col.LENGTH: lengths,
        Col.INFO: infos,
        Col.TCP_FLAGS: tcp_flags_list,
        Col.HTTP_METHOD: http_methods_list,
        Col.HTTP_URI: http_uris_list,
        Col.HTTP_BODY: http_bodies_list,
        Col.HTTP_UA: http_uas_list,
        Col.HTTP_HOST: http_hosts_list,
        Col.TLS_SNI: tls_snis_list
    })
    
    # Vectorized Timestamp Conversion: Cực nhanh (5-10x so với Python loop)
    df[Col.TIMESTAMP] = pd.to_datetime(df[Col.TIMESTAMP], unit='s', utc=True)
    
    # Sắp xếp theo thời gian để dễ dàng phân tích sau này
    df = df.sort_values(by=Col.TIMESTAMP).reset_index(drop=True)
    
    # Tối ưu RAM: Chuyển đổi kiểu dữ liệu các cột lặp lại thành category
    for col in [Col.SOURCE_IP, Col.DEST_IP, Col.PROTOCOL, Col.TCP_FLAGS]:
        if col in df.columns:
            df[col] = df[col].astype('category')
            
    # Gắn metadata thống kê parse
    df.attrs['parser_stats'] = {
        'total_packets': packet_count,
        'parsed_packets': parsed_count,
        'skipped_packets': skipped_count,
        'truncated_packets': truncated_count,
        'unsupported_packets': unsupported_count,
        'datalink_name': datalink_name
    }
    
    return df
