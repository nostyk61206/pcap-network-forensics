import os
import pandas as pd  # type: ignore
import numpy as np
import ipaddress
import math
import re
import urllib.parse
from collections import Counter, deque, defaultdict

from modules.constants import (
    Col,
    PORT_SCAN_COLUMNS,
    WEB_ATTACK_COLUMNS,
    THREAT_IP_COLUMNS,
    DNS_COLUMNS,
    DOS_BRUTEFORCE_COLUMNS,
    TLS_SNI_COLUMNS,
    EXTERNAL_CONNECTION_COLUMNS
)
from modules.rules_config import (
    PORT_SERVICE_MAP,
    WEB_ATTACK_PATTERNS,
    SCANNER_UA_PATTERN,
    SUSPICIOUS_TLDS,
    KNOWN_DNS_PROBES,
    PUBLIC_DNS_RESOLVERS,
    DEFAULT_PORT_SCAN_THRESHOLD,
    DEFAULT_DOS_PPS_THRESHOLD,
    DEFAULT_FLOOD_PPS_THRESHOLD,
    DEFAULT_DNS_ENTROPY_THRESHOLD,
    DEFAULT_DNS_LENGTH_THRESHOLD,
    DEFAULT_UNUSUAL_PORTS,
    DEFAULT_EXTERNAL_CONNECTION_THRESHOLD,
    DEFAULT_MULTI_PORT_THRESHOLD,
    DEFAULT_ALLOWLIST
)

_EXT_IP_CACHE = {}

def is_external_ip(ip_str):
    """
    Kiểm tra xem một địa chỉ IP có phải là IP public/toàn cầu (External IP) hay không.
    Sử dụng thư viện chuẩn ipaddress kết hợp bộ đệm nhớ O(1) và kiểm tra nhanh IPv4.
    Loại trừ tuyệt đối:
    - Private IPv4/IPv6
    - Loopback
    - Link-local
    - Multicast
    - Unspecified
    - Reserved
    - Broadcast hoặc địa chỉ không hợp lệ
    """
    if not ip_str or not isinstance(ip_str, (str, bytes)):
        return False
    s = str(ip_str).strip()
    if not s or s.lower() in ('unknown', 'nan', 'none', '-', 'null'):
        return False

    cached = _EXT_IP_CACHE.get(s)
    if cached is not None:
        return cached

    # Đường dẫn kiểm tra nhanh cho IPv4 thông dụng
    parts = s.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        first = int(parts[0])
        second = int(parts[1])
        if (first == 10 or first == 127 or first == 0 or
            (first == 172 and 16 <= second <= 31) or
            (first == 192 and second == 168) or
            (first == 169 and second == 254) or
            first >= 224):
            _EXT_IP_CACHE[s] = False
            return False

    try:
        ip = ipaddress.ip_address(s)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or 
            ip.is_multicast or ip.is_unspecified or ip.is_reserved):
            _EXT_IP_CACHE[s] = False
            return False
        if isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address('255.255.255.255'):
            _EXT_IP_CACHE[s] = False
            return False
        res = bool(ip.is_global)
        _EXT_IP_CACHE[s] = res
        return res
    except ValueError:
        _EXT_IP_CACHE[s] = False
        return False

def is_public_ip(ip_str):
    """
    Kiểm tra xem một địa chỉ IP có phải là IP public hay không (tương thích ngược).
    """
    return is_external_ip(ip_str)

def parse_ip_or_network_list(items):
    """
    Phân tích chuỗi hoặc danh sách các địa chỉ IP / dải CIDR (IPv4 và IPv6).
    Cho phép nhập dấu phẩy hoặc xuống dòng. Báo lỗi mục không hợp lệ mà không crash ứng dụng.
    Trả về tuple: (networks_list, errors_list)
    """
    networks = []
    errors = []
    if items is None:
        return networks, errors
        
    if isinstance(items, str):
        raw_items = [x.strip() for x in items.replace(',', '\n').split('\n') if x.strip()]
    elif isinstance(items, (list, set, tuple)):
        raw_items = []
        for it in items:
            if isinstance(it, str):
                for part in it.replace(',', '\n').split('\n'):
                    part = part.strip()
                    if part:
                        raw_items.append(part)
            else:
                raw_items.append(str(it).strip())
    else:
        return networks, errors

    for raw in raw_items:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            networks.append(net)
        except (ValueError, TypeError) as e:
            errors.append((raw, str(e)))
            
    return networks, errors

def ip_matches_network_list(ip_obj, network_list):
    """
    Kiểm tra xem đối tượng IP (IPv4Address, IPv6Address hoặc str) có thuộc bất kỳ subnet nào trong network_list không.
    """
    if not ip_obj or not network_list:
        return False
    if isinstance(ip_obj, str):
        try:
            ip_obj = ipaddress.ip_address(ip_obj.strip())
        except ValueError:
            return False
    for net in network_list:
        try:
            if ip_obj in net:
                return True
        except TypeError:
            continue
    return False

def calculate_entropy(text):
    """
    Tính toán Shannon Entropy của chuỗi văn bản (ví dụ: subdomain, domain).
    """
    if not text or not isinstance(text, str):
        return 0.0
    text = text.strip().lower()
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def normalize_payload(text):
    """
    Chuẩn hóa và giải mã payload (chống URL Encoding / Double Encoding bypass).
    """
    if not text or not isinstance(text, str):
        return ""
    try:
        # Giải mã 2 lần để xử lý Double URL Encoding (%252e%252e -> %2e%2e -> ..)
        decoded = urllib.parse.unquote(urllib.parse.unquote(text))
        return decoded
    except Exception:
        return text

def _parse_time_window_seconds(window_val, default=60.0):
    """Chuyển đổi chuỗi window (vd: '60s', '1m') sang số giây float."""
    if window_val is None:
        return default
    if isinstance(window_val, (int, float)):
        return max(1.0, float(window_val))
    if isinstance(window_val, str):
        w = window_val.strip().lower()
        if w.endswith('s'):
            try:
                return max(1.0, float(w[:-1]))
            except ValueError:
                pass
        elif w.endswith('m'):
            try:
                return max(1.0, float(w[:-1]) * 60.0)
            except ValueError:
                pass
        elif w.endswith('h'):
            try:
                return max(1.0, float(w[:-1]) * 3600.0)
            except ValueError:
                pass
        try:
            return max(1.0, float(w))
        except ValueError:
            pass
    return default

def detect_port_scan(df, server_ip=None, time_window='60s', port_threshold=DEFAULT_PORT_SCAN_THRESHOLD):
    """
    Phát hiện hành vi Port Scan (Hỗ trợ cả TCP SYN Scan, Stealth Scan và UDP Port Scan).
    Chỉ xét lưu lượng gửi đến server_ip khi được chỉ định.
    Dùng cửa sổ thời gian trượt để phát hiện các đợt quét cổng tập trung.
    """
    if df.empty or Col.SOURCE_IP not in df.columns or Col.PROTOCOL not in df.columns or Col.DEST_PORT not in df.columns:
        return pd.DataFrame(columns=PORT_SCAN_COLUMNS)
        
    server_ip_str = str(server_ip).strip() if server_ip else None
    window_sec = _parse_time_window_seconds(time_window, default=60.0)
    
    # Lọc các gói tin hợp lệ và giới hạn phạm vi máy chủ mục tiêu
    base_mask = df[Col.DEST_PORT].notna()
    if server_ip_str:
        if Col.DEST_IP in df.columns:
            base_mask = base_mask & (df[Col.DEST_IP].astype(str) == server_ip_str)
        if Col.SOURCE_IP in df.columns:
            base_mask = base_mask & (df[Col.SOURCE_IP].astype(str) != server_ip_str)
        
    # TCP Filter: SYN-only hoặc Stealth Flags
    tcp_mask = (df[Col.PROTOCOL] == 'TCP') & base_mask
    if Col.TCP_FLAGS in df.columns:
        syn_mask = df[Col.TCP_FLAGS].str.contains('SYN', na=False) & (~df[Col.TCP_FLAGS].str.contains('ACK', na=False))
        fin_mask = (df[Col.TCP_FLAGS] == 'FIN')
        null_mask = (df[Col.TCP_FLAGS] == '')
        xmas_mask = df[Col.TCP_FLAGS].str.contains('FIN', na=False) & df[Col.TCP_FLAGS].str.contains('URG', na=False) & df[Col.TCP_FLAGS].str.contains('PSH', na=False)
        tcp_mask = tcp_mask & (syn_mask | fin_mask | null_mask | xmas_mask)
        
    # UDP Filter: UDP packets to various destination ports
    udp_mask = (df[Col.PROTOCOL] == 'UDP') & base_mask
    
    scan_packets = df[tcp_mask | udp_mask].copy()
    if scan_packets.empty:
        return pd.DataFrame(columns=PORT_SCAN_COLUMNS)
        
    scan_packets[Col.SOURCE_IP] = scan_packets[Col.SOURCE_IP].astype(str)
    scan_packets[Col.DEST_PORT] = pd.to_numeric(scan_packets[Col.DEST_PORT], errors='coerce').fillna(0).astype(int)

    # 2. Sàng lọc sơ bộ (Pre-filter): Phải đạt tối thiểu port_threshold cổng trên toàn bộ file
    port_counts = scan_packets.groupby(Col.SOURCE_IP, observed=True)[Col.DEST_PORT].nunique()
    candidate_ips = set(port_counts[port_counts >= port_threshold].index)
    if not candidate_ips:
        return pd.DataFrame(columns=PORT_SCAN_COLUMNS)
        
    filtered_packets = scan_packets[scan_packets[Col.SOURCE_IP].isin(candidate_ips)].copy()
    
    # Kiểm tra timestamp
    has_timestamps = (Col.TIMESTAMP in filtered_packets.columns) and not filtered_packets[Col.TIMESTAMP].isna().all()
    if has_timestamps:
        filtered_packets['__ts'] = pd.to_datetime(filtered_packets[Col.TIMESTAMP], errors='coerce')
        has_valid_dt = not filtered_packets['__ts'].isna().all()
    else:
        has_valid_dt = False

    detected_records = []
    group_cols = [Col.SOURCE_IP]
    if Col.DEST_IP in filtered_packets.columns:
        group_cols.append(Col.DEST_IP)

    # 3. Quét sliding window theo từng mục tiêu
    for group_key, ip_df in filtered_packets.groupby(group_cols, observed=True):
        if isinstance(group_key, tuple):
            src_ip = str(group_key[0]).strip()
            dst_ip = str(group_key[1]).strip() if len(group_key) > 1 else (server_ip_str or '')
        else:
            src_ip = str(group_key).strip()
            dst_ip = server_ip_str or ''
        
        if not has_valid_dt or ip_df['__ts'].isna().all():
            # Fallback khi dữ liệu hoàn toàn không có timestamp
            unique_ports = ip_df[Col.DEST_PORT].unique()
            if len(unique_ports) >= port_threshold:
                protos = ip_df[Col.PROTOCOL].unique()
                scan_type = 'Hybrid TCP/UDP Scan' if ('TCP' in protos and 'UDP' in protos) else ('UDP Port Scan' if 'UDP' in protos else 'TCP SYN Scan')
                top_ports = ', '.join(str(p) for p in ip_df[Col.DEST_PORT].value_counts().head(50).index)
                first_seen = ip_df[Col.TIMESTAMP].min() if Col.TIMESTAMP in ip_df.columns else None
                last_seen = ip_df[Col.TIMESTAMP].max() if Col.TIMESTAMP in ip_df.columns else None
                detected_records.append({
                    Col.SOURCE_IP: src_ip,
                    Col.DEST_IP: dst_ip,
                    Col.SCANNED_PORTS_COUNT: len(unique_ports),
                    Col.TOTAL_PACKETS: len(ip_df),
                    Col.TARGETED_PORTS: top_ports,
                    Col.SCAN_TYPE: scan_type,
                    Col.FIRST_SEEN: first_seen,
                    Col.LAST_SEEN: last_seen
                })
            continue

        # Two-pointer sliding window với sessionization
        sorted_df = ip_df.dropna(subset=['__ts']).sort_values('__ts')
        ts_values = sorted_df['__ts'].values.astype('datetime64[ns]').astype('int64') / 1e9
        ports = sorted_df[Col.DEST_PORT].values
        n = len(ports)
        if n == 0:
            continue

        cooldown_sec = max(window_sec * 2, 120.0)
        port_counts_in_win = Counter()
        left = 0
        sessions = []
        current_session = set()
        current_session_last_ts = -1.0

        for right in range(n):
            port_counts_in_win[ports[right]] += 1
            while ts_values[right] - ts_values[left] > window_sec:
                port_counts_in_win[ports[left]] -= 1
                if port_counts_in_win[ports[left]] <= 0:
                    del port_counts_in_win[ports[left]]
                left += 1

            curr_unique = len(port_counts_in_win)
            if curr_unique >= port_threshold:
                win_indices = set(range(left, right + 1))
                win_first_ts = ts_values[left]
                win_last_ts = ts_values[right]

                if not current_session:
                    current_session = win_indices
                    current_session_last_ts = win_last_ts
                else:
                    if win_first_ts - current_session_last_ts <= cooldown_sec:
                        current_session.update(win_indices)
                        current_session_last_ts = max(current_session_last_ts, win_last_ts)
                    else:
                        sessions.append(sorted(current_session))
                        current_session = win_indices
                        current_session_last_ts = win_last_ts

        if current_session:
            sessions.append(sorted(current_session))

        for idx_list in sessions:
            first_seen = sorted_df.iloc[idx_list[0]]['__ts']
            last_seen = sorted_df.iloc[idx_list[-1]]['__ts']
            event_packet_count = len(idx_list)
            protos = sorted_df.iloc[idx_list][Col.PROTOCOL].unique()
            scan_type = 'Hybrid TCP/UDP Scan' if ('TCP' in protos and 'UDP' in protos) else ('UDP Port Scan' if 'UDP' in protos else 'TCP SYN Scan')
            
            ports_series = sorted_df.iloc[idx_list][Col.DEST_PORT]
            unique_scanned_count = len(ports_series.unique())
            top_ports = ', '.join(str(p) for p in ports_series.value_counts().head(50).index)
            if not top_ports:
                top_ports = ', '.join(str(p) for p in sorted_df[Col.DEST_PORT].value_counts().head(50).index)

            detected_records.append({
                Col.SOURCE_IP: src_ip,
                Col.DEST_IP: dst_ip,
                Col.SCANNED_PORTS_COUNT: unique_scanned_count,
                Col.TOTAL_PACKETS: event_packet_count,
                Col.TARGETED_PORTS: top_ports,
                Col.SCAN_TYPE: scan_type,
                Col.FIRST_SEEN: first_seen,
                Col.LAST_SEEN: last_seen
            })

    if not detected_records:
        return pd.DataFrame(columns=PORT_SCAN_COLUMNS)

    res_df = pd.DataFrame(detected_records)
    res_df = res_df.sort_values(by=[Col.SCANNED_PORTS_COUNT, Col.TOTAL_PACKETS], ascending=[False, False]).reset_index(drop=True)
    for col in PORT_SCAN_COLUMNS:
        if col not in res_df.columns:
            res_df[col] = None
    return res_df[PORT_SCAN_COLUMNS]



def _calculate_traffic_burst(sorted_df, window_seconds=60.0, flood_threshold=40, min_pps_threshold=3.0, 
                             single_port_syn_threshold=15, is_auth_port=False, high_peak_threshold=DEFAULT_DOS_PPS_THRESHOLD):
    """
    Phân tích lưu lượng theo cửa sổ trượt:
    - Đảm bảo số gói, tốc độ đỉnh (Peak PPS), tỷ lệ trung bình, first/last seen đều thuộc cùng một cửa sổ quan sát.
    - Áp dụng ngưỡng peak riêng cho TCP (25 pps) và ICMP/UDP (50 pps).
    - Dùng monotonic deque để tìm giá trị cực đại trong O(n).
    """
    n = len(sorted_df)
    if n == 0:
        return None

    if '__ts_sec' in sorted_df.columns:
        ts_vals = sorted_df['__ts_sec'].values
    else:
        ts_parsed = pd.to_datetime(sorted_df[Col.TIMESTAMP], errors='coerce')
        valid_m = ts_parsed.notna()
        if not valid_m.any():
            return None
        sorted_df = sorted_df[valid_m]
        ts_vals = ts_parsed[valid_m].values.astype('datetime64[ns]').astype('int64') / 1e9
        n = len(ts_vals)

    if n == 0:
        return None

    # 1. Precompute mảng 1-second PPS cho từng gói tin (O(n))
    pps_1s = np.zeros(n, dtype=float)
    left_1s = 0
    for i in range(n):
        while ts_vals[i] - ts_vals[left_1s] > 1.0:
            left_1s += 1
        cnt_1s = i - left_1s + 1
        dt_1s = ts_vals[i] - ts_vals[left_1s]
        pps_1s[i] = 1.0 if cnt_1s == 1 else (cnt_1s / max(dt_1s, 0.1) if dt_1s < 1.0 else cnt_1s / dt_1s)

    # 2. Monotonic deque duy trì maximum pps_1s trong sliding window [left_win, right] (O(n) toàn bộ)
    best_candidate = None
    left_win = 0
    max_deque = deque()

    for right in range(n):
        # Đẩy right vào monotonic deque
        while max_deque and pps_1s[max_deque[-1]] <= pps_1s[right]:
            max_deque.pop()
        max_deque.append(right)

        # Trượt left_win đảm bảo khoảng cách <= window_seconds
        while ts_vals[right] - ts_vals[left_win] > window_seconds:
            left_win += 1

        # Loại bỏ các index đã trượt ra ngoài cửa sổ [left_win, right]
        while max_deque and max_deque[0] < left_win:
            max_deque.popleft()

        win_count = right - left_win + 1
        win_dt = max(ts_vals[right] - ts_vals[left_win], 0.1)
        win_peak = float(pps_1s[max_deque[0]])

        is_win_flood = (win_count >= flood_threshold and win_peak >= min_pps_threshold) or (win_peak >= high_peak_threshold and win_count >= single_port_syn_threshold)
        is_win_auth = is_auth_port and (win_count >= single_port_syn_threshold) and not (win_dt > 1800 and win_peak < 0.1)

        if is_win_flood or is_win_auth:
            cand_score = (2 if is_win_flood else 1, win_peak, win_count)
            if best_candidate is None or cand_score > best_candidate['score']:
                best_candidate = {
                    'score': cand_score,
                    'is_flood': is_win_flood,
                    'left': left_win,
                    'right': right,
                    'count': win_count,
                    'peak': win_peak,
                    'dt': win_dt
                }

    if not best_candidate:
        return None

    b_l = best_candidate['left']
    b_r = best_candidate['right']
    dur_s = round(best_candidate['dt'], 2)
    pkt_cnt = best_candidate['count']
    return {
        'is_flood': best_candidate['is_flood'],
        'packet_count': pkt_cnt,
        'duration_s': dur_s,
        'avg_rate': round(pkt_cnt / max(dur_s, 0.1), 2),
        'peak_pps': round(best_candidate['peak'], 2),
        'first_seen': sorted_df.iloc[b_l][Col.TIMESTAMP],
        'last_seen': sorted_df.iloc[b_r][Col.TIMESTAMP]
    }


def detect_dos_bruteforce(df, server_ip=None, single_port_syn_threshold=15, flood_threshold=40, min_pps_threshold=3.0):
    """
    Phát hiện DoS/DDoS và Brute-force dựa trên Rolling Window Peak PPS và Ngưỡng Lưu Lượng.
    - Dùng cùng một evidence window nhất quán cho mọi thuộc tính (Count, Peak PPS, Rate, First/Last Seen).
    - Tiền lọc cardinality nhóm, tối ưu hóa tốc độ xử lý xuống dưới 5 giây trên 400.000+ packet.
    """
    if df.empty or Col.SOURCE_IP not in df.columns:
        return pd.DataFrame(columns=DOS_BRUTEFORCE_COLUMNS)
        
    records = []
    server_ip_str = str(server_ip).strip() if server_ip else None
    
    # Lọc lưu lượng Inbound gửi đến máy chủ đích
    if server_ip_str:
        if Col.DEST_IP in df.columns:
            work_df = df[(df[Col.DEST_IP].astype(str) == server_ip_str) & (df[Col.SOURCE_IP].astype(str) != server_ip_str)]
        else:
            work_df = df[df[Col.SOURCE_IP].astype(str) != server_ip_str]
    else:
        work_df = df
        
    if work_df.empty:
        return pd.DataFrame(columns=DOS_BRUTEFORCE_COLUMNS)

    # Chuẩn hóa timestamp một lần duy nhất cho toàn bộ work_df
    if Col.TIMESTAMP in work_df.columns:
        ts_parsed = pd.to_datetime(work_df[Col.TIMESTAMP], errors='coerce')
        valid_mask = ts_parsed.notna()
        if not valid_mask.any():
            return pd.DataFrame(columns=DOS_BRUTEFORCE_COLUMNS)
        work_df = work_df[valid_mask].copy()
        work_df['__ts_sec'] = ts_parsed[valid_mask].values.astype('datetime64[ns]').astype('int64') / 1e9
    else:
        work_df = work_df.copy()
        work_df['__ts_sec'] = 0.0
        
    auth_sensitive_ports = {22, 21, 23, 3389, 445, 139, 3306, 5432, 1433, 1521, 6379, 27017}
    web_ports = {80, 443, 8080, 8443, 8000, 8888}

    # --- 1. PHÁT HIỆN FLOOD VÀ KẾT NỐI LẶP LẠI TRÊN TCP SYN ---
    if Col.PROTOCOL in work_df.columns and Col.DEST_PORT in work_df.columns:
        tcp_df = work_df[work_df[Col.PROTOCOL] == 'TCP']
        if not tcp_df.empty:
            if Col.TCP_FLAGS in tcp_df.columns:
                syn_df = tcp_df[tcp_df[Col.TCP_FLAGS].str.contains('SYN', na=False) & (~tcp_df[Col.TCP_FLAGS].str.contains('ACK', na=False))]
            else:
                syn_df = tcp_df
                
            if not syn_df.empty:
                # Tiền lọc nhóm theo cardinality tối thiểu (nhóm < 15 gói chắc chắn không đạt)
                min_tcp_thresh = min(single_port_syn_threshold, flood_threshold)
                group_sizes = syn_df.groupby([Col.SOURCE_IP, Col.DEST_PORT], observed=True).size()
                qualifying_keys = set(group_sizes[group_sizes >= min_tcp_thresh].index)
                
                if qualifying_keys:
                    syn_df = syn_df.copy()
                    syn_df['_grp_k'] = list(zip(syn_df[Col.SOURCE_IP], syn_df[Col.DEST_PORT]))
                    syn_candidates = syn_df[syn_df['_grp_k'].isin(qualifying_keys)].sort_values('__ts_sec')

                    for (src_ip, port), group_df in syn_candidates.groupby([Col.SOURCE_IP, Col.DEST_PORT], observed=True):
                        port_int = int(port)
                        service_name = PORT_SERVICE_MAP.get(port_int, f'Port {port_int}')
                        is_auth = port_int in auth_sensitive_ports
                        burst_res = _calculate_traffic_burst(
                            group_df, window_seconds=60.0,
                            flood_threshold=flood_threshold, min_pps_threshold=min_pps_threshold,
                            single_port_syn_threshold=single_port_syn_threshold, is_auth_port=is_auth
                        )

                        if not burst_res:
                            continue

                        if burst_res['is_flood']:
                            atk_type = "HTTP/SYN Flood" if port_int in web_ports else f"TCP SYN Flood ({service_name.split(' ')[0]})"
                            risk = "Cao"
                        else:
                            atk_type = f"Repeated Connection Attempts ({service_name.split(' ')[0]})"
                            risk = "Cao" if burst_res['packet_count'] >= 30 else "Trung bình"

                        records.append({
                            Col.SOURCE_IP: str(src_ip).strip(),
                            Col.TARGET_PORT: port_int,
                            Col.TARGET_SERVICE: service_name,
                            Col.ATTACK_TYPE: atk_type,
                            Col.PACKET_COUNT: burst_res['packet_count'],
                            Col.DURATION_S: burst_res['duration_s'],
                            Col.AVG_RATE: burst_res['avg_rate'],
                            Col.PEAK_PPS: burst_res['peak_pps'],
                            Col.RISK_LEVEL: risk,
                            Col.FIRST_SEEN: burst_res['first_seen'],
                            Col.LAST_SEEN: burst_res['last_seen']
                        })
                        
    # --- 2. PHÁT HIỆN ICMP PING FLOOD & UDP VOLUMETRIC FLOOD ---
    if Col.PROTOCOL in work_df.columns:
        icmp_udp_df = work_df[work_df[Col.PROTOCOL].isin(['ICMP', 'UDP'])]
        if not icmp_udp_df.empty:
            # Tiền lọc nhóm ICMP / UDP
            group_sizes_other = icmp_udp_df.groupby([Col.SOURCE_IP, Col.PROTOCOL], observed=True).size()
            qualifying_other = set(
                group_sizes_other[
                    ((group_sizes_other.index.get_level_values(Col.PROTOCOL) == 'ICMP') & (group_sizes_other >= 10)) |
                    ((group_sizes_other.index.get_level_values(Col.PROTOCOL) == 'UDP') & (group_sizes_other >= 20))
                ].index
            )

            if qualifying_other:
                icmp_udp_df = icmp_udp_df.copy()
                icmp_udp_df['_grp_k'] = list(zip(icmp_udp_df[Col.SOURCE_IP], icmp_udp_df[Col.PROTOCOL]))
                candidates_other = icmp_udp_df[icmp_udp_df['_grp_k'].isin(qualifying_other)].sort_values('__ts_sec')

                for (src_ip, proto), group_df in candidates_other.groupby([Col.SOURCE_IP, Col.PROTOCOL], observed=True):
                    f_thresh = flood_threshold if proto == 'ICMP' else flood_threshold * 2
                    p_thresh = DEFAULT_FLOOD_PPS_THRESHOLD
                    min_pps = min_pps_threshold

                    burst_res = _calculate_traffic_burst(
                        group_df, window_seconds=60.0,
                        flood_threshold=f_thresh, min_pps_threshold=min_pps,
                        single_port_syn_threshold=10 if proto == 'ICMP' else 20, is_auth_port=False,
                        high_peak_threshold=p_thresh
                    )

                    if not burst_res or not burst_res['is_flood']:
                        continue

                    records.append({
                        Col.SOURCE_IP: str(src_ip).strip(),
                        Col.TARGET_PORT: 0,
                        Col.TARGET_SERVICE: str(proto),
                        Col.ATTACK_TYPE: f"{proto} Flood",
                        Col.PACKET_COUNT: burst_res['packet_count'],
                        Col.DURATION_S: burst_res['duration_s'],
                        Col.AVG_RATE: burst_res['avg_rate'],
                        Col.PEAK_PPS: burst_res['peak_pps'],
                        Col.RISK_LEVEL: 'Cao',
                        Col.FIRST_SEEN: burst_res['first_seen'],
                        Col.LAST_SEEN: burst_res['last_seen']
                    })
                        
    if not records:
        return pd.DataFrame(columns=DOS_BRUTEFORCE_COLUMNS)
        
    res_df = pd.DataFrame(records)
    res_df = res_df.sort_values(by=[Col.PEAK_PPS, Col.PACKET_COUNT], ascending=[False, False]).reset_index(drop=True)
    
    for col in DOS_BRUTEFORCE_COLUMNS:
        if col not in res_df.columns:
            res_df[col] = None
    return res_df[DOS_BRUTEFORCE_COLUMNS]


def detect_suspicious_tls_sni(df, server_ip=None):
    """
    Phân tích và phát hiện các tên miền TLS SNI (HTTPS) khả nghi, C2 Domains, Phishing & High Entropy.
    Chỉ kiểm tra lưu lượng liên quan đến máy chủ nếu có cấu hình server_ip.
    Đánh dấu kết quả heuristic ở mức nghi ngờ thay vì khẳng định độc hại.
    """
    if df.empty or Col.TLS_SNI not in df.columns:
        return pd.DataFrame(columns=TLS_SNI_COLUMNS)
        
    mask = df[Col.TLS_SNI].notna() & (df[Col.TLS_SNI] != '')
    server_ip_str = str(server_ip).strip() if server_ip else None
    if server_ip_str:
        if Col.DEST_IP in df.columns and Col.SOURCE_IP in df.columns:
            mask = mask & ((df[Col.DEST_IP].astype(str) == server_ip_str) | (df[Col.SOURCE_IP].astype(str) == server_ip_str))
        elif Col.SOURCE_IP in df.columns:
            mask = mask & (df[Col.SOURCE_IP].astype(str) != server_ip_str)
        
    tls_df = df[mask].copy()
    if tls_df.empty:
        return pd.DataFrame(columns=TLS_SNI_COLUMNS)
        
    cols_to_pick = [c for c in [Col.TIMESTAMP, Col.SOURCE_IP, Col.DEST_IP, Col.TLS_SNI] if c in tls_df.columns]
    res_df = tls_df[cols_to_pick].copy()
    res_df['_sni_lower'] = res_df[Col.TLS_SNI].astype(str).str.strip().str.lower()
    res_df[Col.ENTROPY] = res_df['_sni_lower'].apply(calculate_entropy).round(2)
    
    # Phân loại Vectorized / Strict
    def _is_direct_ip(sni_val):
        if not sni_val or not isinstance(sni_val, str):
            return False
        try:
            ipaddress.ip_address(sni_val.strip())
            return True
        except ValueError:
            return False

    is_ip = res_df['_sni_lower'].apply(_is_direct_ip)
    is_dga = (res_df[Col.ENTROPY] >= DEFAULT_DNS_ENTROPY_THRESHOLD) & (res_df['_sni_lower'].str.len() >= 20)
    tld_pattern = '|'.join(re.escape(t) for t in SUSPICIOUS_TLDS)
    is_sus_tld = res_df['_sni_lower'].str.contains(rf'(?:{tld_pattern})$', regex=True)
    
    res_df[Col.CLASSIFICATION] = 'Legitimate HTTPS'
    res_df.loc[is_sus_tld, Col.CLASSIFICATION] = 'Suspicious Dynamic DNS'
    res_df.loc[is_dga, Col.CLASSIFICATION] = 'High Entropy DGA'
    res_df.loc[is_ip, Col.CLASSIFICATION] = 'Suspicious C2 (Direct IP)'
    
    res_df = res_df.drop(columns=['_sni_lower'])
    if Col.TIMESTAMP in res_df.columns:
        res_df = res_df.sort_values(by=Col.TIMESTAMP)
    res_df = res_df.reset_index(drop=True)
    
    for col in TLS_SNI_COLUMNS:
        if col not in res_df.columns:
            res_df[col] = None
    return res_df[TLS_SNI_COLUMNS]

def detect_abnormal_dns(df, server_ip=None, entropy_threshold=DEFAULT_DNS_ENTROPY_THRESHOLD, length_threshold=DEFAULT_DNS_LENGTH_THRESHOLD):
    """
    Phân loại Inbound DNS Probes vs Outbound DNS Tunneling.
    Truy vấn outbound thông thường của máy nội bộ tới DNS server bên ngoài không tính là probe.
    """
    empty_res = {
        'inbound_probes': pd.DataFrame(columns=DNS_COLUMNS),
        'inbound_queries': pd.DataFrame(columns=DNS_COLUMNS),
        'outbound_tunneling': pd.DataFrame(columns=DNS_COLUMNS),
        'all_queries': pd.DataFrame(columns=DNS_COLUMNS),
        'summary': {
            'inbound_probe_count': 0,
            'inbound_query_count': 0,
            'inbound_count': 0,
            'outbound_count': 0,
            'suspicious_tunneling_count': 0
        }
    }
    
    if df.empty or Col.INFO not in df.columns:
        return empty_res
        
    mask = df[Col.INFO].str.startswith('DNS Query:', na=False)
    dns_df = df[mask].copy()
    if dns_df.empty:
        return empty_res
        
    dns_df[Col.DOMAIN] = dns_df[Col.INFO].str.replace('DNS Query: ', '', regex=False).str.strip()
    dns_df[Col.DOMAIN_LENGTH] = dns_df[Col.DOMAIN].str.len()
    dns_df[Col.ENTROPY] = dns_df[Col.DOMAIN].apply(calculate_entropy)
    
    server_ip_str = str(server_ip).strip() if server_ip else None
    src_str = dns_df[Col.SOURCE_IP].astype(str) if Col.SOURCE_IP in dns_df.columns else pd.Series('', index=dns_df.index)
    dst_str = dns_df[Col.DEST_IP].astype(str) if Col.DEST_IP in dns_df.columns else pd.Series('', index=dns_df.index)
    dport = pd.to_numeric(dns_df[Col.DEST_PORT], errors='coerce').fillna(0).astype(int) if Col.DEST_PORT in dns_df.columns else pd.Series(0, index=dns_df.index)
    sport = pd.to_numeric(dns_df[Col.SOURCE_PORT], errors='coerce').fillna(0).astype(int) if Col.SOURCE_PORT in dns_df.columns else pd.Series(0, index=dns_df.index)
    
    if server_ip_str:
        # Inbound CHỈ KHI đích là server_ip và cổng đích là 53 (máy chủ là DNS server)
        is_inbound = (dst_str == server_ip_str) & (dport == 53)
        # Outbound: server_ip gửi truy vấn ra ngoài
        is_outbound = (src_str == server_ip_str)
        
        dns_df[Col.DIRECTION] = 'Transit'
        dns_df.loc[is_outbound, Col.DIRECTION] = 'Outbound'
        dns_df.loc[is_inbound, Col.DIRECTION] = 'Inbound'
    else:
        # Không có server_ip: Client gửi tới port 53 là Outbound query
        dns_df[Col.DIRECTION] = 'Outbound'
        dns_df.loc[sport == 53, Col.DIRECTION] = 'Response'
        
    dns_df['_domain_lower'] = dns_df[Col.DOMAIN].astype(str).str.lower()
    probe_pattern = '|'.join(re.escape(kp) for kp in KNOWN_DNS_PROBES)
    is_probe_match = dns_df['_domain_lower'].str.contains(rf'(?:{probe_pattern})', regex=True)
    
    is_inbound_flow = dns_df[Col.DIRECTION] == 'Inbound'
    is_long_or_high_entropy = (dns_df[Col.DOMAIN_LENGTH] >= length_threshold) | (dns_df[Col.ENTROPY] >= entropy_threshold)
    
    # Phân loại chuẩn xác:
    # 1. Mặc định là Legitimate Outbound DNS (truy vấn ra resolver)
    dns_df[Col.CLASSIFICATION] = 'Legitimate Outbound DNS'
    
    # 2. DNS Probe: CHỈ khi là luồng Inbound vào máy chủ giám sát VÀ khớp mẫu probe
    dns_df.loc[is_inbound_flow & is_probe_match, Col.CLASSIFICATION] = 'DNS Probe (Internet Noise)'
    dns_df.loc[is_inbound_flow & ~is_probe_match, Col.CLASSIFICATION] = 'Inbound DNS Query'
    
    # 3. DNS Tunneling: Outbound hoặc Transit có tên miền quá dài hoặc entropy cao
    dns_df.loc[~is_inbound_flow & is_long_or_high_entropy, Col.CLASSIFICATION] = 'Suspicious DNS Tunneling'
    
    dns_df = dns_df.drop(columns=['_domain_lower'])
    
    for col in DNS_COLUMNS:
        if col not in dns_df.columns:
            dns_df[col] = None
    dns_df = dns_df[DNS_COLUMNS]
    
    inbound_probes = dns_df[dns_df[Col.CLASSIFICATION] == 'DNS Probe (Internet Noise)'].copy()
    inbound_queries = dns_df[dns_df[Col.CLASSIFICATION] == 'Inbound DNS Query'].copy()
    outbound_tunneling = dns_df[dns_df[Col.CLASSIFICATION] == 'Suspicious DNS Tunneling'].copy()
    
    return {
        'inbound_probes': inbound_probes,
        'inbound_queries': inbound_queries,
        'outbound_tunneling': outbound_tunneling,
        'all_queries': dns_df,
        'summary': {
            'inbound_probe_count': len(inbound_probes),
            'inbound_query_count': len(inbound_queries),
            'inbound_count': len(inbound_probes),
            'outbound_count': len(dns_df[dns_df[Col.DIRECTION] == 'Outbound']),
            'suspicious_tunneling_count': len(outbound_tunneling)
        }
    }


def detect_web_attacks(df, server_ip=None):
    """
    Tự động phát hiện các mẫu tấn công Web, khai thác lỗ hổng (Exploit Attempts), mã độc và công cụ quét tự động.
    Tích hợp URL Normalizer chống kỹ thuật né tránh WAF (URL Encoding, Double Encoding).
    """
    if df.empty:
        return pd.DataFrame(columns=WEB_ATTACK_COLUMNS)
        
    server_ip_str = str(server_ip).strip() if server_ip else None
    
    if Col.HTTP_URI in df.columns:
        mask = df[Col.HTTP_URI].notna() & (df[Col.HTTP_URI] != '')
        if server_ip_str:
            if Col.DEST_IP in df.columns:
                mask = mask & (df[Col.DEST_IP].astype(str) == server_ip_str)
            if Col.SOURCE_IP in df.columns:
                mask = mask & (df[Col.SOURCE_IP].astype(str) != server_ip_str)
        http_df = df[mask].copy()
    elif Col.INFO in df.columns:
        mask = df[Col.INFO].str.startswith('HTTP ', na=False)
        if server_ip_str:
            if Col.DEST_IP in df.columns:
                mask = mask & (df[Col.DEST_IP].astype(str) == server_ip_str)
            if Col.SOURCE_IP in df.columns:
                mask = mask & (df[Col.SOURCE_IP].astype(str) != server_ip_str)
        http_df = df[mask].copy()
        if not http_df.empty:
            http_df[Col.HTTP_URI] = http_df[Col.INFO].apply(lambda x: x.split(' ')[2] if len(x.split(' ')) > 2 else '')
            http_df[Col.HTTP_METHOD] = http_df[Col.INFO].apply(lambda x: x.split(' ')[1] if len(x.split(' ')) > 1 else 'GET')
            http_df[Col.HTTP_UA] = ''
            http_df[Col.HTTP_BODY] = ''
    else:
        http_df = pd.DataFrame()
            
    if http_df.empty:
        return pd.DataFrame(columns=WEB_ATTACK_COLUMNS)
        
    # Chuẩn hóa URL & Ghép thêm HTTP Body để quét toàn diện
    uri_raw = http_df[Col.HTTP_URI].astype(str) if Col.HTTP_URI in http_df.columns else pd.Series('', index=http_df.index)
    body_raw = http_df[Col.HTTP_BODY].astype(str) if Col.HTTP_BODY in http_df.columns else pd.Series('', index=http_df.index)
    
    # Kết hợp URI và Body, áp dụng URL decode chống bypass
    combined_payload = (uri_raw + " " + body_raw).apply(normalize_payload)
    ua_series = http_df[Col.HTTP_UA].astype(str) if Col.HTTP_UA in http_df.columns else pd.Series([''] * len(http_df), index=http_df.index)
    
    # Tạo mask Vectorized cho mỗi pattern category
    category_masks = {}
    for cat_name, pat in WEB_ATTACK_PATTERNS.items():
        category_masks[cat_name] = combined_payload.str.contains(pat, regex=True, na=False)
    category_masks['Automated Vulnerability Scanner'] = ua_series.str.contains(SCANNER_UA_PATTERN, regex=True, na=False)
    
    # Lọc các dòng có ít nhất 1 match
    mask_df = pd.DataFrame(category_masks, index=http_df.index)
    any_match = mask_df.any(axis=1)
    matched_df = http_df[any_match].copy()
    
    if matched_df.empty:
        return pd.DataFrame(columns=WEB_ATTACK_COLUMNS)
    
    # Ghép tất cả category khớp được cho mỗi dòng
    def get_attack_category(idx):
        row_matches = mask_df.loc[idx]
        matched_cats = row_matches[row_matches].index.tolist()
        return ', '.join(matched_cats) if matched_cats else 'Suspicious Web Request'
        
    matched_df[Col.ATTACK_CATEGORY] = [get_attack_category(idx) for idx in matched_df.index]
    
    cols_to_pick = [c for c in [Col.TIMESTAMP, Col.SOURCE_IP, Col.DEST_IP, Col.HTTP_METHOD, Col.HTTP_URI, Col.ATTACK_CATEGORY, Col.HTTP_UA] if c in matched_df.columns]
    attacks_df = matched_df[cols_to_pick].copy()
    attacks_df = attacks_df.rename(columns={
        Col.HTTP_METHOD: 'Method',
        Col.HTTP_URI: 'URI',
        Col.HTTP_UA: 'User-Agent'
    })
    
    if Col.TIMESTAMP in attacks_df.columns and attacks_df[Col.TIMESTAMP].notna().any():
        attacks_df = attacks_df.sort_values(by=Col.TIMESTAMP)
    attacks_df = attacks_df.reset_index(drop=True)
    
    for col in WEB_ATTACK_COLUMNS:
        if col not in attacks_df.columns:
            attacks_df[col] = None
    return attacks_df[WEB_ATTACK_COLUMNS]

def detect_suspicious_ips(df, server_ip=None, port_scans_df=None, web_attacks_df=None, dns_results=None, dos_df=None, tls_df=None):
    """
    Tổng hợp hồ sơ IP đe dọa từ các vector tấn công đã phát hiện.
    Bỏ qua các IP có Hit Count bằng 0 và không gắn nhãn máy chủ đích thành nguồn tấn công.
    """
    threat_map = {}
    server_ip_str = str(server_ip).strip() if server_ip else None
    
    # 1. Tổng hợp từ Port Scan (tích lũy các phiên quét của cùng IP)
    if port_scans_df is not None and not port_scans_df.empty:
        for _, row in port_scans_df.iterrows():
            ip_s = str(row.get(Col.SOURCE_IP, '')).strip()
            if not ip_s or (server_ip_str and ip_s == server_ip_str):
                continue
            pkts_cnt = int(row.get(Col.TOTAL_PACKETS, 0)) if pd.notna(row.get(Col.TOTAL_PACKETS)) else 0
            if pkts_cnt <= 0:
                continue
            dst_target = str(row.get(Col.DEST_IP, '')).strip()
            ports_str = str(row.get(Col.TARGETED_PORTS, ''))
            cnt_ports = row.get(Col.SCANNED_PORTS_COUNT, '')
            target_desc = f"Target: {dst_target} (Ports: {ports_str})" if dst_target else f"Ports: {ports_str} ({cnt_ports} ports)"
            
            if ip_s not in threat_map:
                threat_map[ip_s] = {
                    'Categories': {'Port Scan'},
                    'Hits': pkts_cnt,
                    'Targeted': [target_desc]
                }
            else:
                threat_map[ip_s]['Categories'].add('Port Scan')
                threat_map[ip_s]['Hits'] += pkts_cnt
                if target_desc not in threat_map[ip_s]['Targeted']:
                    threat_map[ip_s]['Targeted'].append(target_desc)
                
    # 2. Tổng hợp từ Web Attacks
    if web_attacks_df is not None and not web_attacks_df.empty:
        web_counts = web_attacks_df[Col.SOURCE_IP].astype(str).value_counts()
        for ip, count in web_counts.items():
            if count <= 0:
                continue
            ip_s = str(ip).strip()
            if not ip_s or (server_ip_str and ip_s == server_ip_str):
                continue
            uri_col = 'URI' if 'URI' in web_attacks_df.columns else Col.HTTP_URI
            sample_uris = web_attacks_df[web_attacks_df[Col.SOURCE_IP].astype(str) == ip_s][uri_col].head(2).tolist()
            sample_str = f"URIs: {', '.join(str(u) for u in sample_uris)}"
            if ip_s not in threat_map:
                threat_map[ip_s] = {
                    'Categories': {'Web Attack'},
                    'Hits': int(count),
                    'Targeted': [sample_str]
                }
            else:
                threat_map[ip_s]['Categories'].add('Web Attack')
                threat_map[ip_s]['Hits'] += int(count)
                threat_map[ip_s]['Targeted'].append(sample_str)
                
    # 3. Tổng hợp từ DoS / DDoS & Brute-Force
    if dos_df is not None and not dos_df.empty:
        for ip, atk_type, pkts, target_port in zip(dos_df[Col.SOURCE_IP], dos_df[Col.ATTACK_TYPE], dos_df[Col.PACKET_COUNT], dos_df[Col.TARGET_PORT]):
            ip_s = str(ip).strip()
            if not ip_s or (server_ip_str and ip_s == server_ip_str):
                continue
            pkts_cnt = int(pkts)
            if pkts_cnt <= 0:
                continue
            target_str = f"{atk_type} (Port {target_port}: {pkts_cnt} pkts)"
            if ip_s not in threat_map:
                threat_map[ip_s] = {
                    'Categories': {atk_type},
                    'Hits': pkts_cnt,
                    'Targeted': [target_str]
                }
            else:
                threat_map[ip_s]['Categories'].add(atk_type)
                threat_map[ip_s]['Hits'] += pkts_cnt
                threat_map[ip_s]['Targeted'].append(target_str)
                
    # 4. Tổng hợp từ Inbound DNS Probes
    if dns_results and 'inbound_probes' in dns_results:
        inbound_dns = dns_results['inbound_probes']
        if not inbound_dns.empty:
            dns_counts = inbound_dns[Col.SOURCE_IP].astype(str).value_counts()
            for ip, count in dns_counts.items():
                if count <= 0:
                    continue
                ip_s = str(ip).strip()
                if not ip_s or (server_ip_str and ip_s == server_ip_str):
                    continue
                if ip_s not in threat_map:
                    threat_map[ip_s] = {
                        'Categories': {'DNS Resolver Scan'},
                        'Hits': int(count),
                        'Targeted': ["DNS: Port 53 (Open Resolver Probe)"]
                    }
                else:
                    threat_map[ip_s]['Categories'].add('DNS Resolver Scan')
                    threat_map[ip_s]['Hits'] += int(count)
                    
    # 5. Tổng hợp từ Outbound DNS Tunneling (quy cho máy nội bộ phát sinh, không gán Resolver là C2)
    if dns_results and 'outbound_tunneling' in dns_results:
        outbound_dns = dns_results['outbound_tunneling']
        if not outbound_dns.empty:
            for src_ip, group in outbound_dns.groupby(Col.SOURCE_IP, observed=True):
                count = len(group)
                if count <= 0:
                    continue
                ip_s = str(src_ip).strip()
                if not ip_s or (server_ip_str and ip_s == server_ip_str):
                    continue
                if ip_s in PUBLIC_DNS_RESOLVERS:
                    continue
                    
                sample_domains = group[Col.DOMAIN].head(2).tolist() if Col.DOMAIN in group.columns else []
                sample_str = f"DNS Tunneling (Domain: {', '.join(str(d) for d in sample_domains)})"
                if ip_s not in threat_map:
                    threat_map[ip_s] = {
                        'Categories': {'Compromised Host (DNS Tunneling)'},
                        'Hits': int(count),
                        'Targeted': [sample_str]
                    }
                else:
                    threat_map[ip_s]['Categories'].add('Compromised Host (DNS Tunneling)')
                    threat_map[ip_s]['Hits'] += int(count)
                    threat_map[ip_s]['Targeted'].append(sample_str)
                    
    # 6. Tổng hợp từ TLS SNI (loại trừ máy chủ đang giám sát)
    if tls_df is not None and not tls_df.empty:
        suspicious_tls = tls_df[tls_df[Col.CLASSIFICATION].astype(str).str.contains('Suspicious|DGA|Direct IP', case=False, na=False)]
        if not suspicious_tls.empty:
            for _, row in suspicious_tls.iterrows():
                src_ip = str(row.get(Col.SOURCE_IP, '')).strip()
                dst_ip = str(row.get(Col.DEST_IP, '')).strip()
                sni = str(row.get(Col.TLS_SNI, ''))
                cls_name = str(row.get(Col.CLASSIFICATION, ''))

                if server_ip_str:
                    if dst_ip == server_ip_str:
                        actor_ip = src_ip
                    elif src_ip == server_ip_str:
                        actor_ip = dst_ip
                    else:
                        actor_ip = src_ip
                else:
                    actor_ip = dst_ip if dst_ip else src_ip

                if not actor_ip or (server_ip_str and actor_ip == server_ip_str):
                    continue

                target_str = f"SNI: {sni} ({cls_name})"
                if actor_ip not in threat_map:
                    threat_map[actor_ip] = {
                        'Categories': {'Suspicious HTTPS'},
                        'Hits': 1,
                        'Targeted': [target_str]
                    }
                else:
                    threat_map[actor_ip]['Categories'].add('Suspicious HTTPS')
                    threat_map[actor_ip]['Hits'] += 1
                    threat_map[actor_ip]['Targeted'].append(target_str)
                    
    records = []
    for ip, data in threat_map.items():
        if data['Hits'] <= 0:
            continue
        categories = sorted(data['Categories'])
        cat_str = "Multi-vector (" + ", ".join(categories) + ")" if len(categories) > 1 else categories[0]
        risk_lvl = "Cao" if (len(categories) > 1 or any(c in cat_str for c in ['C2', 'Brute-Force', 'Flood', 'DoS', 'RCE', 'Tunneling', 'Compromised'])) else "Trung bình"
        targeted_str = " | ".join(dict.fromkeys(data['Targeted']))
        
        records.append({
            Col.IP: ip,
            Col.THREAT_CATEGORY: cat_str,
            Col.HIT_COUNT: data['Hits'],
            Col.TARGETED_VECTORS: targeted_str,
            Col.RISK_LEVEL: risk_lvl
        })
        
    if not records:
        return pd.DataFrame(columns=THREAT_IP_COLUMNS)
        
    res_df = pd.DataFrame(records)
    res_df = res_df[res_df[Col.HIT_COUNT] > 0]
    res_df = res_df.sort_values(by=[Col.HIT_COUNT], ascending=[False]).reset_index(drop=True)
    
    for col in THREAT_IP_COLUMNS:
        if col not in res_df.columns:
            res_df[col] = None
    return res_df[THREAT_IP_COLUMNS]

_GEO_CACHE = {}
_GEO_READER = None
_GEO_READER_PATH = None

def _get_geo_reader(actual_path):
    global _GEO_READER, _GEO_READER_PATH
    if not actual_path:
        return None
    if _GEO_READER is not None and _GEO_READER_PATH == actual_path:
        return _GEO_READER
    try:
        import geoip2.database
        if _GEO_READER is not None:
            try:
                _GEO_READER.close()
            except Exception:
                pass
        _GEO_READER = geoip2.database.Reader(actual_path)
        _GEO_READER_PATH = actual_path
        return _GEO_READER
    except Exception:
        _GEO_READER = None
        return None

def build_external_connection_summary(df, server_ip=None):
    """
    Tổng hợp lưu lượng kết nối giữa máy nội bộ và các địa chỉ IP public bên ngoài.
    
    Quy tắc phân loại:
    1. Một đầu private và một đầu public: Đầu public luôn là External IP, kể cả khi trùng server_ip.
    2. Cả hai đầu public và có server_ip: Đầu còn lại là External IP.
    3. Cả hai đầu public nhưng không có server_ip: Ghi nhận hướng là 'Không xác định'.
    4. Cả hai đầu private: Bỏ qua (lưu lượng mạng nội bộ LAN).
    """
    if df is None or not hasattr(df, 'columns') or df.empty or Col.SOURCE_IP not in df.columns or Col.DEST_IP not in df.columns:
        return pd.DataFrame()

    server_ip_str = str(server_ip).strip() if server_ip else None

    # Lấy danh sách IP duy nhất để kiểm tra IP public một lần
    unique_src = df[Col.SOURCE_IP].dropna().unique()
    unique_dst = df[Col.DEST_IP].dropna().unique()
    all_unique_ips = set(unique_src) | set(unique_dst)

    is_pub_map = {}
    for ip_val in all_unique_ips:
        ip_s = str(ip_val).strip()
        if not ip_s or ip_s.lower() in ('unknown', 'nan', 'none', '-'):
            is_pub_map[ip_val] = False
        else:
            is_pub_map[ip_val] = is_external_ip(ip_s)

    src_is_pub = df[Col.SOURCE_IP].map(is_pub_map).fillna(False).to_numpy(dtype=bool)
    dst_is_pub = df[Col.DEST_IP].map(is_pub_map).fillna(False).to_numpy(dtype=bool)

    c_priv_to_pub = (~src_is_pub) & dst_is_pub
    c_pub_to_priv = src_is_pub & (~dst_is_pub)
    c_both_pub = src_is_pub & dst_is_pub

    n = len(df)
    ext_ip_arr = np.full(n, None, dtype=object)
    int_ip_arr = np.full(n, None, dtype=object)
    is_inbound_arr = np.zeros(n, dtype=bool)
    is_outbound_arr = np.zeros(n, dtype=bool)
    is_undet_arr = np.zeros(n, dtype=bool)

    src_series = df[Col.SOURCE_IP].astype(str).str.strip()
    dst_series = df[Col.DEST_IP].astype(str).str.strip()

    # 1. Private -> Public (Outbound): Đầu public là External IP
    if c_priv_to_pub.any():
        ext_ip_arr[c_priv_to_pub] = dst_series[c_priv_to_pub].to_numpy()
        int_ip_arr[c_priv_to_pub] = src_series[c_priv_to_pub].to_numpy()
        is_outbound_arr[c_priv_to_pub] = True

    # 2. Public -> Private (Inbound): Đầu public là External IP
    if c_pub_to_priv.any():
        ext_ip_arr[c_pub_to_priv] = src_series[c_pub_to_priv].to_numpy()
        int_ip_arr[c_pub_to_priv] = dst_series[c_pub_to_priv].to_numpy()
        is_inbound_arr[c_pub_to_priv] = True

    # 3. Cả hai đầu đều Public
    if c_both_pub.any():
        if server_ip_str:
            src_srv = (src_series == server_ip_str).to_numpy(dtype=bool)
            dst_srv = (dst_series == server_ip_str).to_numpy(dtype=bool)

            # server_ip -> public khác: Outbound, đầu còn lại là External IP
            m_srv_out = c_both_pub & src_srv & (~dst_srv)
            if m_srv_out.any():
                ext_ip_arr[m_srv_out] = dst_series[m_srv_out].to_numpy()
                int_ip_arr[m_srv_out] = src_series[m_srv_out].to_numpy()
                is_outbound_arr[m_srv_out] = True

            # public khác -> server_ip: Inbound, đầu còn lại là External IP
            m_srv_in = c_both_pub & (~src_srv) & dst_srv
            if m_srv_in.any():
                ext_ip_arr[m_srv_in] = src_series[m_srv_in].to_numpy()
                int_ip_arr[m_srv_in] = dst_series[m_srv_in].to_numpy()
                is_inbound_arr[m_srv_in] = True

            # Cả hai đầu public đều khác server_ip
            m_neither = c_both_pub & (~src_srv) & (~dst_srv)
            if m_neither.any():
                ext_ip_arr[m_neither] = dst_series[m_neither].to_numpy()
                int_ip_arr[m_neither] = src_series[m_neither].to_numpy()
                is_undet_arr[m_neither] = True
        else:
            # Không có server_ip: ghi nhận hướng Không xác định
            ext_ip_arr[c_both_pub] = dst_series[c_both_pub].to_numpy()
            int_ip_arr[c_both_pub] = src_series[c_both_pub].to_numpy()
            is_undet_arr[c_both_pub] = True

    relevant_mask = (ext_ip_arr != None)
    if not relevant_mask.any():
        return pd.DataFrame()

    sub_ext_ips = ext_ip_arr[relevant_mask]
    sub_int_ips = int_ip_arr[relevant_mask]
    sub_is_in = is_inbound_arr[relevant_mask]
    sub_is_out = is_outbound_arr[relevant_mask]
    sub_is_un = is_undet_arr[relevant_mask]

    # Trích xuất độ dài byte
    if Col.LENGTH in df.columns:
        sub_pkt_len = pd.to_numeric(df.loc[relevant_mask, Col.LENGTH], errors='coerce').fillna(0).to_numpy(dtype=np.int64)
    else:
        sub_pkt_len = np.zeros(len(sub_ext_ips), dtype=np.int64)

    # Trích xuất cờ TCP SYN (SYN=1, ACK=0)
    if Col.TCP_FLAGS in df.columns:
        flags_series = df.loc[relevant_mask, Col.TCP_FLAGS].fillna('').astype(str)
        sub_is_syn = (flags_series.str.contains('SYN', na=False) & (~flags_series.str.contains('ACK', na=False))).to_numpy(dtype=bool)
    else:
        sub_is_syn = np.zeros(len(sub_ext_ips), dtype=bool)

    # Cổng và giao thức
    has_sport = Col.SOURCE_PORT in df.columns
    has_dport = Col.DEST_PORT in df.columns
    has_proto = Col.PROTOCOL in df.columns
    has_ts = Col.TIMESTAMP in df.columns
    has_tls = Col.TLS_SNI in df.columns

    sub_sport = pd.to_numeric(df.loc[relevant_mask, Col.SOURCE_PORT], errors='coerce').to_numpy(dtype=np.float64) if has_sport else None
    sub_dport = pd.to_numeric(df.loc[relevant_mask, Col.DEST_PORT], errors='coerce').to_numpy(dtype=np.float64) if has_dport else None
    sub_proto = df.loc[relevant_mask, Col.PROTOCOL].fillna('').astype(str).str.strip().to_numpy() if has_proto else None
    sub_ts = df.loc[relevant_mask, Col.TIMESTAMP].to_numpy() if has_ts else None
    sub_tls = df.loc[relevant_mask, Col.TLS_SNI].to_numpy() if has_tls else None

    class Agg:
        __slots__ = (
            'total_pkts', 'total_bytes', 'in_p', 'out_p', 'un_p',
            'i_syn', 'e_syn', 's_count', 'flow_keys',
            'in_dports', 'out_dports', 'all_src_ports', 'all_dst_ports',
            'host_out_dports', 'proto_set', 'int_hosts_set', 'sni_set',
            'f_seen', 'l_seen'
        )
        def __init__(self):
            self.total_pkts = 0
            self.total_bytes = 0
            self.in_p = 0
            self.out_p = 0
            self.un_p = 0
            self.i_syn = 0
            self.e_syn = 0
            self.s_count = 0
            self.flow_keys = set()
            self.in_dports = set()
            self.out_dports = set()
            self.all_src_ports = set()
            self.all_dst_ports = set()
            self.host_out_dports = defaultdict(set)
            self.proto_set = set()
            self.int_hosts_set = set()
            self.sni_set = set()
            self.f_seen = None
            self.l_seen = None

    stats_map = defaultdict(Agg)
    m = len(sub_ext_ips)

    for i in range(m):
        e_ip = sub_ext_ips[i]
        i_ip = sub_int_ips[i]
        i_in = sub_is_in[i]
        i_out = sub_is_out[i]
        p_len = int(sub_pkt_len[i])
        is_s = sub_is_syn[i]

        sp_val = sub_sport[i] if sub_sport is not None else np.nan
        dp_val = sub_dport[i] if sub_dport is not None else np.nan
        sp_int = int(sp_val) if not np.isnan(sp_val) else None
        dp_int = int(dp_val) if not np.isnan(dp_val) else None
        pr = sub_proto[i] if sub_proto is not None else ''

        st = stats_map[e_ip]
        st.total_pkts += 1
        st.total_bytes += p_len

        if i_in:
            st.in_p += 1
            if dp_int is not None:
                st.in_dports.add(dp_int)
            flow_p1 = dp_int
            flow_p2 = sp_int
        elif i_out:
            st.out_p += 1
            if dp_int is not None:
                st.out_dports.add(dp_int)
                st.host_out_dports[i_ip].add(dp_int)
            flow_p1 = sp_int
            flow_p2 = dp_int
        else:
            st.un_p += 1
            flow_p1 = sp_int
            flow_p2 = dp_int

        if is_s:
            st.s_count += 1
            if i_out:
                st.i_syn += 1
            elif i_in:
                st.e_syn += 1

        st.flow_keys.add((i_ip, flow_p1, flow_p2, pr))
        if sp_int is not None:
            st.all_src_ports.add(sp_int)
        if dp_int is not None:
            st.all_dst_ports.add(dp_int)
        if pr:
            st.proto_set.add(pr)
        st.int_hosts_set.add(i_ip)

        if sub_tls is not None:
            tv = sub_tls[i]
            if tv is not None and not pd.isna(tv):
                tsni_str = str(tv).strip()
                if tsni_str and tsni_str.lower() != 'nan':
                    st.sni_set.add(tsni_str)

        if sub_ts is not None:
            ts_val = sub_ts[i]
            if ts_val is not None and not pd.isna(ts_val):
                if st.f_seen is None or ts_val < st.f_seen:
                    st.f_seen = ts_val
                if st.l_seen is None or ts_val > st.l_seen:
                    st.l_seen = ts_val

    records = []
    for ext_ip in sorted(stats_map.keys()):
        st = stats_map[ext_ip]
        ext_ip_str = str(ext_ip).strip()
        t_pkts = st.total_pkts
        t_bytes = st.total_bytes
        in_p = st.in_p
        out_p = st.out_p
        un_p = st.un_p
        i_syn = st.i_syn
        e_syn = st.e_syn
        s_count = st.s_count
        c_count = len(st.flow_keys)
        if c_count == 0:
            c_count = 1 if t_pkts > 0 else 0

        # Suy luận hướng giao tiếp
        if un_p > 0 and in_p == 0 and out_p == 0:
            direction = 'Không xác định'
        elif i_syn > 0 and e_syn == 0:
            direction = 'Outbound'
        elif e_syn > 0 and i_syn == 0:
            direction = 'Inbound'
        elif i_syn > 0 and e_syn > 0:
            direction = 'Outbound' if i_syn >= e_syn else 'Inbound'
        else:
            if out_p > 0 and in_p == 0:
                direction = 'Outbound'
            elif in_p > 0 and out_p == 0:
                direction = 'Inbound'
            elif out_p >= in_p:
                direction = 'Outbound'
            else:
                direction = 'Inbound'

        in_dports = st.in_dports
        out_dports = st.out_dports

        if direction == 'Inbound':
            targeted_ports_set = in_dports if in_dports else out_dports
        elif direction == 'Outbound':
            targeted_ports_set = out_dports if out_dports else in_dports
        else:
            all_dp = st.all_dst_ports
            targeted_ports_set = all_dp if all_dp else (out_dports | in_dports)

        max_ports_per_host = max((len(p) for p in st.host_out_dports.values()), default=0)

        f_seen_str = '—'
        if st.f_seen is not None:
            ts_p = pd.Timestamp(st.f_seen)
            f_seen_str = ts_p.strftime('%Y-%m-%d %H:%M:%S')

        l_seen_str = '—'
        if st.l_seen is not None:
            ts_p = pd.Timestamp(st.l_seen)
            l_seen_str = ts_p.strftime('%Y-%m-%d %H:%M:%S')

        proto_str = ', '.join(sorted(st.proto_set)) if st.proto_set else 'Unknown'
        int_hosts_str = ', '.join(sorted(st.int_hosts_set))

        records.append({
            Col.EXTERNAL_IP: ext_ip_str,
            Col.INTERNAL_IP: int_hosts_str,
            Col.DIRECTION: direction,
            Col.PROTOCOLS: proto_str,
            Col.SOURCE_PORTS: ', '.join(str(p) for p in sorted(st.all_src_ports)[:8]),
            Col.DEST_PORTS: ', '.join(str(p) for p in sorted(st.all_dst_ports)[:8]),
            Col.TARGETED_PORTS: ', '.join(str(p) for p in sorted(targeted_ports_set)[:10]),
            Col.TOTAL_PACKETS: t_pkts,
            Col.TOTAL_BYTES: t_bytes,
            Col.CONNECTION_COUNT: c_count,
            Col.SYN_COUNT: s_count,
            Col.FIRST_SEEN: f_seen_str,
            Col.LAST_SEEN: l_seen_str,
            Col.DOMAIN_SNI: ', '.join(sorted(st.sni_set)) if st.sni_set else '—',
            '_targeted_ports_tuple': tuple(sorted(targeted_ports_set)),
            '_max_ports_per_host': max_ports_per_host,
            '_domains_sni_str': ', '.join(sorted(st.sni_set))
        })

    return pd.DataFrame(records)

def classify_external_connections(
    summary_df,
    allowlist=None,
    blocklist=None,
    threat_ips_df=None,
    tls_df=None,
    dns_results=None,
    unusual_ports=None,
    connection_threshold=None,
    multi_port_threshold=None,
    server_ip=None
):
    """
    Phân loại trạng thái (Tin cậy, Chưa xác minh, Đáng ngờ) cho các IP bên ngoài.
    
    Thứ tự ưu tiên đánh giá:
    1. Blocklist
    2. Bằng chứng tấn công rõ ràng (Port Scan, DoS, Web Attack, DNS Tunneling, TLS nguy hiểm)
    3. Allowlist
    4. Heuristics (cổng dịch vụ rủi ro theo targeted_ports, quét nhiều cổng, tần suất kết nối cao)
    5. Chưa xác minh
    """
    if summary_df is None or summary_df.empty:
        return pd.DataFrame(columns=EXTERNAL_CONNECTION_COLUMNS)

    server_ip_str = str(server_ip).strip() if server_ip else None
    unusual_ports_map = unusual_ports if unusual_ports is not None else DEFAULT_UNUSUAL_PORTS
    conn_thresh = int(connection_threshold) if connection_threshold is not None else DEFAULT_EXTERNAL_CONNECTION_THRESHOLD
    multi_port_thresh = int(multi_port_threshold) if multi_port_threshold is not None else DEFAULT_MULTI_PORT_THRESHOLD

    # Phân tích danh sách IP và CIDR cho Allowlist và Blocklist
    allowlist_input = allowlist if allowlist is not None else DEFAULT_ALLOWLIST
    blocklist_input = blocklist if blocklist is not None else []
    allowlist_nets, _ = parse_ip_or_network_list(allowlist_input)
    blocklist_nets, _ = parse_ip_or_network_list(blocklist_input)

    exact_allow = {str(n.network_address) for n in allowlist_nets if n.num_addresses == 1}
    subnet_allow = [n for n in allowlist_nets if n.num_addresses > 1]
    exact_block = {str(n.network_address) for n in blocklist_nets if n.num_addresses == 1}
    subnet_block = [n for n in blocklist_nets if n.num_addresses > 1]

    def _matches_nets(ip_s, exact_s, sub_list):
        if not exact_s and not sub_list:
            return False
        if ip_s in exact_s:
            return True
        if not sub_list:
            return False
        return ip_matches_network_list(ip_s, sub_list)

    # Chuẩn bị trước tra cứu Threat IPs dạng O(1)
    threat_map = {}
    if threat_ips_df is not None and not threat_ips_df.empty and Col.IP in threat_ips_df.columns:
        has_cat = Col.THREAT_CATEGORY in threat_ips_df.columns
        has_vec = Col.TARGETED_VECTORS in threat_ips_df.columns
        tip_arr = threat_ips_df[Col.IP].astype(str).str.strip().to_numpy()
        cat_arr = threat_ips_df[Col.THREAT_CATEGORY].astype(str).str.strip().to_numpy() if has_cat else None
        vec_arr = threat_ips_df[Col.TARGETED_VECTORS].astype(str).str.strip().to_numpy() if has_vec else None
        for i in range(len(tip_arr)):
            tip = tip_arr[i]
            if tip:
                cat = cat_arr[i] if cat_arr is not None else 'Đe dọa'
                vec = vec_arr[i] if vec_arr is not None else ''
                desc = f"{cat} ({vec})" if vec else cat
                threat_map.setdefault(tip, []).append(desc)

    # Chuẩn bị trước tra cứu TLS bất thường dạng O(1)
    suspicious_tls_map = {}
    tls_sni_map = {}
    if tls_df is not None and not tls_df.empty:
        cls_col = Col.CLASSIFICATION if Col.CLASSIFICATION in tls_df.columns else None
        has_src = Col.SOURCE_IP in tls_df.columns
        has_dst = Col.DEST_IP in tls_df.columns
        has_sni = Col.TLS_SNI in tls_df.columns

        if cls_col and has_src and has_dst:
            bad_mask = tls_df[cls_col].astype(str).str.contains('Suspicious|DGA|Direct IP|Dynamic DNS', case=False, na=False)
            if bad_mask.any():
                bad_tls = tls_df[bad_mask]
                b_src = bad_tls[Col.SOURCE_IP].astype(str).str.strip().to_numpy()
                b_dst = bad_tls[Col.DEST_IP].astype(str).str.strip().to_numpy()
                b_cls = bad_tls[cls_col].astype(str).str.strip().to_numpy()
                b_sni = bad_tls[Col.TLS_SNI].astype(str).str.strip().to_numpy() if has_sni else None
                for i in range(len(b_src)):
                    sni_val = b_sni[i] if b_sni is not None else ''
                    cls_val = b_cls[i]
                    desc = f"TLS SNI bất thường: {sni_val} ({cls_val})" if sni_val and sni_val.lower() != 'nan' else f"TLS: {cls_val}"
                    s_ip = b_src[i]
                    d_ip = b_dst[i]
                    if s_ip:
                        suspicious_tls_map.setdefault(s_ip, []).append(desc)
                    if d_ip:
                        suspicious_tls_map.setdefault(d_ip, []).append(desc)

        if has_sni:
            valid_tls = tls_df[[c for c in [Col.SOURCE_IP, Col.DEST_IP, Col.TLS_SNI] if c in tls_df.columns]].dropna(subset=[Col.TLS_SNI])
            if not valid_tls.empty:
                v_src = valid_tls[Col.SOURCE_IP].astype(str).str.strip().to_numpy() if has_src else None
                v_dst = valid_tls[Col.DEST_IP].astype(str).str.strip().to_numpy() if has_dst else None
                v_sni = valid_tls[Col.TLS_SNI].astype(str).str.strip().to_numpy()
                for i in range(len(v_sni)):
                    t_sni = v_sni[i]
                    if t_sni and t_sni.lower() != 'nan':
                        if v_src is not None and v_src[i]:
                            tls_sni_map.setdefault(v_src[i], set()).add(t_sni)
                        if v_dst is not None and v_dst[i]:
                            tls_sni_map.setdefault(v_dst[i], set()).add(t_sni)

    # Chuẩn bị trước tra cứu tên miền từ DNS
    dns_domain_map = {}
    if dns_results and isinstance(dns_results, dict):
        all_dns_df = dns_results.get('all_queries')
        if all_dns_df is not None and not all_dns_df.empty and Col.DOMAIN in all_dns_df.columns:
            has_dsrc = Col.SOURCE_IP in all_dns_df.columns
            has_ddst = Col.DEST_IP in all_dns_df.columns
            valid_dns = all_dns_df[[c for c in [Col.SOURCE_IP, Col.DEST_IP, Col.DOMAIN] if c in all_dns_df.columns]].dropna(subset=[Col.DOMAIN])
            if not valid_dns.empty:
                vd_src = valid_dns[Col.SOURCE_IP].astype(str).str.strip().to_numpy() if has_dsrc else None
                vd_dst = valid_dns[Col.DEST_IP].astype(str).str.strip().to_numpy() if has_ddst else None
                vd_dom = valid_dns[Col.DOMAIN].astype(str).str.strip().to_numpy()
                for i in range(len(vd_dom)):
                    d_dom = vd_dom[i]
                    if d_dom and d_dom.lower() != 'nan':
                        if vd_src is not None and vd_src[i]:
                            dns_domain_map.setdefault(vd_src[i], set()).add(d_dom)
                        if vd_dst is not None and vd_dst[i]:
                            dns_domain_map.setdefault(vd_dst[i], set()).add(d_dom)

    classified_records = []
    for row_dict in summary_df.to_dict(orient='records'):
        ext_ip = str(row_dict[Col.EXTERNAL_IP]).strip()
        conn_count = int(row_dict[Col.CONNECTION_COUNT])
        syn_count = int(row_dict.get(Col.SYN_COUNT, 0))

        # Lấy targeted_ports: CHỈ lấy các cổng dịch vụ mục tiêu, KHÔNG dùng source port ephemeral
        targeted_ports = row_dict.get('_targeted_ports_tuple', None)
        if targeted_ports is None:
            t_str = str(row_dict.get(Col.TARGETED_PORTS, ''))
            targeted_ports = [int(p) for p in t_str.split(',') if p.strip().isdigit()]

        max_ports_per_host = int(row_dict.get('_max_ports_per_host', 0))

        # Gộp domain và TLS SNI
        row_sni_str = str(row_dict.get('_domains_sni_str', '')).strip()
        row_sni_set = {s.strip() for s in row_sni_str.split(',') if s.strip()} if row_sni_str else set()
        if ext_ip in tls_sni_map:
            row_sni_set.update(tls_sni_map[ext_ip])
        if ext_ip in dns_domain_map:
            row_sni_set.update(dns_domain_map[ext_ip])
        domain_sni_str = ", ".join(sorted(row_sni_set)) if row_sni_set else row_dict.get(Col.DOMAIN_SNI, "—")

        # 1. Bằng chứng tấn công trực tiếp
        direct_threats = []
        if ext_ip in threat_map:
            direct_threats.extend(threat_map[ext_ip])
        if ext_ip in suspicious_tls_map:
            direct_threats.extend(suspicious_tls_map[ext_ip])

        # 2. Bằng chứng theo heuristic: CHỈ kiểm tra targeted_ports
        heuristics = []
        hit_unusual = [f"{p} ({unusual_ports_map[p]})" for p in sorted(targeted_ports) if p in unusual_ports_map]
        if hit_unusual:
            heuristics.append(f"Kết nối tới cổng dịch vụ rủi ro: {', '.join(hit_unusual[:4])}")

        if max_ports_per_host >= multi_port_thresh:
            heuristics.append(f"Máy nội bộ kết nối đến {max_ports_per_host} cổng khác nhau trên IP này")

        if conn_count >= conn_thresh:
            heuristics.append(f"Số lượng kết nối vượt ngưỡng cấu hình ({conn_count:,} >= {conn_thresh})")

        # 3. Phân loại theo thứ tự ưu tiên:
        # Blocklist > Bằng chứng tấn công > Allowlist > Heuristics > Chưa xác minh
        in_blocklist = _matches_nets(ext_ip, exact_block, subnet_block)
        in_allowlist = _matches_nets(ext_ip, exact_allow, subnet_allow)

        if in_blocklist and in_allowlist:
            status = 'Đáng ngờ'
            risk_lvl = 'Cao'
            reason = 'IP nằm trong cả Allowlist và Blocklist (Ưu tiên Blocklist)'
            if direct_threats:
                reason += f" | {'; '.join(dict.fromkeys(direct_threats))}"
        elif in_blocklist:
            status = 'Đáng ngờ'
            risk_lvl = 'Cao'
            reason = 'IP/dải mạng nằm trong Blocklist cấu hình'
            if direct_threats:
                reason += f" | {'; '.join(dict.fromkeys(direct_threats))}"
        elif direct_threats:
            status = 'Đáng ngờ'
            risk_lvl = 'Cao'
            reason = f"Phát hiện hành vi đe dọa: {'; '.join(dict.fromkeys(direct_threats))}"
            if in_allowlist:
                reason += " (Bằng chứng tấn công được ưu tiên hơn Allowlist)"
        elif in_allowlist:
            status = 'Tin cậy'
            risk_lvl = 'An toàn'
            reason = 'Nằm trong Allowlist tin cậy do người dùng cấu hình'
        elif server_ip_str and ext_ip == server_ip_str:
            # IP máy chủ mục tiêu đang phân tích, không có hành vi đe dọa
            status = 'Tin cậy'
            risk_lvl = 'An toàn'
            reason = 'IP máy chủ được chọn phân tích (không ghi nhận hành vi đe dọa)'
        elif heuristics:
            status = 'Đáng ngờ'
            risk_lvl = 'Trung bình'
            reason = ' | '.join(dict.fromkeys(heuristics))
        else:
            status = 'Chưa xác minh'
            risk_lvl = 'Thấp'
            reason = 'IP public bên ngoài thông thường, chưa ghi nhận dấu hiệu bất thường'

        rec = {
            Col.EXTERNAL_IP: ext_ip,
            Col.INTERNAL_IP: row_dict[Col.INTERNAL_IP],
            Col.DIRECTION: row_dict[Col.DIRECTION],
            Col.PROTOCOLS: row_dict[Col.PROTOCOLS],
            Col.SOURCE_PORTS: row_dict[Col.SOURCE_PORTS],
            Col.DEST_PORTS: row_dict[Col.DEST_PORTS],
            Col.TARGETED_PORTS: row_dict[Col.TARGETED_PORTS],
            Col.TOTAL_PACKETS: row_dict[Col.TOTAL_PACKETS],
            Col.TOTAL_BYTES: row_dict[Col.TOTAL_BYTES],
            Col.CONNECTION_COUNT: conn_count,
            Col.SYN_COUNT: syn_count,
            Col.FIRST_SEEN: row_dict[Col.FIRST_SEEN],
            Col.LAST_SEEN: row_dict[Col.LAST_SEEN],
            Col.DOMAIN_SNI: domain_sni_str,
            Col.GEO_LOCATION: row_dict.get(Col.GEO_LOCATION, "Chưa rõ"),
            Col.STATUS: status,
            Col.RISK_LEVEL: risk_lvl,
            Col.FLAG_REASON: reason
        }
        classified_records.append(rec)

    res_df = pd.DataFrame(classified_records)

    # Sắp xếp: Đáng ngờ (Cao -> Trung bình) -> Chưa xác minh -> Tin cậy, sau đó theo Tổng gói tin giảm dần
    status_order = {'Đáng ngờ': 0, 'Chưa xác minh': 1, 'Tin cậy': 2}
    risk_order = {'Cao': 0, 'Trung bình': 1, 'Thấp': 2, 'An toàn': 3}
    res_df['__status_rank'] = res_df[Col.STATUS].map(status_order).fillna(9)
    res_df['__risk_rank'] = res_df[Col.RISK_LEVEL].map(risk_order).fillna(9)
    res_df = res_df.sort_values(
        by=['__status_rank', '__risk_rank', Col.TOTAL_PACKETS],
        ascending=[True, True, False]
    ).drop(columns=['__status_rank', '__risk_rank']).reset_index(drop=True)

    for col in EXTERNAL_CONNECTION_COLUMNS:
        if col not in res_df.columns:
            res_df[col] = None

    return res_df[EXTERNAL_CONNECTION_COLUMNS]

def enrich_external_connections_geoip(result_df, db_path=None):
    """
    Bổ sung vị trí địa lý (Quốc gia, Thành phố) cho danh sách IP bên ngoài.
    
    Mở tệp cơ sở dữ liệu một lần và lưu tạm kết quả theo từng IP để tái sử dụng.
    """
    if result_df is None or result_df.empty or Col.EXTERNAL_IP not in result_df.columns:
        return result_df

    res_df = result_df.copy()

    possible_paths = [
        db_path,
        "data/GeoLite2-City.mmdb",
        "../data/GeoLite2-City.mmdb",
        "./GeoLite2-City.mmdb"
    ]
    actual_path = None
    for p in possible_paths:
        if p and os.path.exists(p):
            actual_path = p
            break

    if not actual_path:
        if Col.GEO_LOCATION not in res_df.columns:
            res_df[Col.GEO_LOCATION] = "Chưa rõ"
        return res_df

    geo_reader = _get_geo_reader(actual_path)
    if not geo_reader:
        if Col.GEO_LOCATION not in res_df.columns:
            res_df[Col.GEO_LOCATION] = "Chưa rõ"
        return res_df

    geo_locations = []
    for ext_ip in res_df[Col.EXTERNAL_IP]:
        ip_str = str(ext_ip).strip()
        if ip_str in _GEO_CACHE:
            geo_locations.append(_GEO_CACHE[ip_str])
            continue

        loc_str = "Chưa rõ"
        try:
            resp = geo_reader.city(ip_str)
            c_city = resp.city.name
            c_country = resp.country.name
            if c_city and c_country:
                loc_str = f"{c_city}, {c_country}"
            elif c_country:
                loc_str = c_country
        except Exception:
            loc_str = "Chưa rõ"

        _GEO_CACHE[ip_str] = loc_str
        geo_locations.append(loc_str)

    res_df[Col.GEO_LOCATION] = geo_locations
    return res_df

def detect_external_connections(
    df,
    server_ip=None,
    allowlist=None,
    blocklist=None,
    threat_ips_df=None,
    unusual_ports=None,
    connection_threshold=None,
    multi_port_threshold=None,
    tls_df=None,
    dns_results=None,
    geoip_db_path=None
):
    """
    Phát hiện, phân tích và thống kê các kết nối giữa máy nội bộ và IP public bên ngoài.
    
    Hàm thực hiện 3 bước:
    1. build_external_connection_summary: Trích xuất và tổng hợp lưu lượng.
    2. classify_external_connections: Đánh giá phân loại theo thứ tự ưu tiên.
    3. enrich_external_connections_geoip: Bổ sung vị trí địa lý nếu có cơ sở dữ liệu.
    """
    summary_df = build_external_connection_summary(df, server_ip=server_ip)
    if summary_df is None or summary_df.empty:
        return pd.DataFrame(columns=EXTERNAL_CONNECTION_COLUMNS)

    classified_df = classify_external_connections(
        summary_df,
        allowlist=allowlist,
        blocklist=blocklist,
        threat_ips_df=threat_ips_df,
        tls_df=tls_df,
        dns_results=dns_results,
        unusual_ports=unusual_ports,
        connection_threshold=connection_threshold,
        multi_port_threshold=multi_port_threshold,
        server_ip=server_ip
    )

    enriched_df = enrich_external_connections_geoip(classified_df, db_path=geoip_db_path)
    return enriched_df

