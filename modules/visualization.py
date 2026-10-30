import os
import pandas as pd  # type: ignore
import plotly.express as px  # type: ignore
import plotly.graph_objects as go  # type: ignore
from modules.constants import Col

def plot_protocol_stats(df):
    """
    Vẽ biểu đồ tròn (Pie chart) thống kê tỷ lệ các giao thức mạng.
    """
    if df is None or df.empty or Col.PROTOCOL not in df.columns:
        return None
        
    proto_counts = df[Col.PROTOCOL].value_counts().reset_index()
    if proto_counts.empty:
        return None
        
    proto_counts.columns = ['Protocol', 'Count']
    total_packets = proto_counts['Count'].sum()
    if total_packets == 0:
        return None
        
    proto_counts['Protocol_Legend'] = proto_counts.apply(
        lambda row: f"{row['Protocol']} ({row['Count'] / total_packets * 100:.1f}%)", axis=1
    )
    
    custom_colors = [
        '#FF4B4B', '#00CC96', '#FFA15A', '#636EFA', '#AB63FA',
        '#19D3F3', '#E763FA', '#FECB52', '#00B8D9', '#FF8B94',
        '#2ECC71', '#E67E22', '#9B59B6', '#34495E', '#F1C40F'
    ]
    
    fig = px.pie(proto_counts, names='Protocol_Legend', values='Count',
                 title='Giao Thức Mạng',
                 color_discrete_sequence=custom_colors,
                 template='plotly_dark')
    fig.update_traces(textposition='inside', textinfo='percent')
    return fig

def plot_time_flow(df, freq='1s'):
    """
    Vẽ biểu đồ đường (Line chart) thể hiện lưu lượng mạng theo thời gian.
    """
    if df is None or df.empty or Col.TIMESTAMP not in df.columns:
        return None
        
    try:
        time_series = df.set_index(Col.TIMESTAMP).resample(freq).size().reset_index(name='Packet Count')
        if time_series.empty:
            return None
            
        fig = px.line(time_series, x=Col.TIMESTAMP, y='Packet Count',
                      title='Lưu Lượng Theo Thời Gian',
                      template='plotly_dark')
        fig.update_layout(xaxis_title="Mốc thời gian", yaxis_title="Số lượng gói tin")
        return fig
    except Exception:
        return None

def plot_top_ips(df, top_n=10):
    """
    Vẽ biểu đồ cột (Bar chart) thống kê Top N IP gửi và nhận gói tin nhiều nhất.
    """
    if df is None or df.empty or Col.SOURCE_IP not in df.columns or Col.DEST_IP not in df.columns:
        return None, None
        
    fig_src = None
    fig_dst = None
    
    src_counts = df[Col.SOURCE_IP].value_counts().nlargest(top_n).reset_index()
    if not src_counts.empty:
        src_counts.columns = ['IP', 'Count']
        fig_src = px.bar(src_counts, x='IP', y='Count', text_auto=True,
                         title=f'Top {top_n} Địa Chỉ IP Nguồn (Gửi Gói Tin)',
                         template='plotly_dark',
                         color='Count',
                         color_continuous_scale='Reds')
        fig_src.update_layout(xaxis_title="Địa chỉ IP Nguồn", yaxis_title="Số lượng gói tin")
                         
    dst_counts = df[Col.DEST_IP].value_counts().nlargest(top_n).reset_index()
    if not dst_counts.empty:
        dst_counts.columns = ['IP', 'Count']
        fig_dst = px.bar(dst_counts, x='IP', y='Count', text_auto=True,
                         title=f'Top {top_n} Địa Chỉ IP Đích (Nhận Gói Tin)',
                         template='plotly_dark',
                         color='Count',
                         color_continuous_scale='Blues')
        fig_dst.update_layout(xaxis_title="Địa chỉ IP Đích", yaxis_title="Số lượng gói tin")
                         
    return fig_src, fig_dst

def plot_geoip_map(df, db_path='data/GeoLite2-City.mmdb'):
    """
    Chấm toạ độ địa lý các IP nguồn (Source IPs / Threat Actors) lên bản đồ thế giới.
    Hỗ trợ cả schema bảng gói tin ('Source IP' / 'Dest IP')
    và bảng Threat IP ('IP', 'Hit Count', 'Threat Category', 'Risk Level').
    """
    try:
        import geoip2.database  # type: ignore
        import geoip2.errors  # type: ignore
    except ImportError:
        return None
        
    if df is None or df.empty or not os.path.exists(db_path):
        return None

    is_threat_table = Col.IP in df.columns
    ip_records = []
    
    if is_threat_table:
        for _, row in df.head(500).iterrows():
            raw_ip = str(row[Col.IP]).strip()
            if not raw_ip:
                continue
            hits = int(row.get(Col.HIT_COUNT, 1)) if pd.notna(row.get(Col.HIT_COUNT)) else 1
            cat = str(row.get(Col.THREAT_CATEGORY, 'Threat Actor'))
            risk = str(row.get(Col.RISK_LEVEL, 'N/A'))
            ip_records.append({'ip': raw_ip, 'count': hits, 'category': cat, 'risk': risk})
    else:
        ip_col = Col.SOURCE_IP if Col.SOURCE_IP in df.columns else (Col.DEST_IP if Col.DEST_IP in df.columns else None)
        if not ip_col:
            return None
        src_counts = df[ip_col].value_counts().head(500)
        for ip, count in src_counts.items():
            raw_ip = str(ip).strip()
            if not raw_ip or count <= 0:
                continue
            ip_records.append({'ip': raw_ip, 'count': int(count), 'category': 'Lưu lượng', 'risk': 'Thường'})

    if not ip_records:
        return None

    geo_data = []
    try:
        with geoip2.database.Reader(db_path) as reader:
            for item in ip_records:
                ip_str = item['ip']
                count = item['count']
                try:
                    response = reader.city(ip_str)
                    lat = response.location.latitude
                    lon = response.location.longitude
                    if lat is not None and lon is not None:
                        city = response.city.name or "Chưa rõ thành phố"
                        country = response.country.name or "Chưa rõ quốc gia"
                        loc_title = f"{city}, {country} ({ip_str})"
                        if is_threat_table and item['risk'] != 'N/A':
                            loc_title += f" - {item['risk']} [{item['category']}]"
                        geo_data.append({
                            'IP': ip_str,
                            'Location': loc_title,
                            'City': city,
                            'Country': country,
                            'Latitude': lat,
                            'Longitude': lon,
                            'Packets': count,
                            'Threat Category': item['category'],
                            'Risk Level': item['risk']
                        })
                except (geoip2.errors.AddressNotFoundError, ValueError):
                    continue
    except Exception:
        return None

    if not geo_data:
        return None
        
    geo_df = pd.DataFrame(geo_data)
    title_text = 'Bản Đồ Đối Tượng Đe Dọa (Threat Actors)' if is_threat_table else 'Bản Đồ IP Nguồn'
    colorbar_label = 'Số Hit Đe Dọa' if is_threat_table else 'Số Gói Tin'

    fig = px.scatter_geo(
        geo_df, 
        lat='Latitude', 
        lon='Longitude',
        hover_name='Location',
        size='Packets',
        size_max=22,
        color='Packets',
        color_continuous_scale='Reds',
        title=title_text,
        template='plotly_dark',
        projection='natural earth'
    )
                         
    fig.update_geos(
        showcoastlines=True, coastlinecolor="#64748b",
        showland=True, landcolor="#1e293b",
        showocean=True, oceancolor="#090d16",
        showcountries=True, countrycolor="#475569",
        showlakes=True, lakecolor="#090d16",
        bgcolor="#0e1117",
        showframe=False
    )
    fig.update_layout(
        margin=dict(l=0, r=0, t=40, b=0),
        coloraxis_colorbar=dict(title=colorbar_label, thickness=15, len=0.75)
    )
    return fig

def plot_web_attacks_stats(web_attacks_df):
    """
    Vẽ biểu đồ hình thanh (Horizontal Bar Chart) thống kê các loại tấn công Web.
    """
    if web_attacks_df is None or web_attacks_df.empty or Col.ATTACK_CATEGORY not in web_attacks_df.columns:
        return None
        
    cats = []
    for val in web_attacks_df[Col.ATTACK_CATEGORY].dropna():
        for sub in str(val).split(', '):
            if sub.strip():
                cats.append(sub.strip())
                
    if not cats:
        return None
        
    counts_df = pd.Series(cats).value_counts().reset_index()
    counts_df.columns = ['Category', 'Count']
    
    fig = px.bar(counts_df, x='Count', y='Category', orientation='h', text_auto=True,
                 title='Danh Mục Web Attack',
                 template='plotly_dark',
                 color='Count',
                 color_continuous_scale='Turbo')
    fig.update_layout(yaxis=dict(autorange="reversed"), xaxis_title="Số lượt phát hiện", yaxis_title="Hình thức tấn công Web")
    return fig

def plot_web_attack_uris(web_attacks_df, top_n=10):
    """
    Vẽ biểu đồ Top URIs bị tấn công / thăm dò nhiều nhất.
    """
    if web_attacks_df is None or not hasattr(web_attacks_df, "columns") or web_attacks_df.empty:
        return None
    uri_col = 'URI' if 'URI' in web_attacks_df.columns else Col.HTTP_URI
    if uri_col not in web_attacks_df.columns:
        return None
        
    counts = web_attacks_df[uri_col].dropna().value_counts().head(top_n).reset_index()
    if counts.empty:
        return None
        
    counts.columns = ['URI', 'Requests']
    
    fig = px.bar(counts, x='Requests', y='URI', orientation='h', text_auto=True,
                 title=f'Top {top_n} URI Bị Tấn Công',
                 template='plotly_dark',
                 color='Requests',
                 color_continuous_scale='Inferno')
    fig.update_layout(yaxis=dict(autorange="reversed"), xaxis_title="Lượt Request", yaxis_title="Đường dẫn HTTP URI")
    return fig

def plot_threat_categories(threat_ips_df):
    """
    Vẽ biểu đồ phân bổ các loại đối tượng đe dọa (Threat Categories).
    """
    if threat_ips_df is None or threat_ips_df.empty or Col.THREAT_CATEGORY not in threat_ips_df.columns:
        return None
        
    counts = threat_ips_df[Col.THREAT_CATEGORY].dropna().value_counts().reset_index()
    if counts.empty:
        return None
        
    counts.columns = ['Category', 'IP Count']
    
    fig = px.pie(counts, names='Category', values='IP Count',
                 title='Nhóm Threat Actor',
                 hole=0.4,
                 template='plotly_dark',
                 color_discrete_sequence=['#ef4444', '#f97316', '#3b82f6', '#8b5cf6', '#10b981'])
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def plot_dns_distribution(dns_results):
    """
    Vẽ biểu đồ phân bổ loại truy vấn DNS (Inbound Probes vs Outbound Queries).
    """
    if not dns_results or 'all_queries' not in dns_results or dns_results['all_queries'].empty:
        return None
        
    all_dns = dns_results['all_queries']
    if Col.CLASSIFICATION not in all_dns.columns:
        return None
        
    counts = all_dns[Col.CLASSIFICATION].dropna().value_counts().reset_index()
    if counts.empty:
        return None
        
    counts.columns = ['Type', 'Count']
    
    fig = px.pie(counts, names='Type', values='Count',
                 title='Phân Bổ DNS Query',
                 hole=0.45,
                 template='plotly_dark',
                 color_discrete_sequence=['#3b82f6', '#10b981', '#ef4444', '#f59e0b'])
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def plot_scanned_ports_stats(port_scans_df, top_n=10):
    """
    Vẽ biểu đồ thống kê các cổng bị nhắm tới nhiều nhất trong các đợt Port Scan.
    """
    if port_scans_df is None or port_scans_df.empty or Col.TARGETED_PORTS not in port_scans_df.columns:
        return None
        
    port_list = []
    for ports_str in port_scans_df[Col.TARGETED_PORTS].dropna():
        for p in str(ports_str).split(','):
            p = p.strip()
            if p.isdigit():
                port_list.append(int(p))
                
    if not port_list:
        return None
        
    counts = pd.Series(port_list).value_counts().head(top_n).reset_index()
    if counts.empty:
        return None
        
    counts.columns = ['Port', 'Scan Attempts']
    counts['Port_Label'] = counts['Port'].apply(lambda x: f"Cổng {x}")
    
    fig = px.bar(counts, x='Port_Label', y='Scan Attempts', text_auto=True,
                 title=f'Top {top_n} Port Bị Quét',
                 template='plotly_dark',
                 color='Scan Attempts',
                 color_continuous_scale='Reds')
    fig.update_layout(xaxis_title="Cổng dịch vụ", yaxis_title="Tần suất bị quét")
    return fig

def plot_tls_sni_stats(tls_df, top_n=10):
    """
    Vẽ biểu đồ Top các tên miền HTTPS (TLS SNI) được truy vấn nhiều nhất.
    """
    if tls_df is None or tls_df.empty or Col.TLS_SNI not in tls_df.columns:
        return None
        
    counts = tls_df[Col.TLS_SNI].dropna().value_counts().head(top_n).reset_index()
    if counts.empty:
        return None
        
    counts.columns = ['Domain', 'Requests']
    
    fig = px.bar(counts, x='Requests', y='Domain', orientation='h', text_auto=True,
                 title=f'Top {top_n} TLS SNI',
                 template='plotly_dark',
                 color='Requests',
                 color_continuous_scale='Teal')
    fig.update_layout(
        yaxis=dict(autorange="reversed"),
        xaxis_title="Số lượt kết nối TLS",
        yaxis_title="Tên miền (SNI)"
    )
    return fig

def plot_tls_classification(tls_df):
    """
    Vẽ biểu đồ phân loại mức độ rủi ro tên miền HTTPS / TLS SNI (Donut chart).
    """
    if tls_df is None or tls_df.empty or Col.CLASSIFICATION not in tls_df.columns:
        return None
        
    counts = tls_df[Col.CLASSIFICATION].dropna().value_counts().reset_index()
    if counts.empty:
        return None
        
    counts.columns = ['Type', 'Count']
    
    color_map = {
        'Legitimate HTTPS': '#10b981',
        'Suspicious C2 (Direct IP)': '#ef4444',
        'High Entropy DGA': '#f59e0b',
        'Suspicious Dynamic DNS': '#8b5cf6'
    }
    
    fig = px.pie(
        counts, 
        names='Type', 
        values='Count',
        title='Phân Loại TLS SNI',
        hole=0.45,
        template='plotly_dark',
        color='Type',
        color_discrete_map=color_map
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def plot_dos_bruteforce_stats(dos_df):
    """
    Vẽ biểu đồ phân loại các hình thức tấn công DoS/DDoS & Brute-force.
    """
    if dos_df is None or dos_df.empty or Col.ATTACK_TYPE not in dos_df.columns:
        return None
        
    counts = dos_df.groupby(Col.ATTACK_TYPE, observed=True)[Col.PACKET_COUNT].sum().reset_index()
    if counts.empty:
        return None
        
    fig = px.pie(counts, names=Col.ATTACK_TYPE, values=Col.PACKET_COUNT,
                 title='Phân Loại Tấn Công Flood & DoS',
                 hole=0.4,
                 template='plotly_dark',
                 color_discrete_sequence=['#dc2626', '#ea580c', '#d97706', '#7c3aed', '#0284c7'])
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def plot_external_ips_stats(external_df, top_n=10, metric='Total Packets'):
    """
    Vẽ biểu đồ hình thanh (Horizontal Bar Chart) thống kê Top N IP bên ngoài.
    Hỗ trợ xếp hạng theo 'Total Packets', 'Connection Count' hoặc 'SYN Count', tô màu theo Trạng thái.
    """
    if external_df is None or external_df.empty or Col.EXTERNAL_IP not in external_df.columns:
        return None
        
    metric_col = metric if metric in external_df.columns else Col.TOTAL_PACKETS
    if metric_col not in external_df.columns:
        return None
        
    top_df = external_df.sort_values(by=metric_col, ascending=False).head(top_n).copy()
    if top_df.empty:
        return None

    status_color_map = {
        'Tin cậy': '#10b981',
        'Chưa xác minh': '#3b82f6',
        'Đáng ngờ': '#ef4444'
    }
    
    if metric_col == Col.TOTAL_PACKETS:
        metric_title = "Số Lượng Gói Tin"
    elif metric_col == Col.SYN_COUNT:
        metric_title = "Số Gói SYN"
    else:
        metric_title = "Số Lượng Kết Nối (Flows)"
    
    fig = px.bar(
        top_df,
        x=metric_col,
        y=Col.EXTERNAL_IP,
        orientation='h',
        text_auto=True,
        title=f'Top {min(top_n, len(top_df))} IP Public Bên Ngoài (Theo {metric_title})',
        template='plotly_dark',
        color=Col.STATUS if Col.STATUS in top_df.columns else None,
        color_discrete_map=status_color_map,
        hover_data=[c for c in [Col.DIRECTION, Col.INTERNAL_IP, Col.PROTOCOLS, Col.RISK_LEVEL, Col.FLAG_REASON] if c in top_df.columns]
    )
    fig.update_layout(
        yaxis=dict(autorange="reversed"),
        xaxis_title=metric_title,
        yaxis_title="Địa Chỉ IP Bên Ngoài"
    )
    return fig

def plot_external_status_distribution(external_df):
    """
    Vẽ biểu đồ tròn/donut thể hiện tỷ lệ phân loại trạng thái IP bên ngoài (Tin cậy, Chưa xác minh, Đáng ngờ).
    """
    if external_df is None or external_df.empty or Col.STATUS not in external_df.columns:
        return None
        
    counts = external_df[Col.STATUS].value_counts().reset_index()
    if counts.empty:
        return None
    counts.columns = ['Status', 'Count']
    
    status_color_map = {
        'Tin cậy': '#10b981',
        'Chưa xác minh': '#3b82f6',
        'Đáng ngờ': '#ef4444'
    }
    
    fig = px.pie(
        counts,
        names='Status',
        values='Count',
        title='Phân Bổ Trạng Thái IP Bên Ngoài',
        hole=0.45,
        template='plotly_dark',
        color='Status',
        color_discrete_map=status_color_map
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def plot_external_direction_distribution(external_df):
    """
    Vẽ biểu đồ donut thể hiện tỷ lệ hướng kết nối (Outbound, Inbound, Không xác định).
    """
    if external_df is None or external_df.empty or Col.DIRECTION not in external_df.columns:
        return None
        
    counts = external_df[Col.DIRECTION].value_counts().reset_index()
    if counts.empty:
        return None
    counts.columns = ['Direction', 'Count']
    
    dir_color_map = {
        'Outbound': '#0284c7',
        'Inbound': '#f59e0b',
        'Không xác định': '#64748b'
    }
    
    fig = px.pie(
        counts,
        names='Direction',
        values='Count',
        title='Phân Bổ Hướng Kết Nối',
        hole=0.45,
        template='plotly_dark',
        color='Direction',
        color_discrete_map=dir_color_map
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig
