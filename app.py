import streamlit as st  # type: ignore
import pandas as pd  # type: ignore
import plotly.express as px  # type: ignore
import os
import datetime
import hashlib
import ipaddress

# Cấu hình giao diện Streamlit
st.set_page_config(
    page_title="PCAP Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

from assets.custom_style import apply_custom_theme
from modules.constants import Col, EXTERNAL_CONNECTION_COLUMNS
from modules.pcap_parser import load_pcap, detect_server_ip, get_parser_stats
from modules.security import (
    detect_port_scan, 
    detect_dos_bruteforce,
    detect_suspicious_tls_sni,
    detect_abnormal_dns, 
    detect_web_attacks, 
    detect_suspicious_ips,
    build_external_connection_summary,
    classify_external_connections,
    enrich_external_connections_geoip,
    detect_external_connections,
    parse_ip_or_network_list
)
from modules.visualization import (
    plot_protocol_stats, 
    plot_time_flow, 
    plot_top_ips, 
    plot_geoip_map,
    plot_web_attacks_stats,
    plot_web_attack_uris,
    plot_tls_sni_stats,
    plot_tls_classification,
    plot_dos_bruteforce_stats,
    plot_scanned_ports_stats,
    plot_threat_categories,
    plot_dns_distribution,
    plot_external_ips_stats,
    plot_external_status_distribution,
    plot_external_direction_distribution
)
from modules.rules_config import DEFAULT_ALLOWLIST
from modules.report_gen import generate_pdf_report, generate_html_report
from modules.state_utils import (
    compute_file_id,
    make_server_ip_widget_key,
    reset_file_scoped_state,
    validate_ip_address
)

# Áp dụng bộ giao diện
apply_custom_theme()

# Cache phân tích độc lập theo nhu cầu (On-Demand Execution)
@st.cache_data(show_spinner=False)
def get_port_scans(df, server_ip, port_threshold=7):
    return detect_port_scan(df, server_ip=server_ip, port_threshold=port_threshold)

@st.cache_data(show_spinner=False)
def get_dos(df, server_ip):
    return detect_dos_bruteforce(df, server_ip=server_ip)

@st.cache_data(show_spinner=False)
def get_tls(df, server_ip):
    return detect_suspicious_tls_sni(df, server_ip=server_ip)

@st.cache_data(show_spinner=False)
def get_dns(df, server_ip):
    return detect_abnormal_dns(df, server_ip=server_ip)

@st.cache_data(show_spinner=False)
def get_web_attacks(df, server_ip):
    return detect_web_attacks(df, server_ip=server_ip)

@st.cache_data(show_spinner=False)
def get_threat_ips(df, server_ip, port_scans_df, web_attacks_df, dns_results, dos_df, tls_df):
    return detect_suspicious_ips(
        df, 
        server_ip=server_ip, 
        port_scans_df=port_scans_df, 
        web_attacks_df=web_attacks_df, 
        dns_results=dns_results,
        dos_df=dos_df,
        tls_df=tls_df
    )

@st.cache_data(show_spinner=False)
def analyze_threats(df, server_ip, port_threshold=7):
    """Phân tích các hành vi tấn công mạng cốt lõi (tương thích ngược)."""
    port_scans = get_port_scans(df, server_ip, port_threshold)
    dos_df = get_dos(df, server_ip)
    tls_df = get_tls(df, server_ip)
    dns_res = get_dns(df, server_ip)
    web_atk = get_web_attacks(df, server_ip)
    threat_ips = get_threat_ips(df, server_ip, port_scans, web_atk, dns_res, dos_df, tls_df)
    return port_scans, dos_df, tls_df, dns_res, web_atk, threat_ips

# Cache tổng hợp lưu lượng IP bên ngoài
@st.cache_data(show_spinner=False)
def get_external_summary(_df, server_ip=None, file_hash=None):
    """Trích xuất và tổng hợp lưu lượng với IP bên ngoài."""
    return build_external_connection_summary(_df, server_ip=server_ip)

# Cache phân loại IP bên ngoài (chỉ chạy lại khi Allowlist/Blocklist thay đổi)
@st.cache_data(show_spinner=False)
def get_classified_external(_summary_df, allowlist_tuple, blocklist_tuple, _threat_ips_df=None, _tls_df=None, _dns_results=None, server_ip=None, file_hash=None):
    """Phân loại IP bên ngoài theo quy tắc và bằng chứng đe dọa."""
    return classify_external_connections(
        _summary_df,
        allowlist=allowlist_tuple,
        blocklist=blocklist_tuple,
        threat_ips_df=_threat_ips_df,
        tls_df=_tls_df,
        dns_results=_dns_results,
        server_ip=server_ip
    )

# Cache bổ sung GeoIP
@st.cache_data(show_spinner=False)
def get_enriched_external(_classified_df, file_hash=None):
    """Bổ sung vị trí địa lý cho danh sách IP bên ngoài."""
    return enrich_external_connections_geoip(_classified_df)

def analyze_all(df, server_ip, port_threshold=7, allowlist_tuple=None, blocklist_tuple=None, file_hash=None):
    """Hàm tổng hợp kết hợp các bước phân tích có cache riêng biệt."""
    port_scans, dos_df, tls_df, dns_res, web_atk, threat_ips = analyze_threats(df, server_ip, port_threshold)
    summary_df = get_external_summary(df, server_ip=server_ip, file_hash=file_hash)
    classified_df = get_classified_external(summary_df, allowlist_tuple, blocklist_tuple, threat_ips, tls_df, dns_res, server_ip=server_ip, file_hash=file_hash)
    external_df = get_enriched_external(classified_df, file_hash=file_hash)
    return port_scans, dos_df, tls_df, dns_res, web_atk, threat_ips, external_df

# Cache quá trình tuần tự hóa dữ liệu CSV và JSON
@st.cache_data(show_spinner=False)
def _serialize_to_csv(df_to_export):
    return df_to_export.to_csv(index=False).encode('utf-8')

@st.cache_data(show_spinner=False)
def _serialize_to_json(df_to_export):
    indent_val = 2 if len(df_to_export) <= 200 else None
    return df_to_export.to_json(orient='records', force_ascii=False, indent=indent_val, date_format='iso').encode('utf-8')

def render_export_buttons(df_to_export, filename_prefix):
    """Tiện ích kết xuất dữ liệu CSV và JSON cho từng bảng phân tích."""
    if df_to_export is None or df_to_export.empty:
        return
    c_exp1, c_exp2 = st.columns(2)
    with c_exp1:
        csv_data = _serialize_to_csv(df_to_export)
        st.download_button(
            label="📥 Xuất Bảng CSV",
            data=csv_data,
            file_name=f"{filename_prefix}.csv",
            mime="text/csv",
            key=f"csv_{filename_prefix}"
        )
    with c_exp2:
        json_data = _serialize_to_json(df_to_export)
        st.download_button(
            label="📥 Xuất Tệp JSON",
            data=json_data,
            file_name=f"{filename_prefix}.json",
            mime="application/json",
            key=f"json_{filename_prefix}"
        )

def render_overview(df, duration, port_scans_df, dos_df, web_attacks_df):
    """Tab 1: Tổng Quan Lưu Lượng & Đe Dọa."""
    col_left, col_right = st.columns(2)
    with col_left:
        fig_proto = plot_protocol_stats(df)
        if fig_proto:
            st.plotly_chart(fig_proto, use_container_width=True)
        else:
            st.info("ℹ️ Không đủ dữ liệu giao thức mạng.")
    with col_right:
        freq = "1h" if duration.days >= 1 else ("1min" if duration.seconds >= 60 else "1s")
        fig_flow = plot_time_flow(df, freq=freq)
        if fig_flow:
            st.plotly_chart(fig_flow, use_container_width=True)
        else:
            st.info("ℹ️ Không có dữ liệu mốc thời gian.")
            
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        fig_web_cats = plot_web_attacks_stats(web_attacks_df)
        if fig_web_cats:
            st.plotly_chart(fig_web_cats, use_container_width=True)
        else:
            st.success("🟢 **Lưu Lượng Web:** An Toàn — Không phát hiện tấn công Web.")
    with col_b2:
        if not dos_df.empty:
            fig_dos = plot_dos_bruteforce_stats(dos_df)
            if fig_dos:
                st.plotly_chart(fig_dos, use_container_width=True)
        elif not port_scans_df.empty:
            fig_ports = plot_scanned_ports_stats(port_scans_df, top_n=8)
            if fig_ports:
                st.plotly_chart(fig_ports, use_container_width=True)
        else:
            st.success("🟢 **Hoạt Động Cổng Mạng:** An Toàn — Không ghi nhận quét cổng.")

def render_port_scan(port_scans_df):
    """Tab 2: Phân Tích Port Scan."""
    if not port_scans_df.empty:
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            fig_ports = plot_scanned_ports_stats(port_scans_df, top_n=10)
            if fig_ports:
                st.plotly_chart(fig_ports, use_container_width=True)
        with col_p2:
            top_scanners = port_scans_df.head(10)
            fig_scanners = px.bar(
                top_scanners, x='Scanned Ports Count', y='Source IP', orientation='h', text_auto=True,
                title='Top 10 Port Scanner', template='plotly_dark',
                color='Scanned Ports Count', color_continuous_scale='Reds'
            )
            fig_scanners.update_layout(
                yaxis=dict(autorange="reversed"),
                xaxis_title="Số cổng bị quét",
                yaxis_title="Địa chỉ IP Nguồn"
            )
            st.plotly_chart(fig_scanners, use_container_width=True)
            
        display_cols = [c for c in ['Source IP', 'Dest IP', 'Scanned Ports Count', 'Total Packets', 'Targeted Ports', 'Scan Type', 'First Seen', 'Last Seen'] if c in port_scans_df.columns]
        st.dataframe(port_scans_df[display_cols], use_container_width=True)
        render_export_buttons(port_scans_df, "port_scans")
    else:
        st.success("✅ **Không phát hiện hành vi quét cổng** trong tệp PCAP này.")

def render_web_attack(web_attacks_df, tls_df):
    """Tab 3: Tấn Công Web & Phân Tích HTTPS (TLS SNI)."""
    tab_web, tab_tls = st.tabs(["🛑 Web Attack", "🔒 HTTPS (TLS SNI)"])
    
    with tab_web:
        if not web_attacks_df.empty:
            col_w1, col_w2 = st.columns(2)
            with col_w1:
                fig_web = plot_web_attacks_stats(web_attacks_df)
                if fig_web:
                    st.plotly_chart(fig_web, use_container_width=True)
            with col_w2:
                fig_uris = plot_web_attack_uris(web_attacks_df, top_n=10)
                if fig_uris:
                    st.plotly_chart(fig_uris, use_container_width=True)
                    
            st.dataframe(web_attacks_df[['Timestamp', 'Source IP', 'Method', 'URI', 'Attack Category', 'User-Agent']], use_container_width=True)
            render_export_buttons(web_attacks_df, "web_attacks")
        else:
            st.success("✅ **Không ghi nhận tấn công ứng dụng Web** (Thử lỗ hổng, RCE, Đọc trộm tệp, SQLi hoặc Công cụ quét tự động).")
            
    with tab_tls:
        if not tls_df.empty:
            col_tls1, col_tls2 = st.columns(2)
            with col_tls1:
                fig_tls = plot_tls_sni_stats(tls_df, top_n=10)
                if fig_tls:
                    st.plotly_chart(fig_tls, use_container_width=True)
            with col_tls2:
                fig_tls_cat = plot_tls_classification(tls_df)
                if fig_tls_cat:
                    st.plotly_chart(fig_tls_cat, use_container_width=True)
                
            st.dataframe(tls_df[['Timestamp', 'Source IP', 'Dest IP', 'TLS_SNI', 'Entropy', 'Classification']], use_container_width=True)
            render_export_buttons(tls_df, "tls_sni_domains")
        else:
            st.info("ℹ️ Không phát hiện gói tin bắt tay TLS ClientHello (HTTPS SNI) trong tệp này.")

def render_dos(dos_df):
    """Tab 4: Flood & DoS / Connection Attempts."""
    st.subheader("💥 Phân Tích Flood & DoS / Connection Attempts")
    if not dos_df.empty:
        col_dos1, col_dos2 = st.columns(2)
        with col_dos1:
            fig_dos_pie = plot_dos_bruteforce_stats(dos_df)
            if fig_dos_pie:
                st.plotly_chart(fig_dos_pie, use_container_width=True)
        with col_dos2:
            fig_dos_bar = px.bar(
                dos_df.head(10), x='Packet Count', y='Source IP', orientation='h', text_auto=True,
                color='Risk Level', color_discrete_map={'Cao': '#ef4444', 'Trung bình': '#f59e0b'},
                title='Top Nguồn Tấn Công Flood / DoS', template='plotly_dark'
            )
            fig_dos_bar.update_layout(
                yaxis=dict(autorange="reversed"),
                xaxis_title="Số lượng gói tin",
                yaxis_title="Địa chỉ IP Nguồn"
            )
            st.plotly_chart(fig_dos_bar, use_container_width=True)
            
        dos_cols = [c for c in ['Source IP', 'Target Port', 'Target Service', 'Attack Type', 'Packet Count', 'Duration (s)', 'Rate (pkts/s)', 'Peak (pkts/s)', 'Risk Level'] if c in dos_df.columns]
        st.dataframe(dos_df[dos_cols], use_container_width=True)
        render_export_buttons(dos_df, "dos_flood_events")
    else:
        st.success("✅ **Không phát hiện hành vi Flooding (TCP/UDP/ICMP) hoặc Kết nối dồn dập khả nghi** vào các dịch vụ đơn lẻ.")

def render_dns(dns_results):
    """Tab 5: Phân Tích DNS Tunneling & Probes."""
    all_dns = dns_results.get('all_queries', pd.DataFrame())
    if not all_dns.empty:
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            fig_dns = plot_dns_distribution(dns_results)
            if fig_dns:
                st.plotly_chart(fig_dns, use_container_width=True)
        with col_d2:
            if 'Domain_Length' in all_dns.columns and 'Entropy' in all_dns.columns:
                fig_entropy = px.scatter(
                    all_dns, x='Domain_Length', y='Entropy', color='Classification',
                    hover_data=['Domain', 'Source IP'],
                    title='Entropy vs Domain Length',
                    template='plotly_dark'
                )
                fig_entropy.update_layout(
                    xaxis_title="Độ dài tên miền",
                    yaxis_title="Độ hỗn loạn Shannon Entropy"
                )
                st.plotly_chart(fig_entropy, use_container_width=True)
                
        st.dataframe(all_dns[['Timestamp', 'Source IP', 'Dest IP', 'Domain', 'Entropy', 'Classification']], use_container_width=True)
        render_export_buttons(all_dns, "dns_queries")
    else:
        st.info("ℹ️ **Không ghi nhận lưu lượng truy vấn DNS** nào trong tệp PCAP này.")

def render_external_connections(external_df, df):
    """Tab: Kết Nối Đến IP Bên Ngoài."""
    st.subheader("🌐 Phân Tích Kết Nối Đến IP Bên Ngoài")
    st.caption("Thống kê và đánh giá các kết nối giữa mạng nội bộ và địa chỉ IP public bên ngoài.")

    if external_df is None or external_df.empty:
        st.info("ℹ️ Không tìm thấy kết nối đến IP public trong tệp này.")
        return

    # 1. Thẻ chỉ số tổng quan
    total_ext = len(external_df)
    trusted_count = len(external_df[external_df[Col.STATUS] == 'Tin cậy']) if Col.STATUS in external_df.columns else 0
    unverified_count = len(external_df[external_df[Col.STATUS] == 'Chưa xác minh']) if Col.STATUS in external_df.columns else 0
    suspicious_count = len(external_df[external_df[Col.STATUS] == 'Đáng ngờ']) if Col.STATUS in external_df.columns else 0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🌐 Tổng IP Bên Ngoài", f"{total_ext:,}")
    m2.metric("🛡️ Tin Cậy", f"{trusted_count:,}")
    m3.metric("❓ Chưa Xác Minh", f"{unverified_count:,}")
    m4.metric("⚠️ Đáng Ngờ", f"{suspicious_count:,}")

    st.markdown("---")

    # 2. Bộ lọc tương tác
    st.markdown("##### 🔍 Bộ Lọc Dữ Liệu")
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        status_opts = ["Tất cả"] + [s for s in ['Đáng ngờ', 'Chưa xác minh', 'Tin cậy'] if s in external_df[Col.STATUS].values]
        sel_status = st.selectbox("Trạng thái:", status_opts, key="filter_ext_status")
    with f_col2:
        dir_opts = ["Tất cả"] + [d for d in ['Outbound', 'Inbound', 'Không xác định'] if d in external_df[Col.DIRECTION].values]
        sel_dir = st.selectbox("Hướng kết nối:", dir_opts, key="filter_ext_dir")
    with f_col3:
        risk_opts = ["Tất cả"] + [r for r in ['Cao', 'Trung bình', 'Thấp', 'An toàn'] if r in external_df[Col.RISK_LEVEL].values]
        sel_risk = st.selectbox("Mức rủi ro:", risk_opts, key="filter_ext_risk")
    with f_col4:
        all_protos = set()
        for p_str in external_df[Col.PROTOCOLS].dropna().unique():
            for p in str(p_str).split(','):
                p_clean = p.strip()
                if p_clean:
                    all_protos.add(p_clean)
        proto_opts = ["Tất cả"] + sorted(list(all_protos))
        sel_proto = st.selectbox("Giao thức:", proto_opts, key="filter_ext_proto")

    # Áp dụng bộ lọc
    filtered_df = external_df
    if sel_status != "Tất cả":
        filtered_df = filtered_df[filtered_df[Col.STATUS] == sel_status]
    if sel_dir != "Tất cả":
        filtered_df = filtered_df[filtered_df[Col.DIRECTION] == sel_dir]
    if sel_risk != "Tất cả":
        filtered_df = filtered_df[filtered_df[Col.RISK_LEVEL] == sel_risk]
    if sel_proto != "Tất cả":
        filtered_df = filtered_df[filtered_df[Col.PROTOCOLS].astype(str).str.contains(sel_proto, regex=False, na=False)]

    # 3. Biểu đồ trực quan hóa
    st.markdown("##### 📊 Trực Quan Hóa")
    c_chart1, c_chart2 = st.columns(2)
    with c_chart1:
        chart_metric = st.radio(
            "Tiêu chí xếp hạng:",
            ["Số Gói Tin", "Số Kết Nối (Flows)", "Số SYN"],
            horizontal=True,
            key="radio_chart_metric"
        )
        if chart_metric == "Số Gói Tin":
            metric_key = Col.TOTAL_PACKETS
        elif chart_metric == "Số SYN":
            metric_key = Col.SYN_COUNT
        else:
            metric_key = Col.CONNECTION_COUNT

        fig_bar = plot_external_ips_stats(filtered_df, top_n=10, metric=metric_key)
        if fig_bar:
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("ℹ️ Không đủ dữ liệu để vẽ biểu đồ thanh.")

    with c_chart2:
        chart_pie_type = st.radio(
            "Biểu đồ phân bổ:",
            ["Phân Bổ Trạng Thái", "Phân Bổ Hướng Kết Nối"],
            horizontal=True,
            key="radio_pie_type"
        )
        if chart_pie_type == "Phân Bổ Trạng Thái":
            fig_pie = plot_external_status_distribution(filtered_df)
        else:
            fig_pie = plot_external_direction_distribution(filtered_df)
        if fig_pie:
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("ℹ️ Không đủ dữ liệu để vẽ biểu đồ phân bổ.")

    # 4. Bảng chi tiết kết quả
    st.markdown(f"##### 📋 Chi Tiết Kết Nối IP Bên Ngoài ({len(filtered_df):,} địa chỉ IP)")
    display_cols = [
        Col.EXTERNAL_IP, Col.INTERNAL_IP, Col.DIRECTION, Col.PROTOCOLS,
        Col.TARGETED_PORTS, Col.TOTAL_PACKETS, Col.TOTAL_BYTES, 
        Col.CONNECTION_COUNT, Col.SYN_COUNT,
        Col.FIRST_SEEN, Col.LAST_SEEN, Col.DOMAIN_SNI, Col.GEO_LOCATION,
        Col.STATUS, Col.RISK_LEVEL, Col.FLAG_REASON
    ]
    avail_cols = [c for c in display_cols if c in filtered_df.columns]
    
    if len(filtered_df) > 500:
        st.caption(f"⚡ Đang hiển thị 500 / {len(filtered_df):,} địa chỉ IP đầu tiên theo mức độ ưu tiên rủi ro. Xuất CSV hoặc JSON để xem toàn bộ danh sách.")
        display_tbl = filtered_df[avail_cols].head(500)
    else:
        display_tbl = filtered_df[avail_cols]
        
    st.dataframe(display_tbl, use_container_width=True)
    render_export_buttons(filtered_df, "external_connections")

def render_threat_ip(threat_ips_df):
    """Tab 6: Hồ Sơ IP Đe Dọa (Threat IP Profiling)."""
    if not threat_ips_df.empty:
        col_t1, col_t2 = st.columns(2)
        with col_t1:
            fig_threat_cats = plot_threat_categories(threat_ips_df)
            if fig_threat_cats:
                st.plotly_chart(fig_threat_cats, use_container_width=True)
        with col_t2:
            top_threats = threat_ips_df.head(10)
            fig_top_threats = px.bar(
                top_threats, x='Hit Count', y='IP', orientation='h', text_auto=True,
                title='Top 10 Threat IP',
                template='plotly_dark', color='Risk Level',
                color_discrete_map={'Cao': '#ef4444', 'Trung bình': '#f59e0b'}
            )
            fig_top_threats.update_layout(
                yaxis=dict(autorange="reversed"),
                xaxis_title="Tổng số lần vi phạm",
                yaxis_title="Địa chỉ IP"
            )
            st.plotly_chart(fig_top_threats, use_container_width=True)
            
        st.dataframe(threat_ips_df[['IP', 'Threat Category', 'Hit Count', 'Targeted Vectors', 'Risk Level']], use_container_width=True)
        render_export_buttons(threat_ips_df, "threat_ips")
    else:
        st.success("✅ **Không phát hiện địa chỉ IP nào có hành vi đe dọa an ninh.**")

def render_traffic(df, duration):
    """Tab 7: Thống Kê Giao Thức & Lưu Lượng."""
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        fig_src, fig_dst = plot_top_ips(df, top_n=10)
        if fig_src: st.plotly_chart(fig_src, use_container_width=True)
    with col_f2:
        if fig_dst: st.plotly_chart(fig_dst, use_container_width=True)
        
    freq = "1h" if duration.days >= 1 else ("1min" if duration.seconds >= 60 else "1s")
    fig_timeline = plot_time_flow(df, freq=freq)
    if fig_timeline:
        st.plotly_chart(fig_timeline, use_container_width=True)

def render_geomap(df, threat_ips_df=None):
    """Tab 8: Bản Đồ Địa Lý IP."""
    st.subheader("🗺️ Bản Đồ Địa Lý IP")
    possible_paths = [
        "data/GeoLite2-City.mmdb",
        "./GeoLite2-City.mmdb"
    ]
    default_db = next((p for p in possible_paths if os.path.exists(p)), possible_paths[0])
    db_path = st.text_input("Đường dẫn tệp cơ sở dữ liệu GeoLite2-City.mmdb:", value=default_db)
    
    target_df = df
    if threat_ips_df is not None and not threat_ips_df.empty:
        map_mode = st.radio(
            "Chọn tập dữ liệu hiển thị trên bản đồ:",
            ["🦹 Địa chỉ IP đe dọa (Threat Actors)", "🌐 Tất cả IP nguồn"],
            horizontal=True
        )
        if map_mode == "🦹 Địa chỉ IP đe dọa (Threat Actors)":
            target_df = threat_ips_df

    if os.path.exists(db_path):
        fig_map = plot_geoip_map(target_df, db_path)
        if fig_map:
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("ℹ️ Không tìm thấy toạ độ địa lý hợp lệ cho các IP trong tệp này (có thể là dải IP mạng nội bộ Private/LAN).")
    else:
        st.warning(f"⚠️ Chưa tìm thấy cơ sở dữ liệu GeoLite2-City tại: `{db_path}`. Vui lòng tải file `GeoLite2-City.mmdb` đặt vào thư mục `data/`.")

def render_raw_data(df):
    """Tab 9: Xem Dữ Liệu Gói Tin Thô."""
    st.caption(f"⚡ Đang hiển thị 1,000 gói tin đầu tiên (Tổng: {len(df):,} gói). Bấm nút 'Xuất Bảng CSV' bên dưới để tải toàn bộ dữ liệu.")
    display_df = df.head(1000)
    st.dataframe(display_df[['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Length', 'Info']], use_container_width=True)
    render_export_buttons(df, "raw_packets")

def render_report(uploaded_file, df, duration, server_ip, port_scans_df, web_attacks_df, dos_df, tls_df, dns_results, threat_ips_df, external_df=None, file_hash=None):
    """Tab 10: Xuất Báo Cáo PDF / HTML."""
    st.subheader("📑 Xuất Báo Cáo PDF")
    st.markdown("Xuất báo cáo an ninh mạng định dạng PDF hoặc HTML độc lập.")
    
    # Đồng bộ ngữ cảnh báo cáo theo mã tệp và Server IP hiện tại
    current_file_id = file_hash or getattr(uploaded_file, '_file_id', None) or f"{uploaded_file.name}_{getattr(uploaded_file, 'size', 0)}"
    reset_file_scoped_state(st.session_state, current_file_id, server_ip=server_ip)

    report_data = {
        'filename': uploaded_file.name,
        'server_ip': server_ip or "Chưa rõ",
        'report_date': datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        'total_packets': len(df),
        'port_scans': port_scans_df,
        'web_attacks': web_attacks_df,
        'dos_bruteforce': dos_df,
        'tls_sni': tls_df,
        'dns_probes': dns_results.get('inbound_probes', pd.DataFrame()) if dns_results else pd.DataFrame(),
        'dns_tunneling': dns_results.get('outbound_tunneling', pd.DataFrame()) if dns_results else pd.DataFrame(),
        'threat_ips': threat_ips_df,
        'external_connections': external_df
    }
    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'report_template.html')
    
    if st.button("🚀 Tạo Báo Cáo PDF", type="primary"):
        with st.spinner("Đang tổng hợp dữ liệu và sinh file PDF..."):
            try:
                figures = {
                    'protocol': plot_protocol_stats(df),
                    'time': plot_time_flow(df, freq='1h' if duration.days >= 1 else '1min'),
                    'web_attacks': plot_web_attacks_stats(web_attacks_df),
                    'dos': plot_dos_bruteforce_stats(dos_df) if not dos_df.empty else None,
                    'external_connections': plot_external_ips_stats(external_df) if external_df is not None and not external_df.empty else None
                }
                pdf_bytes = generate_pdf_report(template_path, report_data, figures)
                st.session_state['generated_pdf'] = pdf_bytes
                st.session_state['generated_pdf_name'] = f"{os.path.splitext(uploaded_file.name)[0]}_Bao_Cao_An_Ninh.pdf"
                st.session_state.pop('generated_html', None)
                st.session_state.pop('generated_html_name', None)
            except Exception as e:
                st.warning(f"Lưu ý: {e}. Tự động sinh báo cáo HTML độc lập thay thế.")
                figures = {
                    'protocol': plot_protocol_stats(df),
                    'time': plot_time_flow(df, freq='1h' if duration.days >= 1 else '1min'),
                    'web_attacks': plot_web_attacks_stats(web_attacks_df),
                    'dos': plot_dos_bruteforce_stats(dos_df) if not dos_df.empty else None,
                    'external_connections': plot_external_ips_stats(external_df) if external_df is not None and not external_df.empty else None
                }
                html_content = generate_html_report(template_path, report_data, figures)
                st.session_state['generated_html'] = html_content.encode('utf-8')
                st.session_state['generated_html_name'] = f"{os.path.splitext(uploaded_file.name)[0]}_Bao_Cao_An_Ninh.html"
                st.session_state.pop('generated_pdf', None)
                st.session_state.pop('generated_pdf_name', None)

    # Hiển thị nút tải xuống lưu trạng thái bền vững
    if 'generated_pdf' in st.session_state:
        st.success("✅ Đã tạo file PDF thành công!")
        st.download_button(
            label="📥 Tải Xuống File PDF",
            data=st.session_state['generated_pdf'],
            file_name=st.session_state['generated_pdf_name'],
            mime="application/pdf",
            type="primary"
        )
    elif 'generated_html' in st.session_state:
        st.success("✅ Đã tạo báo cáo HTML thành công!")
        st.download_button(
            label="📥 Tải Báo Cáo HTML (Mở xem & In PDF ngay)",
            data=st.session_state['generated_html'],
            file_name=st.session_state['generated_html_name'],
            mime="text/html",
            type="primary"
        )

class _DemoUploadedFile:
    """Đối tượng giả lập UploadedFile cho chế độ nạp nhanh tệp PCAP mẫu."""
    def __init__(self, name: str, data: bytes):
        self.name = name
        self.size = len(data)
        self._data = data

    def getvalue(self) -> bytes:
        return self._data


def main():
    st.sidebar.title("🛡️ Phân Tích PCAP")
    
    # 1. Tải lên tệp PCAP hoặc chọn tệp mẫu có sẵn
    uploaded_file = st.sidebar.file_uploader("Chọn tệp .pcap hoặc .pcapng:", type=['pcap', 'pcapng'])
    demo_pcap_path = os.path.join(os.path.dirname(__file__), "data", "demo_external.pcap")
    if uploaded_file is None and os.path.exists(demo_pcap_path):
        if st.sidebar.checkbox("🧪 Dùng tệp PCAP mẫu (demo_external.pcap)", value=False):
            with open(demo_pcap_path, "rb") as demo_f:
                uploaded_file = _DemoUploadedFile("demo_external.pcap", demo_f.read())
    
    # Danh mục chức năng 100% Tiếng Việt
    menu = [
        "📊 Tổng Quan",
        "🎯 Port Scan",
        "🌐 Web Attack & HTTPS",
        "💥 Flood & DoS",
        "📡 DNS Tunneling",
        "🌍 Kết Nối IP Lạ",
        "🦹 Threat IP",
        "📈 Giao Thức & Lưu Lượng",
        "🗺️ Bản Đồ Địa Lý",
        "📄 Raw Data",
        "📑 Báo Cáo PDF"
    ]
    
    choice = st.sidebar.radio("Chức Năng Phân Tích", menu)
    
    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Làm Mới Bộ Nhớ Đệm"):
        st.cache_data.clear()
        if 'generated_pdf' in st.session_state:
            del st.session_state['generated_pdf']
        if 'generated_html' in st.session_state:
            del st.session_state['generated_html']
        st.sidebar.success("Đã làm mới bộ nhớ đệm!")
        
    if uploaded_file is not None:
        file_size_mb = getattr(uploaded_file, 'size', 0) / (1024 * 1024)
        if file_size_mb > 200:
            st.error(f"❌ Tệp vượt quá giới hạn an toàn ({file_size_mb:.1f} MB > 200 MB). Vui lòng sử dụng tệp bắt gói nhỏ hơn hoặc lọc bằng tshark/tcpdump trước.")
            return
        elif file_size_mb > 100:
            st.sidebar.warning(f"⚠️ Tệp có kích thước lớn ({file_size_mb:.1f} MB). Quá trình phân tích có thể cần thêm thời gian.")
            
        file_bytes = uploaded_file.getvalue()
        file_hash = compute_file_id(file_bytes)

        # Reset trạng thái khi đổi sang file PCAP khác
        reset_file_scoped_state(st.session_state, file_hash)

        df = load_pcap(file_bytes)
        
        if df.empty:
            st.error("Không tìm thấy dữ liệu gói tin hợp lệ trong tệp.")
            return

        p_stats = get_parser_stats(df)
        st.sidebar.caption(
            f"🔗 **Chuẩn Link-Layer:** `{p_stats.get('datalink_name', 'Ethernet')}` "
            f"({p_stats.get('parsed_packets', len(df)):,}/{p_stats.get('total_packets', len(df)):,} gói IP)"
        )
            
        auto_server_ip = detect_server_ip(df)
        server_ip_raw = st.sidebar.text_input(
            "Địa Chỉ IP Máy Chủ Mục Tiêu (Tùy chọn):",
            value=auto_server_ip or "",
            help="Gợi ý tự động từ lưu lượng gói tin. Có thể sửa hoặc xóa trống nếu không phân tích máy chủ cụ thể.",
            key=make_server_ip_widget_key(file_hash)
        )
        st.sidebar.caption("💡 *Gợi ý tự động từ lưu lượng gói tin. Có thể sửa hoặc xóa trống.*")
        server_ip = server_ip_raw.strip() if server_ip_raw else None
        if server_ip:
            if not validate_ip_address(server_ip):
                st.sidebar.error(f"❌ Địa chỉ IP '{server_ip}' không hợp lệ (không phải IPv4/IPv6 chuẩn). Vui lòng sửa lại hoặc để trống.")
                st.error(f"❌ Địa chỉ IP '{server_ip}' không hợp lệ! Vui lòng nhập đúng định dạng IPv4/IPv6 trên thanh bên trước khi tiếp tục phân tích.")
                return

        # Cấu hình Allowlist / Blocklist IP trong sidebar
        with st.sidebar.expander("⚙️ Cấu Hình Allowlist / Blocklist IP", expanded=False):
            st.caption("Nhập IP hoặc dải CIDR (IPv4/IPv6), phân cách bằng dấu phẩy hoặc xuống dòng.")
            allowlist_raw = st.text_area(
                "Danh Sách Tin Cậy (Allowlist):",
                value=",\n".join(DEFAULT_ALLOWLIST),
                height=90,
                key="cfg_allowlist"
            )
            blocklist_raw = st.text_area(
                "Danh Sách Chặn (Blocklist):",
                value="",
                height=70,
                key="cfg_blocklist"
            )
            allow_nets, allow_errs = parse_ip_or_network_list(allowlist_raw)
            block_nets, block_errs = parse_ip_or_network_list(blocklist_raw)
            if allow_errs:
                st.sidebar.warning(f"⚠️ {len(allow_errs)} mục Allowlist không hợp lệ: {', '.join(e[0] for e in allow_errs[:2])}")
            if block_errs:
                st.sidebar.warning(f"⚠️ {len(block_errs)} mục Blocklist không hợp lệ: {', '.join(e[0] for e in block_errs[:2])}")

        allow_tuple = tuple(str(n) for n in allow_nets) if allow_nets else None
        block_tuple = tuple(str(n) for n in block_nets) if block_nets else None

        # Đồng bộ ngữ cảnh báo cáo khi Server IP thay đổi trên cùng tệp
        reset_file_scoped_state(st.session_state, file_hash, server_ip=server_ip)
        
        # --- THANH CHỈ SỐ NHANH (KPI METRICS) VỚI DỮ LIỆU TỔNG QUAN NHẸ ---
        try:
            ts_clean = df['Timestamp'].dropna()
            if len(ts_clean) >= 2:
                duration = ts_clean.iloc[-1] - ts_clean.iloc[0]
                days = duration.days
                hours = duration.seconds // 3600
                dur_str = f"{days} ngày {hours} giờ" if days > 0 else f"{hours} giờ {duration.seconds%3600//60} phút"
            else:
                duration = datetime.timedelta(seconds=1)
                dur_str = "< 1 phút"
        except Exception:
            duration = datetime.timedelta(seconds=1)
            dur_str = "N/A"
        
        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("📦 Tổng Gói Tin", f"{len(df):,}")
        k2.metric("🖥️ IP Nguồn", f"{df[Col.SOURCE_IP].nunique():,}" if Col.SOURCE_IP in df.columns else "0")
        k3.metric("🌐 IP Đích", f"{df[Col.DEST_IP].nunique():,}" if Col.DEST_IP in df.columns else "0")
        k4.metric("📡 Giao Thức", f"{df[Col.PROTOCOL].nunique():,}" if Col.PROTOCOL in df.columns else "0")
        k5.metric("⏱️ Thời Lượng", dur_str)
        
        st.markdown("---")
        
        # --- ĐIỀU HƯỚNG TỪNG MỤC THEO NHU CẦU (ON-DEMAND EXECUTION) ---
        if choice == "📊 Tổng Quan":
            ps_df = get_port_scans(df, server_ip)
            dos_df = get_dos(df, server_ip)
            web_df = get_web_attacks(df, server_ip)
            render_overview(df, duration, ps_df, dos_df, web_df)
        elif choice == "🎯 Port Scan":
            port_scans_df = get_port_scans(df, server_ip)
            render_port_scan(port_scans_df)
        elif choice == "🌐 Web Attack & HTTPS":
            web_attacks_df = get_web_attacks(df, server_ip)
            tls_df = get_tls(df, server_ip)
            render_web_attack(web_attacks_df, tls_df)
        elif choice == "💥 Flood & DoS":
            dos_df = get_dos(df, server_ip)
            render_dos(dos_df)
        elif choice == "📡 DNS Tunneling":
            dns_results = get_dns(df, server_ip)
            render_dns(dns_results)
        elif choice == "🌍 Kết Nối IP Lạ":
            summary_df = get_external_summary(df, server_ip=server_ip, file_hash=file_hash)
            if summary_df is None or summary_df.empty:
                render_external_connections(pd.DataFrame(columns=EXTERNAL_CONNECTION_COLUMNS), df)
            else:
                ps_df = get_port_scans(df, server_ip)
                dos_df = get_dos(df, server_ip)
                web_df = get_web_attacks(df, server_ip)
                dns_res = get_dns(df, server_ip)
                tls_df = get_tls(df, server_ip)
                threat_ips_df = get_threat_ips(df, server_ip, ps_df, web_df, dns_res, dos_df, tls_df)
                classified_df = get_classified_external(
                    summary_df, allow_tuple, block_tuple, threat_ips_df, tls_df, dns_res, server_ip=server_ip, file_hash=file_hash
                )
                external_df = get_enriched_external(classified_df, file_hash=file_hash)
                render_external_connections(external_df, df)
        elif choice == "🦹 Threat IP":
            ps_df = get_port_scans(df, server_ip)
            dos_df = get_dos(df, server_ip)
            web_df = get_web_attacks(df, server_ip)
            dns_res = get_dns(df, server_ip)
            tls_df = get_tls(df, server_ip)
            threat_ips_df = get_threat_ips(df, server_ip, ps_df, web_df, dns_res, dos_df, tls_df)
            render_threat_ip(threat_ips_df)
        elif choice == "📈 Giao Thức & Lưu Lượng":
            render_traffic(df, duration)
        elif choice == "🗺️ Bản Đồ Địa Lý":
            ps_df = get_port_scans(df, server_ip)
            dos_df = get_dos(df, server_ip)
            web_df = get_web_attacks(df, server_ip)
            dns_res = get_dns(df, server_ip)
            tls_df = get_tls(df, server_ip)
            threat_ips_df = get_threat_ips(df, server_ip, ps_df, web_df, dns_res, dos_df, tls_df)
            render_geomap(df, threat_ips_df=threat_ips_df)
        elif choice == "📄 Raw Data":
            render_raw_data(df)
        elif choice == "📑 Báo Cáo PDF":
            ps_df = get_port_scans(df, server_ip)
            dos_df = get_dos(df, server_ip)
            web_df = get_web_attacks(df, server_ip)
            dns_res = get_dns(df, server_ip)
            tls_df = get_tls(df, server_ip)
            threat_ips_df = get_threat_ips(df, server_ip, ps_df, web_df, dns_res, dos_df, tls_df)
            summary_df = get_external_summary(df, server_ip=server_ip, file_hash=file_hash)
            classified_df = get_classified_external(
                summary_df, allow_tuple, block_tuple, threat_ips_df, tls_df, dns_res, server_ip=server_ip, file_hash=file_hash
            )
            external_df = get_enriched_external(classified_df, file_hash=file_hash)
            render_report(
                uploaded_file, df, duration, server_ip,
                ps_df, web_df, dos_df, tls_df, dns_res, threat_ips_df,
                external_df=external_df,
                file_hash=file_hash
            )
    else:
        st.info("👋 Vui lòng tải lên tệp `.pcap` hoặc `.pcapng` ở thanh bên trái để bắt đầu phân tích dữ liệu.")

if __name__ == "__main__":
    main()
