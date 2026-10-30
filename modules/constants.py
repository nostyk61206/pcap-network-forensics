from dataclasses import dataclass

@dataclass(frozen=True)
class Col:
    """Tên các cột chuẩn hóa trong DataFrame gói tin và phân tích an ninh."""
    # Các cột cơ sở trích xuất từ PCAP
    TIMESTAMP = 'Timestamp'
    SOURCE_IP = 'Source IP'
    DEST_IP = 'Dest IP'
    SOURCE_PORT = 'Source Port'
    DEST_PORT = 'Dest Port'
    PROTOCOL = 'Protocol'
    LENGTH = 'Length'
    INFO = 'Info'
    TCP_FLAGS = 'TCP_Flags'
    HTTP_METHOD = 'HTTP_Method'
    HTTP_URI = 'HTTP_URI'
    HTTP_BODY = 'HTTP_Body'
    HTTP_UA = 'HTTP_UA'
    HTTP_HOST = 'HTTP_Host'
    TLS_SNI = 'TLS_SNI'

    # Các cột kết quả phân tích
    SCANNED_PORTS_COUNT = 'Scanned Ports Count'
    TOTAL_PACKETS = 'Total Packets'
    TARGETED_PORTS = 'Targeted Ports'
    SCAN_TYPE = 'Scan Type'
    FIRST_SEEN = 'First Seen'
    LAST_SEEN = 'Last Seen'
    ATTACK_CATEGORY = 'Attack Category'
    IP = 'IP'
    THREAT_CATEGORY = 'Threat Category'
    HIT_COUNT = 'Hit Count'
    TARGETED_VECTORS = 'Targeted Vectors'
    RISK_LEVEL = 'Risk Level'
    DOMAIN = 'Domain'
    DOMAIN_LENGTH = 'Domain_Length'
    ENTROPY = 'Entropy'
    DIRECTION = 'Direction'
    CLASSIFICATION = 'Classification'
    TARGET_PORT = 'Target Port'
    TARGET_SERVICE = 'Target Service'
    ATTACK_TYPE = 'Attack Type'
    PACKET_COUNT = 'Packet Count'
    DURATION_S = 'Duration (s)'
    AVG_RATE = 'Rate (pkts/s)'
    PEAK_PPS = 'Peak (pkts/s)'

    # Các cột phân tích kết nối IP lạ / IP bên ngoài (External Connections)
    EXTERNAL_IP = 'External IP'
    INTERNAL_IP = 'Internal IP'
    PROTOCOLS = 'Protocols'
    SOURCE_PORTS = 'Source Ports'
    DEST_PORTS = 'Dest Ports'
    TOTAL_BYTES = 'Total Bytes'
    CONNECTION_COUNT = 'Connection Count'
    SYN_COUNT = 'SYN Count'
    DOMAIN_SNI = 'Domain / SNI'
    GEO_LOCATION = 'Location'
    STATUS = 'Status'
    FLAG_REASON = 'Flag Reason'

# Schema danh sách cột cho các DataFrame phân tích
PORT_SCAN_COLUMNS = [
    Col.SOURCE_IP, Col.DEST_IP, Col.SCANNED_PORTS_COUNT, Col.TOTAL_PACKETS, 
    Col.TARGETED_PORTS, Col.SCAN_TYPE, Col.FIRST_SEEN, Col.LAST_SEEN
]

WEB_ATTACK_COLUMNS = [
    Col.TIMESTAMP, Col.SOURCE_IP, Col.DEST_IP, 
    'Method', 'URI', Col.ATTACK_CATEGORY, 'User-Agent'
]

THREAT_IP_COLUMNS = [
    Col.IP, Col.THREAT_CATEGORY, Col.HIT_COUNT, 
    Col.TARGETED_VECTORS, Col.RISK_LEVEL
]

DNS_COLUMNS = [
    Col.TIMESTAMP, Col.SOURCE_IP, Col.DEST_IP, Col.SOURCE_PORT, 
    Col.DEST_PORT, Col.DOMAIN, Col.DOMAIN_LENGTH, Col.ENTROPY, 
    Col.DIRECTION, Col.CLASSIFICATION
]

DOS_BRUTEFORCE_COLUMNS = [
    Col.SOURCE_IP, Col.TARGET_PORT, Col.TARGET_SERVICE, Col.ATTACK_TYPE, 
    Col.PACKET_COUNT, Col.DURATION_S, Col.AVG_RATE, Col.PEAK_PPS, Col.RISK_LEVEL, 
    Col.FIRST_SEEN, Col.LAST_SEEN
]

TLS_SNI_COLUMNS = [
    Col.TIMESTAMP, Col.SOURCE_IP, Col.DEST_IP, 
    Col.TLS_SNI, Col.ENTROPY, Col.CLASSIFICATION
]

EXTERNAL_CONNECTION_COLUMNS = [
    Col.EXTERNAL_IP,
    Col.INTERNAL_IP,
    Col.DIRECTION,
    Col.PROTOCOLS,
    Col.SOURCE_PORTS,
    Col.DEST_PORTS,
    Col.TARGETED_PORTS,
    Col.TOTAL_PACKETS,
    Col.TOTAL_BYTES,
    Col.CONNECTION_COUNT,
    Col.SYN_COUNT,
    Col.FIRST_SEEN,
    Col.LAST_SEEN,
    Col.DOMAIN_SNI,
    Col.GEO_LOCATION,
    Col.STATUS,
    Col.RISK_LEVEL,
    Col.FLAG_REASON
]

