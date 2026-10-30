import re

PORT_SERVICE_MAP = {
    22: 'SSH',
    21: 'FTP',
    23: 'Telnet',
    3389: 'RDP',
    445: 'SMB / AD',
    139: 'NetBIOS',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    1433: 'MS-SQL',
    1521: 'Oracle DB',
    6379: 'Redis',
    27017: 'MongoDB',
    80: 'HTTP',
    443: 'HTTPS',
    8080: 'HTTP Alt',
    8443: 'HTTPS Alt',
    8000: 'HTTP Alt',
    8888: 'HTTP Alt',
    53: 'DNS',
    25: 'SMTP'
}

WEB_ATTACK_PATTERNS = {
    'Khai Thác Tệp Nhạy Cảm & Cấu Hình (.env/.git)': re.compile(
        r'(?:\.env|\.git|\.aws|\.svn|\.bak|\.old|\.zip|\.tar|\.gz|\.sql|config\.(?:php|json|yml|yaml|inc|ini)|database\.yml|web\.config|\.htpasswd|\.docker|credentials)',
        re.I
    ),
    'Dò Quét Trang Quản Trị & CMS (Admin/Login)': re.compile(
        r'(?:wp-login|wp-admin|phpmyadmin|administrator|manager/html|/admin/|/login|actuator|drupal|joomla|typo3|cpanel|webmin)',
        re.I
    ),
    'Tấn Công Đọc Trộm Tệp (Path Traversal / LFI)': re.compile(
        r'(?:\.\./|\.\.\\|%2e%2e|/etc/passwd|/win\.ini|/boot\.ini|/etc/shadow|pearcmd|php://|file://|/proc/self)',
        re.I
    ),
    'Tấn Công Chèn Mã SQL (SQL Injection)': re.compile(
        r'(?:union.*select|select.*from|information_schema|waitfor.*delay|benchmark\(|\' OR \'1\'=\'1|\' OR 1=1|\-\- | sleep\(|load_file\()',
        re.I
    ),
    'Thực Thi Mã Từ Xa (RCE) & Webshell': re.compile(
        r'(?:eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(|cmd=|/bin/sh|/bin/bash|\.jsp\?|\.action\?|invokefunction|eval-stdin\.php|phpunit|think\\app|call_user_func|\bjndi:|\$\{jndi:)',
        re.I
    ),
    'Khai Thác Thiết Bị IoT & Router': re.compile(
        r'(?:SDK/webLanguage|HNAP1|setup\.cgi|form2user\.cgi|boaform|cgi-bin|dlink|netgear|tplink|hikvision|goahead|telesquare)',
        re.I
    ),
    'Tải Tệp Mã Độc & Dropper Payload': re.compile(
        r'(?:\.exe|\.dll|\.scr|\.bat|\.ps1|\.vbs|\.jar|\.swf|\.bin|\.hta|payload|dropper|beacon|gate\.php|download\.php\?file=)',
        re.I
    )
}

SCANNER_UA_PATTERN = re.compile(
    r'(?:nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|hydra|acunetix|nessus|openvas|censys|shodan)',
    re.I
)

SUSPICIOUS_TLDS = (
    '.xyz', '.top', '.tk', '.pw', '.cc', '.onion', '.duckdns.org', '.ngrok.io', '.loca.lt'
)

KNOWN_DNS_PROBES = (
    'version.bind', 'hostname.bind', 'id.server', 'isc.org', 'shadowserver.org', 'root-servers.net', 'gtld-servers.net'
)

PUBLIC_DNS_RESOLVERS = {
    '8.8.8.8', '8.8.4.4',
    '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220',
    '4.2.2.1', '4.2.2.2',
    '76.76.2.0', '76.76.10.0',
    '94.140.14.14', '94.140.15.15'
}

# Cấu hình ngưỡng phát hiện an ninh
DEFAULT_PORT_SCAN_THRESHOLD = 7
DEFAULT_DOS_PPS_THRESHOLD = 25  # Gói tin / giây (Peak PPS)
DEFAULT_FLOOD_PPS_THRESHOLD = 50 # Gói tin / giây cho ICMP/UDP
DEFAULT_DNS_ENTROPY_THRESHOLD = 3.8
DEFAULT_DNS_LENGTH_THRESHOLD = 45

# Cấu hình phát hiện kết nối IP lạ / IP bên ngoài (External Connections)
DEFAULT_UNUSUAL_PORTS = {
    23: 'Telnet (Không mã hóa)',
    445: 'SMB (Rủi ro ransomware/lateral movement)',
    135: 'MS-RPC',
    139: 'NetBIOS',
    3389: 'RDP (Truy cập từ xa rủi ro)',
    5900: 'VNC (Điều khiển từ xa)',
    6667: 'IRC (Thường dùng cho Botnet C2)',
    6666: 'IRC Alt',
    4444: 'Metasploit Default Listener',
    1337: 'Backdoor Elite / Hacker Port',
    31337: 'Back Orifice / Trojan Backdoor',
    9001: 'Tor Relay',
    9050: 'Tor SOCKS Proxy',
    8333: 'Bitcoin P2P',
    18080: 'Monero P2P'
}

DEFAULT_EXTERNAL_CONNECTION_THRESHOLD = 50  # Ngưỡng số kết nối / TCP SYN đến cùng 1 IP
DEFAULT_MULTI_PORT_THRESHOLD = 5            # Ngưỡng số cổng khác nhau truy cập trên cùng 1 IP
DEFAULT_ALLOWLIST = sorted(list(PUBLIC_DNS_RESOLVERS))
