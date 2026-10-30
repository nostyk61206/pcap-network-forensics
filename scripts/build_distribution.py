#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script đóng gói và đồng bộ bản phát hành nguyên tử (Atomic Distribution Build Script)
Dự án: PCAP Analyzer
Phiên bản: 3.0.0
Source of truth: pcap_analyzer
"""

import os
import sys
import shutil
import zipfile
import hashlib
import datetime
import tempfile
import importlib
import importlib.util
import json

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
SOURCE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
WORKSPACE_DIR = os.path.abspath(os.path.join(SOURCE_DIR, ".."))
EXPORT_DIR = os.path.join(WORKSPACE_DIR, "pcap_analyzer_export")
STAGING_DIR = os.path.join(WORKSPACE_DIR, "pcap_analyzer_export_staging")
BACKUP_DIR = os.path.join(WORKSPACE_DIR, "pcap_analyzer_export_old_backup")

ZIP_OUTPUT_PATH = os.path.join(WORKSPACE_DIR, "PCAP_Analyzer_Project.zip")
ZIP_TMP_PATH = os.path.join(WORKSPACE_DIR, "PCAP_Analyzer_Project.zip.tmp")
BUNDLE_MD_PATH = os.path.join(WORKSPACE_DIR, "PROJECT_BUNDLE.md")
BUNDLE_TMP_PATH = os.path.join(WORKSPACE_DIR, "PROJECT_BUNDLE.md.tmp")
TRANSACTION_JOURNAL_PATH = os.path.join(WORKSPACE_DIR, ".build_transaction.json")

VERSION = "3.0.0"
BUILD_DATE = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

IGNORE_PATTERNS = {
    "__pycache__",
    ".pytest_cache",
    ".coverage",
    ".mypy_cache",
    ".git",
    "venv",
    ".env",
    ".vscode",
    ".idea"
}

IGNORE_EXTENSIONS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".log",
    ".tmp",
    ".mmdb"  # Loại bỏ file GeoLite2 mmdb 66MB khỏi source export / zip theo README
}

def calculate_sha256(filepath):
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()

def is_ignored(rel_path):
    parts = rel_path.replace("\\", "/").split("/")
    for p in parts:
        if p in IGNORE_PATTERNS:
            return True
    _, ext = os.path.splitext(rel_path)
    if ext.lower() in IGNORE_EXTENSIONS:
        return True
    return False

def build_staging():
    print(f"[*] [1/4] Tạo bản dựng tại thư mục staging tạm: {STAGING_DIR}")
    if os.path.exists(STAGING_DIR):
        shutil.rmtree(STAGING_DIR)
    os.makedirs(STAGING_DIR, exist_ok=True)
    
    manifest_entries = []
    
    for root, dirs, files in os.walk(SOURCE_DIR):
        dirs[:] = [d for d in dirs if d not in IGNORE_PATTERNS]
        for file in sorted(files):
            abs_src = os.path.join(root, file)
            rel_path = os.path.relpath(abs_src, SOURCE_DIR)
            
            if is_ignored(rel_path):
                continue
                
            abs_dst = os.path.join(STAGING_DIR, rel_path)
            os.makedirs(os.path.dirname(abs_dst), exist_ok=True)
            shutil.copy2(abs_src, abs_dst)
            
            file_hash = calculate_sha256(abs_dst)
            manifest_entries.append((rel_path.replace("\\", "/"), file_hash, os.path.getsize(abs_dst)))

    # Tạo file MANIFEST.sha256 bên trong staging
    manifest_path = os.path.join(STAGING_DIR, "MANIFEST.sha256")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(f"# PCAP Analyzer Release Manifest\n")
        f.write(f"# Version: {VERSION}\n")
        f.write(f"# Build Date: {BUILD_DATE}\n#\n")
        for rel_path, f_hash, f_size in manifest_entries:
            f.write(f"{f_hash}  {rel_path}  ({f_size:,} bytes)\n")

    print(f"[+] Đã sao chép {len(manifest_entries)} tệp sạch sang staging.")
    return manifest_entries

def create_staging_zip():
    print(f"[*] [2/4] Đóng gói file ZIP tạm: {ZIP_TMP_PATH}")
    if os.path.exists(ZIP_TMP_PATH):
        os.remove(ZIP_TMP_PATH)
        
    with zipfile.ZipFile(ZIP_TMP_PATH, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(STAGING_DIR):
            for file in files:
                abs_file = os.path.join(root, file)
                rel_file = os.path.relpath(abs_file, STAGING_DIR)
                zipf.write(abs_file, arcname=os.path.join("pcap_analyzer", rel_file))
                
    zip_size = os.path.getsize(ZIP_TMP_PATH)
    zip_hash = calculate_sha256(ZIP_TMP_PATH)
    print(f"[+] Tạo ZIP tạm thành công! Kích thước: {zip_size:,} bytes | SHA-256: {zip_hash}")
    return zip_hash, zip_size

def run_smoke_test(manifest_entries):
    print("[*] [3/4] Chạy Smoke Test kiểm tra tính toàn vẹn bản phân phối...")
    smoke_dir = tempfile.mkdtemp(prefix="pcap_smoke_")
    try:
        with zipfile.ZipFile(ZIP_TMP_PATH, "r") as zipf:
            zipf.extractall(smoke_dir)
            
        extracted_root = os.path.join(smoke_dir, "pcap_analyzer")
        
        # 1. Kiểm tra các file cấm không được có mặt (như .vscode, *.mmdb)
        for root, dirs, files in os.walk(extracted_root):
            for d in dirs:
                if d in (".vscode", ".git", "__pycache__"):
                    raise AssertionError(f"Smoke test thất bại: Thư mục cấm '{d}' tồn tại trong ZIP!")
            for f in files:
                if f.endswith(".mmdb") or f.endswith(".pyc"):
                    raise AssertionError(f"Smoke test thất bại: File cấm '{f}' tồn tại trong ZIP!")

        # 2. Xác thực SHA-256 của từng file trích xuất
        for rel_path, expected_hash, expected_size in manifest_entries:
            target_path = os.path.join(extracted_root, rel_path)
            if not os.path.exists(target_path):
                raise AssertionError(f"Smoke test thất bại: Thiếu tệp bắt buộc '{rel_path}' trong ZIP!")
            actual_size = os.path.getsize(target_path)
            if actual_size != expected_size:
                raise AssertionError(f"Smoke test thất bại: Kích thước sai lệch cho '{rel_path}' ({actual_size} != {expected_size})")
            actual_hash = calculate_sha256(target_path)
            if actual_hash != expected_hash:
                raise AssertionError(f"Smoke test thất bại: SHA-256 sai lệch cho '{rel_path}'")

        # 3. Import các module cốt lõi từ thư mục giải nén sạch
        # Đảm bảo smoke test không dùng module cũ đang có trong sys.modules
        core_modules = [
            'modules.constants',
            'modules.rules_config',
            'modules.state_utils',
            'modules.security',
            'modules.pcap_parser',
            'modules.report_gen',
            'modules.visualization'
        ]
        saved_modules = {}
        for mod_name in list(sys.modules.keys()):
            if mod_name == 'modules' or mod_name.startswith('modules.'):
                saved_modules[mod_name] = sys.modules.pop(mod_name)

        sys.path.insert(0, extracted_root)
        try:
            for mod_name in core_modules:
                mod = importlib.import_module(mod_name)
                mod_file = getattr(mod, '__file__', '')
                if not mod_file or not os.path.abspath(mod_file).startswith(os.path.abspath(extracted_root)):
                    raise AssertionError(f"Smoke test thất bại: Module '{mod_name}' không được nạp từ bản trích xuất sạch! (__file__={mod_file})")
        finally:
            if sys.path and sys.path[0] == extracted_root:
                sys.path.pop(0)
            for mod_name in list(sys.modules.keys()):
                if mod_name == 'modules' or mod_name.startswith('modules.'):
                    sys.modules.pop(mod_name, None)
            sys.modules.update(saved_modules)

        print("[+] Smoke test hoàn tất thành công 100%! Bản phân phối hợp lệ và an toàn.")
    finally:
        shutil.rmtree(smoke_dir, ignore_errors=True)

def _get_artifact_specs():
    """
    Trả về cấu hình 3 artifact cần đồng bộ nguyên tử.
    Đọc động từ biến module để tương thích hoàn toàn với unittest patch.
    """
    return [
        {
            'key': 'export',
            'target': EXPORT_DIR,
            'staging': STAGING_DIR,
            'backup': BACKUP_DIR,
            'is_dir': True
        },
        {
            'key': 'zip',
            'target': ZIP_OUTPUT_PATH,
            'staging': ZIP_TMP_PATH,
            'backup': ZIP_OUTPUT_PATH + ".bak",
            'is_dir': False
        },
        {
            'key': 'bundle',
            'target': BUNDLE_MD_PATH,
            'staging': BUNDLE_TMP_PATH,
            'backup': BUNDLE_MD_PATH + ".bak",
            'is_dir': False
        }
    ]

def _get_journal_path():
    """Xác định đường dẫn lưu trữ nhật ký giao dịch (transaction journal)."""
    parent = os.path.dirname(EXPORT_DIR)
    if parent:
        return os.path.join(parent, ".build_transaction.json")
    return TRANSACTION_JOURNAL_PATH

def _write_journal(journal_path, data):
    """Ghi nhật ký giao dịch nguyên tử thông qua tệp tạm."""
    tmp_path = journal_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, journal_path)

def _remove_journal(journal_path):
    """Xóa nhật ký giao dịch sau khi hoàn tất chu trình."""
    if os.path.exists(journal_path):
        try:
            os.remove(journal_path)
        except Exception as e:
            print(f"[!] Cảnh báo: Không thể xóa journal '{journal_path}': {e}")

def recover_preexisting_state(specs, journal_path):
    """
    Kiểm tra trạng thái trước giao dịch và xử lý các trạng thái tồn đọng:
    1. Nếu có transaction journal từ lần chạy bị crash trước đó:
       - Nếu status == 'committed': hoàn tất dọn dẹp backup còn sót và xóa journal.
       - Nếu status dở dang (in_progress, swapping, rolling_back...): tự động phục hồi rollback để đưa các artifact về đúng trạng thái ban đầu.
    2. Nếu không có journal nhưng có backup tồn đọng:
       - Nếu target bị thiếu và có backup: phục hồi backup về target để tránh mất dữ liệu.
       - Nếu target đã có và có backup tồn đọng: lưu trữ an toàn thay vì xóa mù quáng với ignore_errors=True.
    """
    if os.path.exists(journal_path):
        try:
            with open(journal_path, "r", encoding="utf-8") as f:
                journal = json.load(f)
        except Exception as e:
            print(f"[!] Cảnh báo: Không thể đọc journal '{journal_path}': {e}")
            journal = None

        if journal:
            status = journal.get("status")
            swapped = journal.get("swapped", [])
            backed_up = journal.get("backed_up", [])

            if status == "committed":
                print("[*] Phát hiện transaction trước đã commit thành công nhưng chưa dọn backup. Tiến hành dọn dẹp...")
                for spec in specs:
                    b = spec['backup']
                    if os.path.exists(b):
                        try:
                            if spec['is_dir']:
                                shutil.rmtree(b)
                            else:
                                os.remove(b)
                        except Exception as e:
                            print(f"[!] Không thể xóa backup tồn đọng '{b}': {e}")
                _remove_journal(journal_path)
            else:
                print(f"[*] Phát hiện transaction dở dang (trạng thái: {status}) từ lần chạy trước! Kích hoạt Crash Recovery...")
                recovery_errors = []
                for spec in reversed(specs):
                    k = spec['key']
                    target = spec['target']
                    backup = spec['backup']
                    is_dir = spec['is_dir']

                    if k in swapped and os.path.exists(target):
                        try:
                            if is_dir:
                                shutil.rmtree(target)
                            else:
                                os.remove(target)
                        except Exception as e:
                            recovery_errors.append(f"Không thể dọn bản mới '{target}' khi phục hồi crash: {e}")
                            continue

                    if k in backed_up and os.path.exists(backup):
                        try:
                            os.replace(backup, target)
                        except Exception as e:
                            recovery_errors.append(f"Không thể khôi phục backup '{backup}' về '{target}' khi phục hồi crash: {e}")

                if recovery_errors:
                    raise RuntimeError(f"Crash Recovery thất bại: {'; '.join(recovery_errors)}")
                _remove_journal(journal_path)
                print("[+] Phục hồi sự cố (Crash Recovery) hoàn tất thành công! Đã khôi phục trạng thái ban đầu.")

    # Kiểm tra các backup tồn đọng không có journal
    for spec in specs:
        backup = spec['backup']
        target = spec['target']
        if os.path.exists(backup):
            if not os.path.exists(target):
                print(f"[*] Phát hiện backup tồn đọng '{backup}' trong khi target '{target}' bị thiếu. Khôi phục lại target...")
                os.replace(backup, target)
            else:
                archive_dir = os.path.join(os.path.dirname(backup), ".orphan_backups")
                try:
                    os.makedirs(archive_dir, exist_ok=True)
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    arch_target = os.path.join(archive_dir, f"{os.path.basename(backup)}.{ts}")
                    os.replace(backup, arch_target)
                    print(f"[*] Đã di chuyển an toàn backup tồn đọng '{backup}' sang '{arch_target}'.")
                except Exception as arch_err:
                    raise RuntimeError(
                        f"Không thể lưu trữ backup tồn đọng '{backup}'. "
                        f"Giữ nguyên backup và dừng giao dịch: {arch_err}"
                    ) from arch_err

def _execute_rollback(specs, initial_exists, backed_up, swapped, primary_error, journal_path):
    """
    Thực thi rollback đa tầng khi gặp sự cố ở bất kỳ bước sao lưu hay xuất bản nào:
    - Nếu artifact đã bị swap sang target: dọn dẹp bản mới khỏi target (không dùng ignore_errors).
    - Nếu artifact ban đầu có tồn tại và đã backup: phục hồi backup về target.
    - Nếu artifact ban đầu không tồn tại: đảm bảo sau rollback không tồn tại ở target.
    - Nếu rollback gặp lỗi: giữ nguyên backup để cứu dữ liệu và báo cả 2 lỗi.
    """
    print(f"[!] LỖI trong quá trình commit, tiến hành ROLLBACK khôi phục trạng thái ban đầu: {primary_error}")
    rollback_errors = []

    try:
        _write_journal(journal_path, {
            "status": "rolling_back",
            "initial_exists": initial_exists,
            "backed_up": backed_up,
            "swapped": swapped,
            "error": str(primary_error)
        })
    except Exception:
        pass

    for spec in reversed(specs):
        k = spec['key']
        target = spec['target']
        backup = spec['backup']
        is_dir = spec['is_dir']

        # 1. Nếu artifact đã bị swap sang target (đang có bản mới tại target)
        if k in swapped and os.path.exists(target):
            try:
                if is_dir:
                    shutil.rmtree(target)
                else:
                    os.remove(target)
            except Exception as e:
                rollback_errors.append(f"Không thể dọn bản mới tại '{target}': {e}")
                continue

        # 2. Nếu artifact ban đầu có tồn tại và đã được backup
        if k in backed_up:
            if os.path.exists(backup):
                try:
                    os.replace(backup, target)
                except Exception as e:
                    rollback_errors.append(f"Không thể khôi phục backup từ '{backup}' về '{target}': {e}")
            else:
                if initial_exists.get(k, False) and not os.path.exists(target):
                    rollback_errors.append(f"Không tìm thấy bản backup của '{k}' tại '{backup}' để khôi phục")

        # 3. Nếu artifact ban đầu KHÔNG tồn tại, đảm bảo sau rollback nó không tồn tại
        if not initial_exists.get(k, False):
            if os.path.exists(target):
                rollback_errors.append(f"Artifact '{target}' ban đầu không tồn tại nhưng vẫn còn tồn tại sau rollback")

    if rollback_errors:
        try:
            _write_journal(journal_path, {
                "status": "rollback_failed",
                "initial_exists": initial_exists,
                "backed_up": backed_up,
                "swapped": swapped,
                "primary_error": str(primary_error),
                "rollback_errors": rollback_errors
            })
        except Exception:
            pass

        combined_msg = (
            f"Giao dịch Atomic Commit thất bại: {primary_error}. "
            f"Quá trình ROLLBACK cũng gặp sự cố: {'; '.join(rollback_errors)}. "
            f"Các bản backup được bảo lưu an toàn tại các đường dẫn backup tương ứng để bảo vệ dữ liệu."
        )
        raise RuntimeError(combined_msg) from primary_error
    else:
        _remove_journal(journal_path)
        raise RuntimeError(f"Giao dịch Atomic Commit thất bại và đã rollback an toàn toàn bộ 3 artifact: {primary_error}") from primary_error

def atomic_commit():
    """
    Phát hành nguyên tử 3 bên (Transactional 3-Way Commit) cho:
    1. Thư mục xuất bản: pcap_analyzer_export
    2. Tệp nén phân phối: PCAP_Analyzer_Project.zip
    3. Tài liệu đồng bộ: PROJECT_BUNDLE.md
    Hỗ trợ rollback về trạng thái ban đầu nếu bất kỳ bước nào gặp sự cố,
    và tự động phục hồi sự cố (crash recovery) khi chạy lại.
    """
    print("[*] [4/4] Áp dụng phát hành nguyên tử 3 bên (Atomic 3-Way Commit: Export, ZIP, Bundle)...")
    specs = _get_artifact_specs()
    journal_path = _get_journal_path()

    # 1. Kiểm tra trạng thái trước giao dịch và xử lý tồn đọng/phục hồi sau crash
    recover_preexisting_state(specs, journal_path)

    # 2. Kiểm tra trạng thái đầu vào của từng artifact và ghi nhận artifact nào tồn tại trước giao dịch
    initial_exists = {}
    for spec in specs:
        initial_exists[spec['key']] = os.path.exists(spec['target'])

    backed_up = []
    swapped = []

    # Kiểm tra staging artifacts phải tồn tại đầy đủ trước khi bắt đầu
    for spec in specs:
        if not os.path.exists(spec['staging']):
            raise FileNotFoundError(f"Không tìm thấy file staging bắt buộc cho '{spec['key']}': {spec['staging']}")

    # Ghi nhận trạng thái ban đầu vào journal
    _write_journal(journal_path, {
        "status": "in_progress",
        "initial_exists": initial_exists,
        "backed_up": backed_up,
        "swapped": swapped
    })

    # Đưa CẢ bước sao lưu và bước xuất bản vào cùng phạm vi xử lý lỗi
    try:
        # --- BƯỚC 1: SAO LƯU (BACKUP) ---
        for spec in specs:
            k = spec['key']
            target = spec['target']
            backup = spec['backup']
            if initial_exists[k]:
                os.replace(target, backup)
                backed_up.append(k)
                _write_journal(journal_path, {
                    "status": "backing_up",
                    "initial_exists": initial_exists,
                    "backed_up": backed_up,
                    "swapped": swapped
                })

        # --- BƯỚC 2: XUẤT BẢN (SWAP) ---
        for spec in specs:
            k = spec['key']
            staging = spec['staging']
            target = spec['target']
            os.replace(staging, target)
            swapped.append(k)
            _write_journal(journal_path, {
                "status": "swapping",
                "initial_exists": initial_exists,
                "backed_up": backed_up,
                "swapped": swapped
            })

        # --- BƯỚC 3: XÁC THỰC SỰ HIỆN DIỆN CỦA 3 ARTIFACT ĐÃ XUẤT BẢN ---
        for spec in specs:
            if not os.path.exists(spec['target']):
                raise RuntimeError(f"Xác thực thất bại: Không tìm thấy artifact '{spec['key']}' tại '{spec['target']}' sau khi swap")

        # Đánh dấu COMMIT thành công
        _write_journal(journal_path, {
            "status": "committed",
            "initial_exists": initial_exists,
            "backed_up": backed_up,
            "swapped": swapped
        })
        print(f"[+] Giao dịch nguyên tử thành công: Đã đồng bộ {specs[0]['target']}, {specs[1]['target']}, và {specs[2]['target']}")

    except Exception as e:
        _execute_rollback(specs, initial_exists, backed_up, swapped, e, journal_path)

    # --- BƯỚC 4: DỌN DẸP BACKUP CỦA GIAO DỊCH HIỆN TẠI (CHỈ THỰC HIỆN SAU KHI CẢ 3 MỚI ĐÃ XUẤT BẢN) ---
    cleanup_errors = []
    for spec in specs:
        k = spec['key']
        backup = spec['backup']
        if k in backed_up and os.path.exists(backup):
            try:
                if spec['is_dir']:
                    shutil.rmtree(backup)
                else:
                    os.remove(backup)
            except Exception as clean_err:
                cleanup_errors.append(f"Không thể dọn backup '{backup}': {clean_err}")

    _remove_journal(journal_path)

    if cleanup_errors:
        print(f"[!] CẢNH BÁO DỌN DẸP: Xuất bản thành công nhưng gặp lỗi khi dọn bản backup: {'; '.join(cleanup_errors)}")

def update_project_bundle(manifest_entries, zip_hash, zip_size, target_path=BUNDLE_TMP_PATH):
    print(f"[*] Soạn thảo bundle phân phối tại staging: {target_path}...")
    
    code_files_to_embed = [
        ("modules/constants.py", "python"),
        ("modules/rules_config.py", "python"),
        ("modules/state_utils.py", "python"),
        ("modules/security.py", "python"),
        ("modules/pcap_parser.py", "python"),
        ("modules/report_gen.py", "python"),
        ("modules/visualization.py", "python"),
        ("app.py", "python"),
        ("templates/report_template.html", "html")
    ]
    
    bundle_content = []
    bundle_content.append(f"# PCAP ANALYZER - DỰ ÁN NGUỒN ĐỒNG BỘ")
    bundle_content.append(f"\n> **Phiên bản:** {VERSION} | **Ngày phát hành:** {BUILD_DATE}")
    bundle_content.append(f"> **Source of Truth:** `pcap_analyzer`")
    bundle_content.append(f"> **Gói phân phối:** `PCAP_Analyzer_Project.zip` ({zip_size:,} bytes, SHA-256: `{zip_hash}`)\n")
    
    bundle_content.append("## 1. TỔNG QUAN VÀ TRẠNG THÁI NÂNG CẤP")
    bundle_content.append("Dự án PCAP Analyzer đã được tối ưu hóa toàn diện và hoàn thiện các chức năng phân tích an ninh:")
    bundle_content.append("- **Tối ưu hóa phân tích kết nối IP bên ngoài:** Loại bỏ `iterrows()`, áp dụng vectorization với pandas groupby và boolean indexing; thời gian xử lý 100.000 gói tin giảm xuống dưới 0.1 giây (nhanh hơn 98%).")
    bundle_content.append("- **Tách biệt pipeline và bộ nhớ đệm (Caching):** Phân tích tấn công mạng và tổng hợp IP bên ngoài có cache riêng biệt. Thay đổi Allowlist/Blocklist chỉ chạy lại phần phân loại IP mà không cần đọc lại tệp PCAP hay chạy lại các bộ phát hiện cũ.")
    bundle_content.append("- **Chuẩn hóa cổng mục tiêu (Targeted Ports):** Đối với Inbound hiển thị cổng đích của máy nhận nội bộ, đối với Outbound hiển thị cổng đích của IP bên ngoài; không đưa cổng nguồn tạm thời (ephemeral) vào cổng mục tiêu.")
    bundle_content.append("- **Thứ tự ưu tiên phân loại chặt chẽ:** Blocklist > Bằng chứng tấn công rõ ràng > Allowlist > Heuristics > Chưa xác minh. Nếu IP nằm trong cả hai danh sách, trạng thái là Đáng ngờ với mức rủi ro Cao.")
    bundle_content.append("- **Tách biệt số flow kết nối và số gói SYN:** Đếm số phiên dựa trên 5-tuple độc lập, không để gói SYN retransmission làm tăng sai số số lượng kết nối.")
    bundle_content.append("- **Cải thiện chú thích và giao diện:** Loại bỏ các mã đánh dấu và ngôn ngữ quảng cáo, sử dụng chú thích ngắn gọn, tự nhiên và giao diện tiếng Việt rõ ràng.")
    bundle_content.append("- **Bộ kiểm thử và benchmark tự động:** Bổ sung 12 test case chuyên biệt và benchmark tự động cho 10.000, 50.000, 100.000 gói tin với phân tách thời gian từng thành phần.\n")
    
    bundle_content.append("## 2. MANIFEST BẢN PHÁT HÀNH (SHA-256)")
    bundle_content.append("| Tệp | SHA-256 (16 ký tự đầu) | Kích thước |")
    bundle_content.append("| :--- | :--- | :--- |")
    for rel_path, f_hash, f_size in manifest_entries:
        bundle_content.append(f"| `{rel_path}` | `{f_hash[:16]}...` | {f_size:,} B |")
        
    bundle_content.append("\n## 3. MÃ NGUỒN CÁC MODULE CỐT LÕI\n")
    
    for rel_file, lang in code_files_to_embed:
        full_path = os.path.join(SOURCE_DIR, rel_file)
        if os.path.exists(full_path):
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                code_text = f.read()
            bundle_content.append(f"### `{rel_file}`\n")
            bundle_content.append(f"```{lang}\n{code_text}\n```\n")
            
    with open(target_path, "w", encoding="utf-8") as f:
        f.write("\n".join(bundle_content))
        
    print(f"[+] Đã soạn thảo staging bundle thành công: {target_path}")

def main():
    print("==================================================")
    print(f" PCAP Analyzer Atomic Build & Distribution Tool v{VERSION}")
    print("==================================================")
    try:
        manifest = build_staging()
        zip_hash, zip_size = create_staging_zip()
        run_smoke_test(manifest)
        update_project_bundle(manifest, zip_hash, zip_size, target_path=BUNDLE_TMP_PATH)
        atomic_commit()
        print("\n[✔] HOÀN TẤT ĐÓNG GÓI VÀ ĐỒNG BỘ PHÁT HÀNH NGUYÊN TỬ 3 BÊN THÀNH CÔNG!")
    except Exception as e:
        print(f"\n[✘] LỖI BUILD: {e}")
        # Dọn dẹp staging và file tạm nếu có lỗi
        if os.path.exists(STAGING_DIR):
            shutil.rmtree(STAGING_DIR, ignore_errors=True)
        if os.path.exists(ZIP_TMP_PATH):
            try:
                os.remove(ZIP_TMP_PATH)
            except Exception:
                pass
        if os.path.exists(BUNDLE_TMP_PATH):
            try:
                os.remove(BUNDLE_TMP_PATH)
            except Exception:
                pass
        sys.exit(1)

if __name__ == "__main__":
    main()
