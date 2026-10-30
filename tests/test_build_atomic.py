import unittest
import os
import shutil
import tempfile
from unittest.mock import patch

class TestBuildDistributionAtomic(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_atomic_build_")
        self.export_dir = os.path.join(self.test_dir, "export")
        self.staging_dir = os.path.join(self.test_dir, "staging")
        self.backup_dir = os.path.join(self.test_dir, "backup")
        
        self.zip_path = os.path.join(self.test_dir, "project.zip")
        self.zip_tmp = os.path.join(self.test_dir, "project.zip.tmp")
        
        self.bundle_path = os.path.join(self.test_dir, "bundle.md")
        self.bundle_tmp = os.path.join(self.test_dir, "bundle.md.tmp")

        # Khởi tạo trạng thái ban đầu của 3 artifact
        os.makedirs(self.export_dir)
        with open(os.path.join(self.export_dir, "file.txt"), "w") as f:
            f.write("export v1")
        with open(self.zip_path, "wb") as f:
            f.write(b"zip v1")
        with open(self.bundle_path, "w", encoding="utf-8") as f:
            f.write("bundle v1")

        # Khởi tạo trạng thái staging mới
        os.makedirs(self.staging_dir)
        with open(os.path.join(self.staging_dir, "file.txt"), "w") as f:
            f.write("export v2")
        with open(self.zip_tmp, "wb") as f:
            f.write(b"zip v2")
        with open(self.bundle_tmp, "w", encoding="utf-8") as f:
            f.write("bundle v2")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_atomic_commit_success(self):
        """[FINAL-07] Giao dịch 3 bên thành công: cả 3 artifact đều được cập nhật lên v2."""
        from scripts import build_distribution

        with patch.object(build_distribution, 'EXPORT_DIR', self.export_dir), \
             patch.object(build_distribution, 'STAGING_DIR', self.staging_dir), \
             patch.object(build_distribution, 'BACKUP_DIR', self.backup_dir), \
             patch.object(build_distribution, 'ZIP_OUTPUT_PATH', self.zip_path), \
             patch.object(build_distribution, 'ZIP_TMP_PATH', self.zip_tmp), \
             patch.object(build_distribution, 'BUNDLE_MD_PATH', self.bundle_path), \
             patch.object(build_distribution, 'BUNDLE_TMP_PATH', self.bundle_tmp):

            build_distribution.atomic_commit()

            with open(os.path.join(self.export_dir, "file.txt"), "r") as f:
                self.assertEqual(f.read(), "export v2")
            with open(self.zip_path, "rb") as f:
                self.assertEqual(f.read(), b"zip v2")
            with open(self.bundle_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "bundle v2")

            # Staging và backup phải được dọn sạch
            self.assertFalse(os.path.exists(self.staging_dir))
            self.assertFalse(os.path.exists(self.backup_dir))
            self.assertFalse(os.path.exists(self.zip_tmp))
            self.assertFalse(os.path.exists(self.bundle_tmp))

    def test_fault_injection_rollback_on_zip_swap_failure(self):
        """[FINAL-07] Fault Injection: Lỗi khi hoán đổi ZIP -> Rollback cả export, zip, bundle về v1."""
        from scripts import build_distribution

        orig_replace = os.replace
        def mock_replace(src, dst):
            # Cố tình ném exception khi replace từ zip_tmp sang zip_path (chiều forward)
            if src == self.zip_tmp:
                raise OSError("Simulated ZIP disk error during atomic commit")
            return orig_replace(src, dst)

        with patch.object(build_distribution, 'EXPORT_DIR', self.export_dir), \
             patch.object(build_distribution, 'STAGING_DIR', self.staging_dir), \
             patch.object(build_distribution, 'BACKUP_DIR', self.backup_dir), \
             patch.object(build_distribution, 'ZIP_OUTPUT_PATH', self.zip_path), \
             patch.object(build_distribution, 'ZIP_TMP_PATH', self.zip_tmp), \
             patch.object(build_distribution, 'BUNDLE_MD_PATH', self.bundle_path), \
             patch.object(build_distribution, 'BUNDLE_TMP_PATH', self.bundle_tmp), \
             patch('os.replace', side_effect=mock_replace):

            with self.assertRaises(RuntimeError):
                build_distribution.atomic_commit()

            # Kiểm tra trạng thái đã được rollback hoàn toàn về v1
            with open(os.path.join(self.export_dir, "file.txt"), "r") as f:
                self.assertEqual(f.read(), "export v1")
            with open(self.zip_path, "rb") as f:
                self.assertEqual(f.read(), b"zip v1")
            with open(self.bundle_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "bundle v1")

    def test_fault_injection_rollback_on_bundle_swap_failure(self):
        """[FINAL-07] Fault Injection: Lỗi khi hoán đổi Bundle -> Rollback toàn bộ về v1."""
        from scripts import build_distribution

        orig_replace = os.replace
        def mock_replace(src, dst):
            # Cố tình ném exception khi replace từ bundle_tmp sang bundle_path (chiều forward)
            if src == self.bundle_tmp:
                raise OSError("Simulated Bundle disk error during atomic commit")
            return orig_replace(src, dst)

        with patch.object(build_distribution, 'EXPORT_DIR', self.export_dir), \
             patch.object(build_distribution, 'STAGING_DIR', self.staging_dir), \
             patch.object(build_distribution, 'BACKUP_DIR', self.backup_dir), \
             patch.object(build_distribution, 'ZIP_OUTPUT_PATH', self.zip_path), \
             patch.object(build_distribution, 'ZIP_TMP_PATH', self.zip_tmp), \
             patch.object(build_distribution, 'BUNDLE_MD_PATH', self.bundle_path), \
             patch.object(build_distribution, 'BUNDLE_TMP_PATH', self.bundle_tmp), \
             patch('os.replace', side_effect=mock_replace):

            with self.assertRaises(RuntimeError):
                build_distribution.atomic_commit()

            # Kiểm tra trạng thái đã được rollback hoàn toàn về v1
            with open(os.path.join(self.export_dir, "file.txt"), "r") as f:
                self.assertEqual(f.read(), "export v1")
            with open(self.zip_path, "rb") as f:
                self.assertEqual(f.read(), b"zip v1")
            with open(self.bundle_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "bundle v1")

    def test_orphan_backup_is_preserved_when_archiving_fails(self):
        """Không xóa backup tồn đọng nếu không thể chuyển nó sang nơi lưu trữ."""
        from scripts import build_distribution

        orphan_backup = os.path.join(self.test_dir, "export_backup")
        shutil.copytree(self.export_dir, orphan_backup)
        specs = [{
            'key': 'export',
            'target': self.export_dir,
            'backup': orphan_backup,
            'is_dir': True,
        }]
        journal_path = os.path.join(self.test_dir, "transaction.json")

        with patch('os.replace', side_effect=OSError("Simulated archive disk error")):
            with self.assertRaisesRegex(RuntimeError, "Giữ nguyên backup và dừng giao dịch"):
                build_distribution.recover_preexisting_state(specs, journal_path)

        with open(os.path.join(orphan_backup, "file.txt"), "r") as f:
            self.assertEqual(f.read(), "export v1")
        with open(os.path.join(self.export_dir, "file.txt"), "r") as f:
            self.assertEqual(f.read(), "export v1")

if __name__ == '__main__':
    unittest.main()
