import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from release import check_build, write_archive, verify_archive


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.info = {
            "GoVersion": "go1.27.4",
            "Deps": [
                {"Path": "go.k6.io/k6/v2", "Version": "v2.4.0"},
                {"Path": "github.com/stanimirivanov/xk6-soap", "Replace": {"Path": "/checkout"}},
            ],
        }

    def test_exact_runtime_and_extension(self):
        check_build(self.info, "go1.27.4", "v2.4.0", Path("/checkout"))
        for go, k6, source in [
            ("go1.27.3", "v2.4.0", "/checkout"),
            ("go1.27.4", "v2.3.0", "/checkout"),
            ("go1.27.4", "v2.4.0", "/other-checkout"),
        ]:
            with self.subTest(go=go, k6=k6, source=source), self.assertRaises(ValueError):
                check_build(self.info, go, k6, Path(source))

    def test_published_module_does_not_count_as_checkout(self):
        del self.info["Deps"][1]["Replace"]
        with self.assertRaises(ValueError):
            check_build(self.info, "go1.27.4", "v2.4.0", Path.cwd())

    def test_replacement_identifies_actual_k6(self):
        k6 = self.info["Deps"][0]
        k6["Replace"] = {"Path": k6["Path"], "Version": "v2.3.0"}
        check_build(self.info, "go1.27.4", "v2.3.0", Path("/checkout"))
        with self.assertRaises(ValueError):
            check_build(self.info, "go1.27.4", "v2.4.0", Path("/checkout"))
        k6["Replace"]["Path"] = "example.invalid/fork"
        with self.assertRaises(ValueError):
            check_build(self.info, "go1.27.4", "v2.3.0", Path("/checkout"))


class ArchiveTest(unittest.TestCase):
    def test_reproducible_archive_preserves_binary_mode_and_contents(self):
        members = {"metadata.json": (b"{}\n", 0o644), "k6": (b"fake binary", 0o755)}
        with tempfile.TemporaryDirectory() as scratch:
            first = Path(scratch) / "first.tar.gz"
            second = Path(scratch) / "second.tar.gz"
            write_archive(first, members)
            write_archive(second, dict(reversed(list(members.items()))))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            verify_archive(first, members)
            with tarfile.open(fileobj=io.BytesIO(first.read_bytes())) as archive:
                self.assertEqual(archive.getmember("k6").mode, 0o755)
            members["k6"] = (b"wrong binary", 0o755)
            with self.assertRaises(ValueError):
                verify_archive(first, members)
