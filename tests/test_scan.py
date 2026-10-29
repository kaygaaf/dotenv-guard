import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dotenv_guard.scan import (  # noqa: E402
    Finding,
    is_blocked_env_filename,
    scan_content,
    scan_paths,
)


def aws_key() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE"


def github_token() -> str:
    return "ghp_" + ("A" * 36)


class EnvNamesTest(unittest.TestCase):
    def test_blocked_names(self):
        for name in (".env", ".env.local", ".env.production", ".ENV", ".Env.Backup", "dir/.env.local"):
            with self.subTest(name=name):
                self.assertTrue(is_blocked_env_filename(Path(name).name))

    def test_allowed_names(self):
        for name in (
            ".env.example",
            ".env.sample",
            ".ENV.EXAMPLE",
            ".envrc",
            ".environment",
            "config.env",
            "env",
            "notes.txt",
        ):
            with self.subTest(name=name):
                self.assertFalse(is_blocked_env_filename(Path(name).name))


class PatternTest(unittest.TestCase):
    def test_each_pattern(self):
        fine = "github_pat_" + ("a" * 22) + "_" + ("b" * 59)
        samples = [
            (aws_key(), "AWS access key"),
            ("aws_secret_access_key=" + ("a" * 40), "AWS secret key"),
            ("sk_live_" + ("c" * 24), "Stripe live key"),
            ("rk_live_" + ("d" * 24), "Stripe live key"),
            ("-----BEGIN " + "PRIVATE KEY-----", "private key"),
            ("-----BEGIN " + "OPENSSH PRIVATE KEY-----", "private key"),
            ("-----BEGIN " + "PGP PRIVATE KEY BLOCK-----", "private key"),
            (github_token(), "GitHub token"),
            ("gho_" + ("b" * 36), "GitHub token"),
            (fine, "GitHub fine-grained token"),
            ("ck_" + ("ab" * 20), "WooCommerce consumer key"),
            ("cs_" + ("cd" * 20), "WooCommerce consumer secret"),
            ("xoxb-" + ("1" * 12), "Slack token"),
            ("AIza" + ("A" * 35), "Google API key"),
            ("npm_" + ("e" * 36), "npm token"),
        ]
        for token, reason in samples:
            with self.subTest(reason=reason):
                found = scan_content("secret.txt", f"prefix {token} suffix\n".encode())
                self.assertEqual(found, [Finding("secret.txt", 1, reason)])

    def test_line_number_and_ignores_lookalikes(self):
        text = "\n".join(
            [
                "sk_test_" + ("a" * 24),
                "sk_live_short",
                "AKIA123",
                "ck_editor",
                "-----BEGIN " + "CERTIFICATE-----",
                "token = " + github_token(),
            ]
        )
        found = scan_content("app.py", text.encode())
        self.assertEqual(found, [Finding("app.py", 6, "GitHub token")])

    def test_env_file_and_secret_both_reported(self):
        body = "A=1\nK=" + aws_key() + "\n"
        found = scan_content(".env", body.encode())
        self.assertEqual(
            found,
            [
                Finding(".env", None, "env file"),
                Finding(".env", 2, "AWS access key"),
            ],
        )

    def test_example_file_is_not_an_env_hit_but_secrets_still_count(self):
        body = "TOKEN=" + aws_key() + "\n"
        found = scan_content(".env.example", body.encode())
        self.assertEqual(found, [Finding(".env.example", 1, "AWS access key")])

    def test_binary_skips_content_but_not_the_filename(self):
        data = b"\0" + aws_key().encode()
        self.assertEqual(scan_content(".env", data), [Finding(".env", None, "env file")])
        self.assertEqual(scan_content("blob.bin", data), [])

    def test_only_the_first_megabyte_is_scanned(self):
        early = aws_key().encode() + b"\n" + (b"x" * (1_000_000))
        late = (b"y" * 1_000_000) + b"\n" + aws_key().encode()
        self.assertEqual(scan_content("early.txt", early), [Finding("early.txt", 1, "AWS access key")])
        self.assertEqual(scan_content("late.txt", late), [])


class TreeTest(unittest.TestCase):
    def test_walk_skips_dependency_dirs_and_flags_real_files(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('hi')\n", encoding="utf-8")
            nested = root / "node_modules" / "pkg"
            nested.mkdir(parents=True)
            (nested / "leak.py").write_text(aws_key() + "\n", encoding="utf-8")
            vendored = root / "vendor"
            vendored.mkdir()
            (vendored / "oops.py").write_text(github_token() + "\n", encoding="utf-8")
            (root / ".env.sample").write_text("KEY=replace-me\n", encoding="utf-8")
            (root / ".env.local").write_text("OK=1\n", encoding="utf-8")

            found, errors = scan_paths([str(root)])

        self.assertEqual(errors, 0)
        reasons = {(Path(item.path).name, item.line, item.reason) for item in found}
        self.assertIn(("oops.py", 1, "GitHub token"), reasons)
        self.assertIn((".env.local", None, "env file"), reasons)
        self.assertFalse(any(Path(item.path).name == "leak.py" for item in found))
        self.assertFalse(any(item.path.endswith(".env.sample") and item.reason == "env file" for item in found))

    def test_explicit_file_inside_a_skipped_dir_is_still_scanned(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            leak = Path(tmp) / "node_modules" / "leak.txt"
            leak.parent.mkdir()
            leak.write_text(aws_key() + "\n", encoding="utf-8")
            found, errors = scan_paths([str(leak)])

        self.assertEqual(errors, 0)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].reason, "AWS access key")

    def test_missing_path_is_an_error(self):
        found, errors = scan_paths(["this-path-does-not-exist-dotenv-guard"])
        self.assertEqual(found, [])
        self.assertEqual(errors, 1)

    def test_repo_itself_is_clean(self):
        found, errors = scan_paths([str(ROOT)])
        self.assertEqual(errors, 0, found)
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
