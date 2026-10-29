import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dotenv_guard.cli import main  # noqa: E402


def aws_key() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE"


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def init_repo(repo: Path) -> None:
    git(repo, "init")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "test")
    git(repo, "config", "commit.gpgsign", "false")


class HelpTest(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "dotenv_guard", *args],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_help_lists_commands(self):
        proc = self._run("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("scan", proc.stdout)
        self.assertIn("check-staged", proc.stdout)

    def test_scan_and_staged_help(self):
        for args in (["scan", "--help"], ["check-staged", "--help"]):
            with self.subTest(args=args):
                proc = self._run(*args)
                self.assertEqual(proc.returncode, 0)
                self.assertIn("usage:", proc.stdout)

    def test_version(self):
        proc = self._run("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("dotenv-guard 0.1.0", proc.stdout)


class ScanCommandTest(unittest.TestCase):
    def test_default_scan_uses_the_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / "app.py").write_text("k = '" + aws_key() + "'\n", encoding="utf-8")
            previous = Path.cwd()
            os.chdir(path)
            try:
                from io import StringIO
                from contextlib import redirect_stdout

                buf = StringIO()
                with redirect_stdout(buf):
                    code = main([])
            finally:
                os.chdir(previous)

        self.assertEqual(code, 1)
        self.assertIn("app.py:1: AWS access key", buf.getvalue())

    def test_clean_directory_prints_ok(self):
        from io import StringIO
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "readme.txt").write_text("hello\n", encoding="utf-8")
            buf = StringIO()
            with redirect_stdout(buf):
                code = main(["scan", tmp])

        self.assertEqual(code, 0)
        self.assertEqual(buf.getvalue().strip(), "ok")

    def test_missing_path_exits_2(self):
        from io import StringIO
        from contextlib import redirect_stderr, redirect_stdout

        with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
            code = main(["scan", "nope-not-a-real-path"])
        self.assertEqual(code, 2)
        self.assertIn("path not found", err.getvalue())


class CheckStagedTest(unittest.TestCase):
    def test_flags_staged_env_and_secret_only(self):
        from io import StringIO
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            init_repo(repo)
            (repo / ".env").write_text("A=1\n", encoding="utf-8")
            (repo / "app.py").write_text("t = '" + aws_key() + "'\n", encoding="utf-8")
            (repo / "later.py").write_text("t = '" + aws_key() + "'\n", encoding="utf-8")
            (repo / ".env.example").write_text("TOKEN=replace-me\n", encoding="utf-8")
            git(repo, "add", ".env", "app.py", ".env.example")

            buf = StringIO()
            with redirect_stdout(buf):
                code = main(["check-staged", "--repo", str(repo)])

        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn(".env: env file", output)
        self.assertIn("app.py:1: AWS access key", output)
        self.assertNotIn("later.py", output)
        self.assertNotIn(".env.example", output)

    def test_unstaged_edit_does_not_hide_the_index(self):
        from io import StringIO
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            init_repo(repo)
            target = repo / "app.py"
            target.write_text("t = '" + aws_key() + "'\n", encoding="utf-8")
            git(repo, "add", "app.py")
            target.write_text("print('clean')\n", encoding="utf-8")

            buf = StringIO()
            with redirect_stdout(buf):
                code = main(["check-staged", "--repo", str(repo)])

        self.assertEqual(code, 1)
        self.assertIn("AWS access key", buf.getvalue())

    def test_not_a_git_repo(self):
        from io import StringIO
        from contextlib import redirect_stderr, redirect_stdout

        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
                code = main(["check-staged", "--repo", tmp])
        self.assertEqual(code, 2)
        self.assertIn("dotenv-guard:", err.getvalue())


class ProjectFilesTest(unittest.TestCase):
    def test_readme_keeps_install_usage_and_kofi(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("pip install -e .", readme)
        self.assertIn("check-staged", readme)
        self.assertIn("https://ko-fi.com/kayorama", readme)

    def test_hook_and_entrypoint_are_wired(self):
        hook = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("id: dotenv-guard", hook)
        self.assertIn("dotenv-guard check-staged", hook)
        self.assertIn("pass_filenames: false", hook)
        self.assertIn('dotenv-guard = "dotenv_guard.cli:main"', project)


if __name__ == "__main__":
    unittest.main()
