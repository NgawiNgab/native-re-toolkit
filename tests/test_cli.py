"""End-to-end CLI tests (run through cli.main with capsys + one subprocess)."""

import json
import subprocess
import sys

import pytest

from native_re_toolkit.cli import main


def test_info_text(hello, capsys):
    rc = main(["info", str(hello)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "format:    elf" in out
    assert "arch:      x86_64" in out


def test_info_json(hello, capsys):
    rc = main(["info", str(hello), "--json"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert rc == 0
    assert doc["format"] == "elf"
    assert doc["arch"] == "x86_64"
    assert doc["security"]["nx"] is True


def test_functions_cli(hello, capsys):
    rc = main(["functions", str(hello)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "main" in out
    assert "functions" in out.splitlines()[0]


def test_disasm_function(hello, capsys):
    rc = main(["disasm", str(hello), "--function", "main"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "call" in out
    assert "ret" in out


def test_disasm_at_symbol(hello, capsys):
    rc = main(["disasm", str(hello), "add", "--count", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "push" in out or "mov" in out


def test_strings_cli(fixtures, capsys):
    rc = main(["strings", str(fixtures["wide"])])
    out = capsys.readouterr().out
    assert rc == 0
    assert "plain ascii marker" in out


def test_xrefs_to(hello, capsys):
    rc = main(["xrefs", str(hello), "--to", "add"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "call" in out


def test_entropy_cli(hello, capsys):
    rc = main(["entropy", str(hello)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "file entropy:" in out


def test_scan_list(capsys):
    rc = main(["scan", "--list", "/dev/null"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "sha256_k_table" in out


def test_scan_crypto(fixtures, capsys):
    rc = main(["scan", str(fixtures["crypto"])])
    out = capsys.readouterr().out
    assert rc == 0
    assert "sha256_k_table" in out


def test_diff_cli(fixtures, capsys):
    rc = main(["diff", str(fixtures["diff_v1"]), str(fixtures["diff_v2"])])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CHANGED" in out
    assert "ADDED" in out
    assert "REMOVED" in out


def test_report_json_cli(hello, capsys):
    rc = main(["report", str(hello), "--format", "json"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert rc == 0
    assert doc["binary"]["format"] == "elf"
    assert doc["functions"]["total"] > 0


def test_report_html_file(hello, tmp_path, capsys):
    out_file = tmp_path / "report.html"
    rc = main(["report", str(hello), "--format", "html", "-o", str(out_file)])
    assert rc == 0
    text = out_file.read_text()
    assert "<html" in text and "Functions" in text


def test_cfg_dot(hello, capsys):
    rc = main(["cfg", str(hello), "add", "--dot"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("digraph")


def test_hexdump_cli(hello, capsys):
    rc = main(["hexdump", str(hello), "main", "--length", "32"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "55" in out  # push rbp


def test_imports_classify(hello, capsys):
    rc = main(["imports", str(hello), "--classify"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "printf" in out


def test_error_exit_code(capsys):
    rc = main(["info", "/nonexistent/binary"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err


def test_subprocess_entrypoint(hello):
    """The installed console script must work end to end."""
    rc = subprocess.run(
        [sys.executable, "-m", "native_re_toolkit", "info", str(hello), "--json"],
        capture_output=True,
        text=True,
    )
    assert rc.returncode == 0
    doc = json.loads(rc.stdout)
    assert doc["format"] == "elf"
