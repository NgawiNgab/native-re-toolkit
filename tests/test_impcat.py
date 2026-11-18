"""Import classification tests."""

from native_re_toolkit.analysis.impcat import classify_import, classify_imports


def test_classify_network():
    assert "network" in classify_import("socket")
    assert "network" in classify_import("InternetOpenA")
    assert "network" in classify_import("curl_easy_perform")


def test_classify_crypto():
    assert "crypto" in classify_import("EVP_EncryptInit")
    assert "crypto" in classify_import("CryptAcquireContextW")
    assert "crypto" in classify_import("AES_set_encrypt_key")


def test_classify_injection():
    assert "memory_injection" in classify_import("VirtualAlloc")
    assert "memory_injection" in classify_import("WriteProcessMemory")
    assert "memory_injection" in classify_import("mprotect")


def test_classify_debug():
    assert "debug_evasion" in classify_import("ptrace")
    assert "debug_evasion" in classify_import("IsDebuggerPresent")


def test_classify_exec():
    assert "process_exec" in classify_import("CreateProcessA")
    assert "process_exec" in classify_import("system")
    assert "process_exec" in classify_import("dlopen")


def test_classify_unknown():
    assert classify_import("some_obscure_function_xyz") == []


def test_classify_imports_grouping():
    out = classify_imports(["socket", "VirtualAlloc", "printf"])
    assert out["network"] == ["socket"]
    assert out["memory_injection"] == ["VirtualAlloc"]
    assert out["other"] == ["printf"]


def test_multi_category():
    # "send" is network; ensure no crash on multi matches
    cats = classify_import("httpsendrequest")
    assert "network" in cats
