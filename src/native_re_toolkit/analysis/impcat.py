"""Import classification into capability categories.

Heuristic: matches imported symbol names against per-category keyword
lists. Useful for a quick capability overview of an unknown binary.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CATEGORIES: dict[str, tuple[str, ...]] = {
    "network": (
        "socket", "connect", "send", "recv", "sendto", "recvfrom", "bind",
        "listen", "accept", "getaddrinfo", "gethostbyname", "http",
        "internetopen", "internetreadfile", "urldownloadtofile", "winhttp",
        "wininet", "curl_", "wsastartup", "wsasocket", "ssl_", "tls",
        "gethostbyaddr", "inet_addr", "getpeername",
    ),
    "crypto": (
        "cryptencrypt", "cryptdecrypt", "cryptacquirecontext", "crypthash",
        "bcrypt", "ncrypt", "evp_", "aes", "sha1", "sha256", "sha512", "md5",
        "hmac", "rsa", "encrypt", "decrypt", "rand_bytes", "rc4", "chacha",
        "x509", "pkcs", "openssl",
    ),
    "process_exec": (
        "createprocess", "shellexecute", "winexec", "system", "popen",
        "execve", "execl", "execvp", "fork", "vfork", "posix_spawn",
        "dlopen", "dlsym", "loadlibrary", "getprocaddress", "lstrcmp",
    ),
    "file_io": (
        "createfile", "readfile", "writefile", "deletefile", "movefile",
        "copyfile", "findfirstfile", "fopen", "fread", "fwrite", "open",
        "read", "write", "unlink", "rename", "mkdir", "opendir", "readdir",
        "stat", "lseek", "mmap", "munmap",
    ),
    "memory_injection": (
        "virtualalloc", "virtualprotect", "writeprocessmemory",
        "readprocessmemory", "createremotethread", "openprocess",
        "mprotect", "ntmapviewofsection", "zwmapviewofsection",
        "queueuserapc", "setwindowshookex",
    ),
    "registry": (
        "regopenkey", "regsetvalue", "regqueryvalue", "regcreatekey",
        "regdeletekey", "regenumkey",
    ),
    "debug_evasion": (
        "ptrace", "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "outputdebugstring", "rdtsc",
        "gettickcount", "queryperformancecounter",
    ),
    "persistence": (
        "setvalue", "createservice", "startservice", "schtasks",
        "registerservice", "atexit", "signal",
    ),
    "screen_input": (
        "getasynckeystate", "setwindowshook", "getforegroundwindow",
        "bitblt", "getdc", "keybd_event", "mouse_event", "getkeystate",
    ),
}


@dataclass(slots=True)
class ImportCategory:
    category: str
    names: list[str] = field(default_factory=list)


def classify_import(name: str) -> list[str]:
    """Return all capability categories that match *name*."""
    low = name.lower()
    hits = []
    for category, keywords in CATEGORIES.items():
        for kw in keywords:
            if kw in low:
                hits.append(category)
                break
    return hits


def classify_imports(names: list[str]) -> dict[str, list[str]]:
    """Group *names* by capability category. Unmatched -> 'other'."""
    out: dict[str, list[str]] = {}
    for name in names:
        cats = classify_import(name)
        if not cats:
            out.setdefault("other", []).append(name)
        for cat in cats:
            out.setdefault(cat, []).append(name)
    return dict(sorted(out.items()))
