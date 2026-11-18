"""Analysis passes over loaded binaries."""

from .entropy import EntropyReport, analyze_entropy, shannon_entropy  # noqa: F401
from .impcat import classify_import, classify_imports  # noqa: F401
from .signatures import (  # noqa: F401
    Signature,
    SigMatch,
    compile_pattern,
    find_all,
    load_signatures,
    parse_pattern,
    scan_binary,
    scan_bytes,
)
from .strings import StringRef, extract_strings  # noqa: F401
from .xrefs import Xref, XrefDB, build_xrefs  # noqa: F401
