"""native-re-toolkit: static analysis toolkit for native binaries.

Provides a unified interface to load ELF/PE/Mach-O binaries, disassemble
them with Capstone, recover functions and control-flow graphs, extract
strings and cross-references, scan byte signatures and diff binaries.
"""

__version__ = "0.1.0"

from .errors import (  # noqa: F401
    NRTError,
    FormatError,
    LoaderError,
    UnsupportedArchError,
)
from .loader import Binary, Section, Symbol, open_binary  # noqa: F401
