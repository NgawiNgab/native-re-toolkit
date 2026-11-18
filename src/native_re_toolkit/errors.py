"""Exception hierarchy for native-re-toolkit."""


class NRTError(Exception):
    """Base class for all toolkit errors."""


class FormatError(NRTError):
    """The input file is not a recognized or well-formed binary format."""


class LoaderError(NRTError):
    """A format-specific loader failed to parse the file."""


class UnsupportedArchError(NRTError):
    """The binary's CPU architecture is not supported by the disassembler."""


class AnalysisError(NRTError):
    """An analysis pass failed."""
