"""Native layer - wrappers for native libraries via QEMU emulation."""

# Parser bridge for libringeventparser.so
from oura.native.parser import (
    parse_events_sync,
    parse_events_async,
    check_parser_available,
    ParseResult,
)

# Import from the working QEMU-based wrapper
try:
    from oura_ecore import EcoreWrapper, IbiResult, SleepScoreResult
    __all__ = [
        "EcoreWrapper", "IbiResult", "SleepScoreResult",
        "parse_events_sync", "parse_events_async", "check_parser_available", "ParseResult",
    ]
except ImportError:
    # Fallback if oura_ecore not available
    EcoreWrapper = None
    IbiResult = None
    SleepScoreResult = None
    __all__ = [
        "parse_events_sync", "parse_events_async", "check_parser_available", "ParseResult",
    ]
