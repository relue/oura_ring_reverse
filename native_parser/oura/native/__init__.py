"""Native layer - wrappers for native libraries via QEMU emulation."""

# Parser bridge for libringeventparser.so
from oura.native.parser import (
    parse_events_sync,
    parse_events_async,
    check_parser_available,
    ParseResult,
)

# AppEvent serialization for 1:1 Oura native calls
from oura.native.app_event import (
    AppEventSerializer,
    SleepCalculationInput,
    create_sleep_input_from_protobuf,
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
