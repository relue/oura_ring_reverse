"""Native layer - wrappers for libappecore.so functions via QEMU emulation."""

# Import from the working QEMU-based wrapper
try:
    from oura_ecore import EcoreWrapper, IbiResult, SleepScoreResult
    __all__ = ["EcoreWrapper", "IbiResult", "SleepScoreResult"]
except ImportError:
    # Fallback if oura_ecore not available
    EcoreWrapper = None
    IbiResult = None
    SleepScoreResult = None
    __all__ = []
