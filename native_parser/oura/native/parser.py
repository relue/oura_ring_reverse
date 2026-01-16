"""
Native Parser Bridge

Python wrapper for the native libringeventparser.so parser.
Converts ring_events.txt -> ring_data.pb via QEMU emulation.
"""

import subprocess
import asyncio
import json
import os
from pathlib import Path
from typing import Optional, Callable, Tuple
from dataclasses import dataclass


@dataclass
class ParseResult:
    """Result of parsing events file."""
    success: bool
    input_events: int
    output_size: int
    output_path: str
    error: Optional[str] = None
    duration_sec: float = 0.0


# Default paths
NATIVE_PARSER_DIR = Path(__file__).parent.parent.parent  # native_parser/
PARSER_BINARY = NATIVE_PARSER_DIR / "parser_bridge_android"
DEFAULT_INPUT = NATIVE_PARSER_DIR / "input_data" / "ring_events.txt"
DEFAULT_OUTPUT = NATIVE_PARSER_DIR / "input_data" / "ring_data.pb"
DEFAULT_SYNC_POINT = NATIVE_PARSER_DIR / "input_data" / "sync_point.json"
ANDROID_ROOT = NATIVE_PARSER_DIR / "android_root"

# QEMU configuration
QEMU_BINARY = "qemu-aarch64"


def check_parser_available() -> Tuple[bool, str]:
    """Check if native parser is available.

    Returns:
        Tuple of (available, message)
    """
    if not PARSER_BINARY.exists():
        return False, f"Parser binary not found: {PARSER_BINARY}"

    # Check QEMU
    try:
        result = subprocess.run(
            ["which", "qemu-aarch64"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return False, "qemu-aarch64 not installed"
    except Exception as e:
        return False, f"Error checking QEMU: {e}"

    # Check android_root
    if not ANDROID_ROOT.exists():
        return False, f"Android root not found: {ANDROID_ROOT}"

    return True, "Parser ready"


def load_sync_point(sync_path: Optional[Path] = None) -> Tuple[Optional[int], Optional[int]]:
    """Load sync point from JSON file.

    Returns:
        Tuple of (ring_time, utc_millis) or (None, None) if not found
    """
    if sync_path is None:
        sync_path = DEFAULT_SYNC_POINT

    if not sync_path.exists():
        return None, None

    try:
        with open(sync_path) as f:
            data = json.load(f)
        return data.get("ring_time"), data.get("utc_millis")
    except Exception:
        return None, None


def parse_events_sync(
    input_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    log_callback: Optional[Callable[[str, str], None]] = None,
    preprocess: bool = True  # Enabled: chronological order required for SleepNet ML
) -> ParseResult:
    """Parse events file to protobuf synchronously.

    Args:
        input_path: Path to ring_events.txt (default: input_data/ring_events.txt)
        output_path: Path for output protobuf (default: input_data/ring_data.pb)
        log_callback: Optional callback for log messages (level, message)
        preprocess: If True (default), sort events chronologically before parsing.
                    Chronological order (oldest first) required for SleepNet ML model.

    Returns:
        ParseResult with status and details
    """
    import time
    start_time = time.time()

    input_path = Path(input_path) if input_path else DEFAULT_INPUT
    output_path = Path(output_path) if output_path else DEFAULT_OUTPUT

    def log(level: str, msg: str):
        if log_callback:
            log_callback(level, msg)
        else:
            print(f"[{level}] {msg}")

    # Check availability
    available, msg = check_parser_available()
    if not available:
        log("error", msg)
        return ParseResult(
            success=False,
            input_events=0,
            output_size=0,
            output_path=str(output_path),
            error=msg
        )

    # Check input exists
    if not input_path.exists():
        log("error", f"Input file not found: {input_path}")
        return ParseResult(
            success=False,
            input_events=0,
            output_size=0,
            output_path=str(output_path),
            error=f"Input file not found: {input_path}"
        )

    # Preprocess: sort by timestamp (oldest dates first)
    # Chronological order required for SleepNet ML model
    # Write to intermediate file, keep original intact
    transformed_path = input_path.parent / "transformed_ring_events.txt"
    if preprocess:
        from oura.data.preprocess import preprocess_events
        log("info", "Preprocessing: chronological order...")
        total, output, _ = preprocess_events(str(input_path), str(transformed_path), reverse_order=False)
        log("info", f"Sorted {output} events (oldest first)")
        parser_input = transformed_path
    else:
        parser_input = input_path

    # Count input events
    with open(parser_input) as f:
        input_events = sum(1 for line in f if line.strip() and not line.startswith('#'))

    log("info", f"Parsing {input_events} events from {parser_input.name}...")
    log("info", "Running native parser via QEMU (this may take a minute)...")

    # Load sync point
    sync_path = input_path.parent / "sync_point.json"
    if not sync_path.exists():
        sync_path = DEFAULT_SYNC_POINT
    ring_time, utc_millis = load_sync_point(sync_path)

    if ring_time and utc_millis:
        log("info", f"Sync point: ring_time={ring_time}, utc_millis={utc_millis}")
    else:
        log("warning", "No sync point found - timestamps may be incorrect")

    try:
        # Build QEMU command - use QEMU_LD_PREFIX for android_root sysroot
        cmd = [
            QEMU_BINARY,
            str(PARSER_BINARY),
            str(parser_input),
        ]

        # Add sync point args if available
        if ring_time and utc_millis:
            cmd.extend([str(ring_time), str(utc_millis)])

        # Set clean environment with QEMU_LD_PREFIX pointing to android_root
        env = {
            "PATH": "/usr/bin:/bin",
            "QEMU_LD_PREFIX": str(ANDROID_ROOT),
        }

        # Run parser - output goes to stdout
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,  # 5 minutes for large raw files (1M+ events)
            cwd=str(NATIVE_PARSER_DIR),
            env=env
        )

        duration = time.time() - start_time
        stderr_text = result.stderr.decode('utf-8', errors='replace')

        if result.returncode != 0:
            log("error", f"Parser failed: {stderr_text}")
            return ParseResult(
                success=False,
                input_events=input_events,
                output_size=0,
                output_path=str(output_path),
                error=stderr_text,
                duration_sec=duration
            )

        # Parser outputs protobuf to stdout - write to output file
        if not result.stdout:
            log("error", "Parser produced no output")
            return ParseResult(
                success=False,
                input_events=input_events,
                output_size=0,
                output_path=str(output_path),
                error="Parser produced no output",
                duration_sec=duration
            )

        # Write protobuf to output file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'wb') as f:
            f.write(result.stdout)

        output_size = len(result.stdout)
        log("success", f"Parsed {input_events} events -> {output_size} bytes in {duration:.1f}s")

        return ParseResult(
            success=True,
            input_events=input_events,
            output_size=output_size,
            output_path=str(output_path),
            duration_sec=duration
        )

    except subprocess.TimeoutExpired:
        log("error", "Parser timed out after 5 minutes")
        return ParseResult(
            success=False,
            input_events=input_events,
            output_size=0,
            output_path=str(output_path),
            error="Parser timed out",
            duration_sec=300.0
        )
    except Exception as e:
        log("error", f"Parser error: {e}")
        return ParseResult(
            success=False,
            input_events=input_events,
            output_size=0,
            output_path=str(output_path),
            error=str(e),
            duration_sec=time.time() - start_time
        )


async def parse_events_async(
    input_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    log_callback: Optional[Callable[[str, str], None]] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> ParseResult:
    """Parse events file to protobuf asynchronously.

    Same as parse_events_sync but runs in executor to not block asyncio.
    """
    import functools
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        functools.partial(parse_events_sync, input_path, output_path, log_callback)
    )


def main():
    """CLI entry point for native parser.

    Usage:
        python -m oura.native.parser <events.txt> [output.pb]

    Or from native_parser directory:
        python oura/native/parser.py input_data/ring_events.txt ring_data.pb
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m oura.native.parser <events.txt> [output.pb]")
        print()
        print("Parse ring events to protobuf via native parser.")
        print("Sync point is auto-detected from sync_point.json in same directory.")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    # Default output next to input
    if output_path is None:
        output_path = input_path.parent / "ring_data.pb"

    result = parse_events_sync(input_path, output_path)

    if result.success:
        print(f"\nOutput: {result.output_path} ({result.output_size} bytes)")
        print(f"Decode with: python decode_ringdata.py {result.output_path}")
        sys.exit(0)
    else:
        print(f"\nError: {result.error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
