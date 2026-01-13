"""
BlueZ Bonding Helpers

Functions for bonding with Oura Ring via BlueZ and enabling kernel auto-connect.
"""

import asyncio
import subprocess
from pathlib import Path
from typing import Optional, List, Callable, Tuple

from oura.ble.protocol import DEFAULT_ADAPTER, DEFAULT_DATA_DIR, BONDED_ADDRESS_FILE


def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
    """Run a shell command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.returncode == 0, result.stdout.strip(), result.stderr.strip())
    except subprocess.TimeoutExpired:
        return (False, "", "Command timed out")
    except Exception as e:
        return (False, "", str(e))


def get_adapter_index(adapter: str = DEFAULT_ADAPTER) -> int:
    """Get numeric index from adapter name (e.g., 'hci1' -> 1)."""
    if adapter.startswith("hci"):
        try:
            return int(adapter[3:])
        except ValueError:
            pass
    return 0


def get_adapter_address(adapter: str = DEFAULT_ADAPTER) -> Optional[str]:
    """Get the MAC address of the Bluetooth adapter."""
    # First try sysfs - most reliable
    try:
        with open(f"/sys/class/bluetooth/{adapter}/address", "r") as f:
            return f.read().strip().upper()
    except:
        pass

    # Fallback to bluetoothctl
    success, stdout, _ = run_cmd(["bluetoothctl", "list"])
    if success:
        for line in stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                addr = parts[1]
                if "[default]" in line:
                    return addr
        for line in stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]

    return None


def list_bluetooth_adapters() -> List[str]:
    """List available Bluetooth adapters."""
    adapters = []
    bt_path = Path("/sys/class/bluetooth")
    if bt_path.exists():
        for adapter_dir in bt_path.iterdir():
            if adapter_dir.name.startswith("hci"):
                adapters.append(adapter_dir.name)
    return sorted(adapters)


async def bond_ring(
    adapter: str = DEFAULT_ADAPTER,
    scan_timeout: float = 15.0,
    log_callback: Optional[Callable[[str, str], None]] = None,
    data_dir: Optional[Path] = None
) -> Optional[str]:
    """
    Bond with Oura Ring and enable kernel auto-connect.

    This replicates the Android bonding behavior:
    1. Scan for Oura Ring (must be in pairing mode!)
    2. Pair/bond with it
    3. Enable kernel auto-connect (btmgmt add-device -a 2)
    4. Trust the device

    Args:
        adapter: Bluetooth adapter (default: hci0)
        scan_timeout: How long to scan for the ring
        log_callback: Optional callback for log messages (level, message)
        data_dir: Directory to save bonded address

    Returns:
        Identity address if successful, None otherwise
    """
    data_dir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR

    def log(level: str, msg: str):
        if log_callback:
            log_callback(level, msg)
        else:
            print(f"[{level}] {msg}")

    log('info', "=" * 60)
    log('info', "  OURA RING BONDING + AUTO-CONNECT SETUP")
    log('info', "=" * 60)
    log('info', "")
    log('warn', "Make sure the ring is in PAIRING MODE!")
    log('info', "(Place on charger, wait for white light, then remove)")
    log('info', "")

    adapter_index = get_adapter_index(adapter)
    adapter_addr = get_adapter_address(adapter)

    if not adapter_addr:
        log('error', f"Could not get address for adapter {adapter}")
        return None

    log('info', f"Using adapter: {adapter} ({adapter_addr})")

    # Step 1: Scan for Oura Ring
    log('info', "[1/5] Scanning for Oura Ring...")

    scan_proc = subprocess.Popen(
        ["bluetoothctl", "scan", "on"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    await asyncio.sleep(scan_timeout)

    scan_proc.terminate()
    run_cmd(["bluetoothctl", "scan", "off"])

    # Find Oura device
    success, stdout, _ = run_cmd(["bluetoothctl", "devices"])
    oura_rpa = None
    for line in stdout.splitlines():
        if "Oura" in line:
            parts = line.split()
            if len(parts) >= 2:
                oura_rpa = parts[1]
                break

    if not oura_rpa:
        log('error', "Oura Ring not found!")
        log('info', "Make sure it's in pairing mode (white light on charger, then remove)")
        return None

    log('success', f"Found Oura Ring at: {oura_rpa}")

    # Step 2: Pair with the ring
    log('info', f"[2/5] Pairing with {oura_rpa}...")
    success, stdout, stderr = run_cmd(["bluetoothctl", "pair", oura_rpa], timeout=30)
    if not success and "Already Paired" not in stderr:
        log('info', f"Pairing output: {stdout} {stderr}")

    await asyncio.sleep(2)

    # Get identity address
    success, stdout, _ = run_cmd(["bluetoothctl", "devices", "Paired"])
    identity_addr = None
    for line in stdout.splitlines():
        if "Oura" in line:
            parts = line.split()
            if len(parts) >= 2:
                identity_addr = parts[1]
                break

    if not identity_addr:
        identity_addr = oura_rpa

    log('info', f"Identity address: {identity_addr}")

    # Step 3: Trust the device
    log('info', "[3/5] Trusting device...")
    success, stdout, stderr = run_cmd(["bluetoothctl", "trust", identity_addr])
    if success:
        log('success', "Trusted!")
    else:
        log('warn', f"Trust output: {stdout} {stderr}")

    # Step 4: Enable kernel auto-connect
    log('info', "[4/5] Enabling kernel auto-connect (btmgmt add-device -a 2)...")
    success, stdout, stderr = run_cmd([
        "sudo", "btmgmt", "--index", str(adapter_index),
        "add-device", "-a", "2", "-t", "1", identity_addr
    ])
    log('info', f"  {stdout}")
    if stderr:
        log('warn', f"  {stderr}")

    # Step 5: Verify bond
    log('info', "[5/5] Verifying bond...")
    bond_file = Path(f"/var/lib/bluetooth/{adapter_addr}/{identity_addr}/info")
    if bond_file.exists():
        log('success', f"Bond file exists: {bond_file}")
        try:
            content = bond_file.read_text()
            for i, line in enumerate(content.splitlines()):
                if "[IdentityResolvingKey]" in line:
                    lines = content.splitlines()
                    if i + 1 < len(lines) and "Key=" in lines[i + 1]:
                        irk = lines[i + 1].split("=")[1]
                        log('info', f"IRK: {irk}")
                    break
        except:
            pass
    else:
        log('warn', f"Bond file not found at {bond_file}")

    # Done!
    log('success', "=" * 60)
    log('success', "  BONDING COMPLETE!")
    log('success', "=" * 60)
    log('info', f"Identity Address: {identity_addr}")
    log('info', "Kernel Action: Auto-connect (0x02)")
    log('info', "")
    log('info', "The kernel will now automatically connect when")
    log('info', "the ring advertises (with any RPA).")

    # Save the bonded address
    try:
        addr_path = data_dir / BONDED_ADDRESS_FILE
        addr_path.parent.mkdir(parents=True, exist_ok=True)
        with open(addr_path, 'w') as f:
            f.write(identity_addr)
        log('success', f"Saved identity address to {addr_path}")
    except Exception as e:
        log('warn', f"Could not save address: {e}")

    return identity_addr


async def remove_bond(
    address: str,
    adapter: str = DEFAULT_ADAPTER,
    log_callback: Optional[Callable[[str, str], None]] = None
) -> bool:
    """Remove bond with a device.

    Args:
        address: Device MAC address
        adapter: Bluetooth adapter
        log_callback: Optional callback for log messages

    Returns:
        True if successful
    """
    def log(level: str, msg: str):
        if log_callback:
            log_callback(level, msg)
        else:
            print(f"[{level}] {msg}")

    log('info', f"Removing bond with {address}...")

    # Remove from bluetoothctl
    success, stdout, stderr = run_cmd(["bluetoothctl", "remove", address])
    if success:
        log('success', "Bond removed via bluetoothctl")
    else:
        log('warn', f"bluetoothctl remove: {stderr}")

    # Remove from btmgmt
    adapter_index = get_adapter_index(adapter)
    success, stdout, stderr = run_cmd([
        "sudo", "btmgmt", "--index", str(adapter_index),
        "rm-device", address
    ])
    if success:
        log('success', "Device removed from btmgmt")
    else:
        log('warn', f"btmgmt rm-device: {stderr}")

    return True
