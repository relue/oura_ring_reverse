"""
BLE WebSocket Handler

Manages BLE connection and streams output to WebSocket clients.
"""

import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import WebSocket

# Add parent paths for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from oura.ble.client import OuraClient
from oura.ble.bonding import bond_ring, list_bluetooth_adapters
from oura.ble.protocol import EventFilter, FILTER_PRESETS, DEFAULT_DATA_DIR


class BLEConnectionManager:
    """Manages single BLE connection shared across WebSocket clients."""

    def __init__(self):
        self.client: Optional[OuraClient] = None
        self.websockets: List[WebSocket] = []
        self.is_busy: bool = False
        self.current_action: Optional[str] = None
        self.adapter: str = "hci0"
        self._heartbeat_task: Optional[asyncio.Task] = None

    async def broadcast(self, message: dict):
        """Send message to all connected WebSocket clients."""
        disconnected = []
        for ws in self.websockets:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(ws)

        # Remove disconnected clients
        for ws in disconnected:
            if ws in self.websockets:
                self.websockets.remove(ws)

    async def send_log(self, level: str, message: str):
        """Send log message to clients."""
        await self.broadcast({
            "type": "log",
            "level": level,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })

    async def send_status(self):
        """Send current status to clients."""
        await self.broadcast({
            "type": "status",
            "connected": self.client.is_connected if self.client else False,
            "authenticated": self.client.is_authenticated if self.client else False,
            "is_busy": self.is_busy,
            "current_action": self.current_action,
            "adapter": self.adapter
        })

    def _setup_client_callbacks(self):
        """Wire up client callbacks to WebSocket broadcast."""
        if not self.client:
            return

        # Log callback
        def on_log(level: str, message: str):
            asyncio.create_task(self.send_log(level, message))

        # Heartbeat callback
        def on_heartbeat(count: int, ibi: int, bpm: float, flag: int):
            asyncio.create_task(self.broadcast({
                "type": "heartbeat",
                "bpm": round(bpm, 1),
                "ibi": ibi,
                "count": count
            }))

        # Progress callback
        def on_progress(action: str, current: int, total: int, label: str):
            asyncio.create_task(self.broadcast({
                "type": "progress",
                "action": action,
                "current": current,
                "total": total,
                "label": label
            }))

        # Sync point callback
        def on_sync_point(sync_point: dict):
            asyncio.create_task(self.broadcast({
                "type": "sync",
                "ring_time": sync_point['ring_time'],
                "utc_millis": sync_point['utc_millis'],
                "timestamp": sync_point['timestamp']
            }))

        # Status change callback
        def on_status_change(status: dict):
            asyncio.create_task(self.send_status())

        self.client.on_log = on_log
        self.client.on_heartbeat = on_heartbeat
        self.client.on_progress = on_progress
        self.client.on_sync_point = on_sync_point
        self.client.on_status_change = on_status_change

    async def connect_ring(self, adapter: Optional[str] = None) -> bool:
        """Connect to ring with output streaming."""
        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "connect"
        await self.send_status()

        try:
            if adapter:
                self.adapter = adapter

            self.client = OuraClient(adapter=self.adapter)
            self._setup_client_callbacks()

            success = await self.client.connect()

            await self.broadcast({
                "type": "complete",
                "action": "connect",
                "success": success
            })

            return success
        except Exception as e:
            await self.send_log("error", f"Connection error: {e}")
            return False
        finally:
            self.is_busy = False
            self.current_action = None
            await self.send_status()

    async def disconnect_ring(self):
        """Disconnect from ring."""
        if self.client:
            await self.client.disconnect()
            self.client = None

        await self.send_status()
        await self.broadcast({
            "type": "complete",
            "action": "disconnect",
            "success": True
        })

    async def authenticate(self, key_hex: Optional[str] = None) -> bool:
        """Authenticate with ring."""
        if not self.client or not self.client.is_connected:
            await self.send_log("error", "Not connected")
            return False

        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "auth"
        await self.send_status()

        try:
            auth_key = None
            if key_hex:
                try:
                    auth_key = bytes.fromhex(key_hex.replace(' ', ''))
                except ValueError:
                    await self.send_log("error", "Invalid auth key hex")
                    return False

            success = await self.client.authenticate(auth_key)

            await self.broadcast({
                "type": "complete",
                "action": "auth",
                "success": success
            })

            return success
        except Exception as e:
            await self.send_log("error", f"Auth error: {e}")
            return False
        finally:
            self.is_busy = False
            self.current_action = None
            await self.send_status()

    async def sync_time(self) -> bool:
        """Sync time with ring."""
        if not self.client or not self.client.is_authenticated:
            await self.send_log("error", "Not authenticated")
            return False

        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "sync-time"
        await self.send_status()

        try:
            await self.client.sync_time()
            await asyncio.sleep(1)

            # Save sync point
            self.client.save_sync_point()

            await self.broadcast({
                "type": "complete",
                "action": "sync-time",
                "success": True
            })

            return True
        except Exception as e:
            await self.send_log("error", f"Sync error: {e}")
            return False
        finally:
            self.is_busy = False
            self.current_action = None
            await self.send_status()

    async def get_data(self, filters: Optional[Dict[str, Any]] = None) -> bool:
        """Get data from ring with optional filters."""
        if not self.client or not self.client.is_authenticated:
            await self.send_log("error", "Not authenticated")
            return False

        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "get-data"
        await self.send_status()

        try:
            # Sync time first
            await self.send_log("info", "Capturing time sync point...")
            await self.client.sync_time()
            await asyncio.sleep(1)

            # Build filter
            event_filter = None
            if filters:
                preset = filters.get('preset')
                whitelist = filters.get('whitelist', [])

                if preset and preset != 'all':
                    event_filter = EventFilter.from_preset(preset)

                if whitelist:
                    event_filter = event_filter or EventFilter()
                    for t in whitelist:
                        if isinstance(t, str):
                            t = int(t, 16) if t.startswith('0x') else int(t)
                        event_filter.add_whitelist(t)

            # Fetch data
            data = await self.client.get_data(event_filter=event_filter, fetch_all=True)

            # Save files
            self.client.save_sync_point()
            self.client.save_events_to_file()

            # Clear cached reader so dashboard uses fresh data
            import main
            main._analyzer = None
            main._reader = None
            await self.send_log("info", "Data cache refreshed")

            await self.broadcast({
                "type": "complete",
                "action": "get-data",
                "success": True,
                "event_count": len(data)
            })

            return True
        except Exception as e:
            await self.send_log("error", f"Get data error: {e}")
            return False
        finally:
            self.is_busy = False
            self.current_action = None
            await self.send_status()

    async def start_heartbeat(self) -> bool:
        """Start heartbeat monitoring."""
        if not self.client or not self.client.is_authenticated:
            await self.send_log("error", "Not authenticated")
            return False

        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "heartbeat"
        await self.send_status()

        try:
            # Start heartbeat in background task
            self._heartbeat_task = asyncio.create_task(
                self.client.start_heartbeat()
            )
            return True
        except Exception as e:
            await self.send_log("error", f"Heartbeat error: {e}")
            self.is_busy = False
            self.current_action = None
            await self.send_status()
            return False

    async def stop_heartbeat(self):
        """Stop heartbeat monitoring."""
        if self.client:
            await self.client.stop_heartbeat()

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        self.is_busy = False
        self.current_action = None
        await self.send_status()

        await self.broadcast({
            "type": "complete",
            "action": "heartbeat",
            "success": True
        })

    async def bond_ring_async(self, adapter: Optional[str] = None) -> bool:
        """Bond with ring (async wrapper)."""
        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "bond"
        await self.send_status()

        try:
            if adapter:
                self.adapter = adapter

            identity = await bond_ring(
                adapter=self.adapter,
                log_callback=lambda level, msg: asyncio.create_task(self.send_log(level, msg))
            )

            await self.broadcast({
                "type": "complete",
                "action": "bond",
                "success": identity is not None,
                "identity_address": identity
            })

            return identity is not None
        except Exception as e:
            await self.send_log("error", f"Bond error: {e}")
            return False
        finally:
            self.is_busy = False
            self.current_action = None
            await self.send_status()

    async def factory_reset(self) -> bool:
        """Factory reset the ring (DANGEROUS)."""
        if not self.client or not self.client.is_connected:
            await self.send_log("error", "Not connected")
            return False

        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "factory-reset"
        await self.send_status()

        try:
            success = await self.client.factory_reset(confirmed=True)

            await self.broadcast({
                "type": "complete",
                "action": "factory-reset",
                "success": success
            })

            return success
        except Exception as e:
            await self.send_log("error", f"Factory reset error: {e}")
            return False
        finally:
            self.is_busy = False
            self.current_action = None
            await self.send_status()

    async def update_ring(self) -> bool:
        """Update ring data: incremental sync + parse.

        This is the main "Update Ring" action for the UI.
        Does NOT sync time - uses existing sync point for time reference.
        """
        if not self.client or not self.client.is_authenticated:
            await self.send_log("error", "Not authenticated")
            return False

        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "update-ring"
        await self.send_status()

        try:
            # Step 1: Load existing sync point (don't call sync_time!)
            await self.send_log("info", "Loading sync point...")
            if not self.client.load_sync_point():
                await self.send_log("error", "No sync point found. Run full Get Data first.")
                return False

            # Step 2: Fetch incremental data
            await self.send_log("info", "Fetching new events...")
            data = await self.client.get_data_incremental()

            if data:
                # Save events to file
                self.client.save_events_to_file(append=True)
                await self.send_log("success", f"Fetched {len(data)} new events")

                # Step 3: Parse events to protobuf
                await self.send_log("info", "Parsing events...")
                parse_success = await self._do_parse()

                if parse_success:
                    await self.broadcast({
                        "type": "complete",
                        "action": "update-ring",
                        "success": True,
                        "event_count": len(data)
                    })
                    return True
                else:
                    await self.send_log("error", "Parse failed after sync")
                    return False
            else:
                await self.send_log("info", "No new events to fetch")
                await self.broadcast({
                    "type": "complete",
                    "action": "update-ring",
                    "success": True,
                    "event_count": 0
                })
                return True

        except Exception as e:
            await self.send_log("error", f"Update ring error: {e}")
            return False
        finally:
            self.is_busy = False
            self.current_action = None
            await self.send_status()

    async def _do_parse(self) -> bool:
        """Internal helper to run parser and refresh cache."""
        from oura.native.parser import parse_events_async, check_parser_available

        available, msg = check_parser_available()
        if not available:
            await self.send_log("error", f"Parser not available: {msg}")
            return False

        def log_callback(level: str, message: str):
            asyncio.create_task(self.send_log(level, message))

        result = await parse_events_async(log_callback=log_callback)

        if result.success:
            await self.send_log("success",
                f"Parsed {result.input_events} events -> {result.output_size} bytes")

            # Clear cached reader so dashboard uses fresh data
            import main
            main._analyzer = None
            main._reader = None
            await self.send_log("info", "Data cache refreshed")
            return True
        else:
            await self.send_log("error", f"Parse failed: {result.error}")
            return False

    async def parse_events(self) -> bool:
        """Parse events file to protobuf using native parser."""
        if self.is_busy:
            await self.send_log("error", "Operation in progress")
            return False

        self.is_busy = True
        self.current_action = "parse"
        await self.send_status()

        try:
            from oura.native.parser import parse_events_async, check_parser_available

            # Check parser available
            available, msg = check_parser_available()
            if not available:
                await self.send_log("error", f"Parser not available: {msg}")
                return False

            await self.send_log("info", "Starting native parser (QEMU)...")

            # Run parser with log callback
            def log_callback(level: str, message: str):
                asyncio.create_task(self.send_log(level, message))

            result = await parse_events_async(log_callback=log_callback)

            if result.success:
                await self.send_log("success",
                    f"Parsed {result.input_events} events -> {result.output_size} bytes")

                # Clear cached reader so dashboard uses fresh data
                import main
                main._analyzer = None
                main._reader = None
                await self.send_log("info", "Data cache refreshed")

            await self.broadcast({
                "type": "complete",
                "action": "parse",
                "success": result.success,
                "input_events": result.input_events,
                "output_size": result.output_size,
                "duration": result.duration_sec,
                "error": result.error
            })

            return result.success
        except Exception as e:
            await self.send_log("error", f"Parse error: {e}")
            return False
        finally:
            self.is_busy = False
            self.current_action = None
            await self.send_status()


# Global instance
ble_manager = BLEConnectionManager()


def get_ble_manager() -> BLEConnectionManager:
    """Get the global BLE connection manager."""
    return ble_manager
