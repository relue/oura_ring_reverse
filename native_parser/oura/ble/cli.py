#!/usr/bin/env python3
"""
Oura Ring BLE CLI

Command-line interface for Oura Ring BLE operations.

Usage:
    # Interactive mode with full menu
    python -m oura.ble.cli

    # Bond with ring (must be in pairing mode!)
    python -m oura.ble.cli --bond

    # Live heartbeat monitoring (requires auth)
    python -m oura.ble.cli --heartbeat

    # Get stored data from ring
    python -m oura.ble.cli --get-data

    # Get ALL data with time sync
    python -m oura.ble.cli --get-all-data

    # Get only NEW data since last sync (like Oura app - prevents duplicates!)
    python -m oura.ble.cli --get-data-incremental

    # Sync time with ring
    python -m oura.ble.cli --sync-time
"""

import asyncio
import argparse
import sys
from datetime import datetime
from pathlib import Path

from oura.ble.client import OuraClient
from oura.ble.bonding import bond_ring, list_bluetooth_adapters
from oura.ble.protocol import (
    DEFAULT_ADAPTER, DEFAULT_AUTH_KEY, DEFAULT_DATA_DIR,
    EventFilter, FILTER_PRESETS, format_hex, get_event_name
)


async def interactive_mode(client: OuraClient):
    """Run interactive menu."""
    print("\n" + "=" * 60)
    print("OURA RING BLE CLIENT - INTERACTIVE MODE")
    print("=" * 60)

    while True:
        print("\n--- Menu ---")
        print("0. Bond Ring (pairing mode required)")
        print("1. Scan and Connect")
        print("2. Authenticate")
        print("3. Start Heartbeat Monitoring")
        print("4. Get Data")
        print("5. Get Data (with filters)")
        print("6. Sync Time and Save")
        print("7. Set Auth Key")
        print("8. Factory Reset (DANGEROUS)")
        print("9. Disconnect")
        print("10. Exit")

        try:
            choice = input("\nChoice: ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == '0':
            identity = await bond_ring(adapter=client.adapter)
            if identity:
                print(f"\nBonding successful! You can now use option 1 to connect.")
        elif choice == '1':
            await client.connect()
        elif choice == '2':
            if not client.is_connected:
                print("Connect first!")
            else:
                key_hex = input("Auth key (hex, 32 chars) or Enter for stored: ").strip()
                if key_hex:
                    try:
                        key = bytes.fromhex(key_hex.replace(' ', ''))
                        await client.authenticate(key)
                    except ValueError:
                        print("Invalid hex!")
                else:
                    await client.authenticate()
        elif choice == '3':
            await client.start_heartbeat()
        elif choice == '4':
            data = await client.get_data()
            print(f"Got {len(data)} events")
            if data:
                save = input("Save to file? (y/n): ").strip().lower()
                if save == 'y':
                    client.save_events_to_file()
        elif choice == '5':
            print("\nFilter options:")
            print("1. Sleep events only")
            print("2. Heart rate events only")
            print("3. Temperature events only")
            print("4. Custom whitelist")
            filter_choice = input("Choice (or Enter to skip): ").strip()

            event_filter = None
            if filter_choice == '1':
                event_filter = EventFilter.from_preset('sleep')
            elif filter_choice == '2':
                event_filter = EventFilter.from_preset('heart_rate')
            elif filter_choice == '3':
                event_filter = EventFilter.from_preset('temperature')
            elif filter_choice == '4':
                event_filter = EventFilter()
                types = input("Whitelist (space-separated hex, e.g. 0x6a 0x46): ").strip().split()
                for t in types:
                    try:
                        event_filter.add_whitelist(int(t, 16))
                    except ValueError:
                        print(f"Invalid hex: {t}")

            data = await client.get_data(event_filter=event_filter)
            print(f"Got {len(data)} events")
        elif choice == '6':
            await client.sync_time()
            await asyncio.sleep(1)
            client.save_sync_point()
        elif choice == '7':
            key_hex = input("New auth key (hex, 32 chars): ").strip()
            try:
                key = bytes.fromhex(key_hex.replace(' ', ''))
                await client.set_auth_key(key)
            except ValueError:
                print("Invalid hex!")
        elif choice == '8':
            confirm = input("Type 'FACTORY RESET' to confirm: ").strip()
            if confirm == "FACTORY RESET":
                await client.factory_reset(confirmed=True)
            else:
                print("Cancelled")
        elif choice == '9':
            await client.disconnect()
        elif choice == '10':
            break

    await client.disconnect()
    print("\nGoodbye!")


async def main():
    parser = argparse.ArgumentParser(
        description='Oura Ring BLE Client',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Actions
    parser.add_argument('--heartbeat', action='store_true',
                        help='Start heartbeat monitoring')
    parser.add_argument('--get-data', action='store_true',
                        help='Get stored data from ring')
    parser.add_argument('--get-all-data', action='store_true',
                        help='Get ALL stored data (with time sync)')
    parser.add_argument('--get-data-incremental', action='store_true',
                        help='Get only NEW data since last sync (like Oura app)')
    parser.add_argument('--sync-time', action='store_true',
                        help='Sync time with ring and save sync point')
    parser.add_argument('--bond', action='store_true',
                        help='Bond with ring (must be in pairing mode)')
    parser.add_argument('--set-auth-key',
                        help='Set new auth key on ring (32 hex chars)')
    parser.add_argument('--factory-reset', action='store_true',
                        help='DANGEROUS: Factory reset the ring')
    parser.add_argument('--list-adapters', action='store_true',
                        help='List available Bluetooth adapters')

    # Options
    parser.add_argument('--output', '-o',
                        default=str(DEFAULT_DATA_DIR / 'ring_events.txt'),
                        help='Output file for events')
    parser.add_argument('--sync-point-file',
                        default=str(DEFAULT_DATA_DIR / 'sync_point.json'),
                        help='Sync point output file')
    parser.add_argument('--duration', '-d', type=int,
                        help='Duration in seconds (for heartbeat)')
    parser.add_argument('--auth-key', '-k',
                        help='Auth key (32 hex chars)')
    parser.add_argument('--adapter', default=DEFAULT_ADAPTER,
                        help=f'BLE adapter (default: {DEFAULT_ADAPTER})')
    parser.add_argument('--data-dir',
                        default=str(DEFAULT_DATA_DIR),
                        help='Data directory for storage')

    # Filtering
    parser.add_argument('--filter', choices=['all', 'sleep', 'heart_rate', 'temperature', 'motion', 'spo2'],
                        default='all',
                        help='Event filter preset')
    parser.add_argument('--filter-whitelist', nargs='+',
                        help='Only include these event types (hex)')
    parser.add_argument('--no-debug', action='store_true',
                        help='Exclude debug events (0x43, 0x5b, 0x66, 0x67) - reduces data ~40%%')
    parser.add_argument('--scan-timeout', type=float, default=15.0,
                        help='Scan timeout for bonding')

    args = parser.parse_args()

    # Handle list-adapters
    if args.list_adapters:
        adapters = list_bluetooth_adapters()
        print("Available Bluetooth adapters:")
        for adapter in adapters:
            print(f"  {adapter}")
        return 0

    # Parse auth key
    auth_key = None
    if args.auth_key:
        try:
            auth_key = bytes.fromhex(args.auth_key.replace(' ', ''))
        except ValueError:
            print("Invalid auth key hex!")
            return 1

    # Handle bonding (separate from other operations)
    if args.bond:
        identity = await bond_ring(
            adapter=args.adapter,
            scan_timeout=args.scan_timeout,
            data_dir=Path(args.data_dir)
        )
        return 0 if identity else 1

    # Run interactive mode if no specific action
    if not (args.heartbeat or args.get_data or args.get_all_data or
            args.get_data_incremental or args.sync_time or args.set_auth_key or
            args.factory_reset):
        client = OuraClient(
            adapter=args.adapter,
            auth_key=auth_key,
            data_dir=Path(args.data_dir)
        )
        await interactive_mode(client)
        return 0

    # Create client and run specific action
    client = OuraClient(
        adapter=args.adapter,
        auth_key=auth_key,
        data_dir=Path(args.data_dir)
    )

    if not await client.connect():
        return 1

    try:
        # Factory reset (no auth needed)
        if args.factory_reset:
            confirm = input("Type 'FACTORY RESET' to confirm: ").strip()
            if confirm == "FACTORY RESET":
                await client.factory_reset(confirmed=True)
            return 0

        # Set auth key
        if args.set_auth_key:
            new_key = bytes.fromhex(args.set_auth_key.replace(' ', ''))
            await client.set_auth_key(new_key)
            return 0

        # Authenticate for other operations
        if args.heartbeat or args.get_data or args.get_all_data or args.get_data_incremental or args.sync_time:
            if not await client.authenticate():
                print("Authentication failed!")
                return 1

        # Sync time
        if args.sync_time:
            await client.sync_time()
            await asyncio.sleep(1)
            client.save_sync_point(args.sync_point_file)
            return 0

        # Heartbeat
        if args.heartbeat:
            await client.start_heartbeat(args.duration)
            return 0

        # Incremental data sync (like Oura app)
        if args.get_data_incremental:
            print("\n=== INCREMENTAL SYNC (like Oura app) ===")
            print("This only fetches NEW events since last sync.\n")
            # Load existing sync point (don't sync time - just use saved reference)
            if not client.load_sync_point(args.sync_point_file):
                print("ERROR: No sync point found. Run --sync-time or --get-all-data first.")
                return 1

            # Build filter
            event_filter = None
            if args.filter != 'all':
                event_filter = EventFilter.from_preset(args.filter)
            if args.filter_whitelist:
                event_filter = event_filter or EventFilter()
                for t in args.filter_whitelist:
                    event_filter.add_whitelist(int(t, 16))

            # Fetch only new data
            data = await client.get_data_incremental(
                event_filter=event_filter,
                sync_point_file=args.sync_point_file
            )

            # Save events if any (append for incremental sync)
            if data:
                client.save_events_to_file(args.output, append=True)
                print(f"\nAppended {len(data)} new events to {args.output}")
            else:
                print("\nNo new events to save.")
            return 0

        # Get data (full)
        if args.get_all_data or args.get_data:
            # Sync time first
            print("\n=== Capturing time sync point ===")
            await client.sync_time()
            await asyncio.sleep(1)

            # Build filter
            event_filter = None
            if args.filter != 'all':
                event_filter = EventFilter.from_preset(args.filter)
            if args.filter_whitelist:
                event_filter = event_filter or EventFilter()
                for t in args.filter_whitelist:
                    event_filter.add_whitelist(int(t, 16))
            if args.no_debug:
                event_filter = event_filter or EventFilter()
                # Blacklist debug/diagnostic events:
                # 0x43: API_DEBUG_EVENT (~274K)
                # 0x5b: API_BLE_CONNECTION_IND (~18K)
                # 0x5c: API_FLASH_USAGE_STATS
                # 0x79: UNKNOWN_79 (~34K, likely debug)
                # 0x82, 0x83: UNKNOWN (~3K, likely debug)
                debug_tags = [0x43, 0x5b, 0x5c, 0x79, 0x82, 0x83]
                for tag in debug_tags:
                    event_filter.add_blacklist(tag)
                print(f"[>] Debug events filtered out: {[hex(t) for t in debug_tags]}")

            # Fetch data (start from 0 for full sync - no binary search needed)
            data = await client.get_data(
                start_seq=0 if args.get_all_data else -1,
                event_filter=event_filter,
                fetch_all=args.get_all_data
            )

            # Calculate last_synced_seq from number of events fetched
            last_seq = None
            if data and args.get_all_data:
                # For full fetch starting at seq 0, last seq = num events - 1
                last_seq = len(data) - 1
                print(f"\nUpdating last_synced_seq to {last_seq}")

            # Save
            client.save_sync_point(args.sync_point_file, last_synced_seq=last_seq)
            client.save_events_to_file(args.output)
            return 0

    finally:
        await client.disconnect()

    return 0


def cli_main():
    """Entry point for CLI."""
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nInterrupted!")
        sys.exit(0)


if __name__ == "__main__":
    cli_main()
