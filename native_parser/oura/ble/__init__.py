"""
Oura Ring BLE Module

Provides BLE connectivity for Oura Ring Gen 3/4.
"""

from oura.ble.client import OuraClient
from oura.ble.protocol import (
    SERVICE_UUID,
    WRITE_CHAR_UUID,
    NOTIFY_CHAR_UUID,
    EVENT_TYPES,
    SLEEP_EVENT_TYPES,
    get_event_name,
)

__all__ = [
    'OuraClient',
    'SERVICE_UUID',
    'WRITE_CHAR_UUID',
    'NOTIFY_CHAR_UUID',
    'EVENT_TYPES',
    'SLEEP_EVENT_TYPES',
    'get_event_name',
]
