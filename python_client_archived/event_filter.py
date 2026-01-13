"""
Event filtering for Oura Ring data retrieval.

Provides whitelist/blacklist filtering by event type and pre-defined filter presets.
"""

from typing import Set, Union


class EventFilter:
    """Filter events by type using whitelist or blacklist patterns."""

    def __init__(self):
        self.whitelist: Set[int] = set()  # Only include these types (if non-empty)
        self.blacklist: Set[int] = set()  # Exclude these types

    def add_whitelist(self, *event_types: Union[int, str]):
        """
        Add event types to whitelist (hex or int).

        Args:
            *event_types: Event type codes as int or hex string (e.g., 0x6a or "0x6a")

        Example:
            filter.add_whitelist(0x6a, 0x46)
            filter.add_whitelist("0x6a", "0x46")
        """
        for t in event_types:
            self.whitelist.add(t if isinstance(t, int) else int(t, 16))

    def add_blacklist(self, *event_types: Union[int, str]):
        """
        Add event types to blacklist (hex or int).

        Args:
            *event_types: Event type codes as int or hex string (e.g., 0x43 or "0x43")

        Example:
            filter.add_blacklist(0x43, 0x61)
            filter.add_blacklist("0x43", "0x61")
        """
        for t in event_types:
            self.blacklist.add(t if isinstance(t, int) else int(t, 16))

    def clear(self):
        """Clear all filters (both whitelist and blacklist)."""
        self.whitelist.clear()
        self.blacklist.clear()

    def should_include(self, event_type: int) -> bool:
        """
        Check if event should be included based on filters.

        Rules:
        1. If whitelist exists and is non-empty, only include whitelisted types
        2. If blacklist exists, exclude blacklisted types
        3. Whitelist takes precedence over blacklist

        Args:
            event_type: Event type code (0x00-0xFF)

        Returns:
            True if event should be included, False otherwise
        """
        # If whitelist exists, only include whitelisted types
        if self.whitelist and event_type not in self.whitelist:
            return False
        # Exclude blacklisted types
        if event_type in self.blacklist:
            return False
        return True


# ============================================================================
# Pre-defined Filter Presets
# ============================================================================

# Sleep-related events (from Android app sleeplist)
SLEEP_EVENTS = {
    0x48,  # SLEEP_ACM_PERIOD
    0x49,  # SLEEP_TEMP_EVENT
    0x4a,  # HRV_EVENT
    0x4b,  # ALERT_EVENT
    0x55,  # SLEEP_SUMMARY_1
    0x68,  # SLEEP_PHASE_INFO
    0x69,  # SLEEP_SUMMARY_2
    0x6a,  # SLEEP_PERIOD_INFO_2 (primary sleep data)
    0x6b,  # RING_SLEEP_FEATURE
    0x6c,  # SLEEP_PHASE_DETAILS
    0x6d,  # SLEEP_SUMMARY_3
    0x6e,  # SLEEP_HR
    0x6f,  # RING_SLEEP_FEATURE_2
    0x70,  # SLEEP_SUMMARY_4
    0x71,  # SLEEP_PHASE_DATA
    0x72,  # SLEEP_ACM_PERIOD (duplicate from 0x48?)
    0x75,  # SLEEP_TEMP_EVENT (duplicate from 0x49?)
    0x76,  # BEDTIME_PERIOD
}

# Heart rate and HRV related events
HEART_RATE_EVENTS = {
    0x4a,  # HRV_EVENT
    0x60,  # IBI_AND_AMPLITUDE
    0x61,  # MEAS_QUALITY
    0x62,  # GREEN_IBI_QUALITY
    0x64,  # SPO2_IBI_AMPLITUDE
    0x6a,  # SLEEP_PERIOD_INFO_2 (includes HR data)
    0x6e,  # SLEEP_HR
    0x80,  # GREEN_IBI_QUALITY_EVENT (from real data)
}

# Temperature related events
TEMP_EVENTS = {
    0x46,  # TEMP_EVENT
    0x49,  # SLEEP_TEMP_EVENT
    0x56,  # TEMP_PERIOD
    0x75,  # SLEEP_TEMP_EVENT (duplicate?)
}

# Activity and motion events
ACTIVITY_EVENTS = {
    0x45,  # MOTION_EVENT
    0x47,  # BEDTIME_PERIOD
    0x48,  # SLEEP_ACM_PERIOD
    0x4e,  # REAL_STEPS_FEATURES
    0x4f,  # FEATURE_SESSION
    0x52,  # ACTIVITY_INFO
    0x5f,  # MOTION_PERIOD
    0x72,  # SLEEP_ACM_PERIOD
}

# Debug and diagnostics events (commonly blacklisted)
DEBUG_EVENTS = {
    0x43,  # DEBUG_EVENT
    0x61,  # MEAS_QUALITY (sometimes noisy)
    0x66,  # REP_DEBUG_DATA
    0x67,  # EXCEPTION_LOG
}

# System and status events
SYSTEM_EVENTS = {
    0x41,  # RING_START_IND
    0x42,  # TIME_SYNC_IND
    0x4c,  # BATTERY_LEVEL
    0x4d,  # STATE_CHANGE
    0x51,  # WEAR_EVENT
    0x57,  # BLE_USAGE_STATS
    0x58,  # BLE_MODE_SWITCH
    0x5b,  # BLE_CONNECTION_IND
    0x5c,  # FLASH_USAGE_STATS
    0x5d,  # SCAN_START
    0x5e,  # SCAN_END
}


def create_sleep_filter() -> EventFilter:
    """Create filter for sleep-related events only."""
    f = EventFilter()
    f.whitelist = SLEEP_EVENTS.copy()
    return f


def create_hr_filter() -> EventFilter:
    """Create filter for heart rate events only."""
    f = EventFilter()
    f.whitelist = HEART_RATE_EVENTS.copy()
    return f


def create_no_debug_filter() -> EventFilter:
    """Create filter that excludes debug events."""
    f = EventFilter()
    f.blacklist = DEBUG_EVENTS.copy()
    return f


if __name__ == "__main__":
    # Test the filter
    print("Testing EventFilter...")

    f = EventFilter()
    print(f"\nEmpty filter: 0x6a included = {f.should_include(0x6a)}")  # True

    f.add_whitelist(0x6a, 0x46)
    print(f"Whitelist [0x6a, 0x46]: 0x6a included = {f.should_include(0x6a)}")  # True
    print(f"Whitelist [0x6a, 0x46]: 0x43 included = {f.should_include(0x43)}")  # False

    f.clear()
    f.add_blacklist(0x43, 0x61)
    print(f"\nBlacklist [0x43, 0x61]: 0x6a included = {f.should_include(0x6a)}")  # True
    print(f"Blacklist [0x43, 0x61]: 0x43 included = {f.should_include(0x43)}")  # False

    print(f"\nSleep events preset: {len(SLEEP_EVENTS)} types")
    print(f"Heart rate events preset: {len(HEART_RATE_EVENTS)} types")
    print(f"Debug events preset: {len(DEBUG_EVENTS)} types")
