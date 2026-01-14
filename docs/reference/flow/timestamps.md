# Timestamp Handling

How timestamps flow from ring to readable UTC times.

---

## Timestamp Formats

The ring uses two timestamp formats:

| Format | Value Range | Example | Used In |
|--------|-------------|---------|---------|
| Ring Deciseconds | ~1-3 million | `2222080` | Events file, sync point |
| UTC Milliseconds | ~1.7 trillion | `1768331460260` | Protobuf data |

### Ring Deciseconds

- Unit: 1/10th of a second since ring boot/reset
- Range: Resets when ring restarts or factory resets
- Example: `2222080` = 61.7 hours of uptime

### UTC Milliseconds

- Unit: Milliseconds since Unix epoch (Jan 1, 1970)
- Example: `1768331460260` = 2026-01-13 20:11:00

---

## Sync Point Mechanism

The ring's internal clock (deciseconds) must be converted to real-world time using a **sync point**.

### Capturing Sync Point

```python
# During time sync, we capture:
sync_point = {
    "ring_time": 2222080,           # Ring deciseconds at sync
    "utc_millis": 1768389959767,    # UTC ms at same moment
    "timestamp": "2026-01-14T12:25:59"
}
```

### Conversion Formula

```python
def ring_to_utc_ms(ring_deciseconds: int) -> int:
    """Convert ring time to UTC milliseconds."""
    ring_ms = ring_deciseconds * 100  # deciseconds -> ms
    delta_ms = sync_point.utc_millis - (sync_point.ring_time * 100)
    return ring_ms + delta_ms
```

### Files

| File | Purpose |
|------|---------|
| `input_data/sync_point.json` | Stored sync point |
| `input_data/ring_events.txt` | Raw events with ring timestamps |
| `input_data/ring_data.pb` | Parsed protobuf (UTC timestamps) |

---

## Data Flow

```
Ring (deciseconds)
     │
     ▼ BLE fetch
ring_events.txt (ring deciseconds in hex)
     │
     ▼ Native parser + sync point
ring_data.pb (UTC milliseconds)
     │
     ▼ RingDataReader
Python datetime objects
```

### Event File Format

```
# index|tag_hex|event_name|hex_data
0|0x6a|API_SLEEP_PERIOD_INFO|6a0c00e8210048510100...
       │                      │
       │                      └─ Bytes 2-5: timestamp (little-endian)
       └─ Event type tag
```

### Extracting Timestamp from Hex

```python
hex_data = "6a0c00e82100..."
ts_hex = hex_data[4:12]  # Skip tag (2) + length (2)
ts_bytes = bytes.fromhex(ts_hex)  # "00e82100"
ring_ts = int.from_bytes(ts_bytes, 'little')  # 2222080
```

---

## RingDataReader Behavior

### Timestamp Sources by Data Type

| Data Type | Primary Source | Fallback |
|-----------|----------------|----------|
| Heart Rate | Protobuf (already UTC) | parsed_events.ibi_timestamps |
| Sleep | parsed_events.sleep_timestamps | Protobuf + convert |
| Temperature | parsed_events.temp_timestamps | Protobuf + convert |
| HRV | parsed_events.hrv_timestamps | Protobuf + convert |
| Activity | parsed_events.activity_timestamps | Protobuf + convert |
| SpO2 | parsed_events.spo2_timestamps | Protobuf + convert |
| Motion | parsed_events.motion_timestamps | Protobuf + convert |

### Auto-Detection

The reader detects timestamp format automatically:

```python
def _convert_timestamps(self, timestamps: List[int]) -> List[int]:
    if not timestamps:
        return timestamps

    # Detect if already UTC milliseconds
    first_ts = timestamps[0]
    if first_ts > 1_000_000_000_000:  # > 1 trillion = UTC ms
        return timestamps  # Already correct

    # Convert from ring deciseconds
    if self._sync_point is not None:
        return [self._sync_point.ring_to_utc_ms(ts) for ts in timestamps]

    return timestamps
```

---

## Common Pitfalls

### 1. Double Conversion

**Problem:** Converting already-UTC timestamps as if they were ring deciseconds.

```python
# Wrong:
utc_ts = 1768331460260  # Already UTC ms
converted = sync_point.ring_to_utc_ms(utc_ts)  # Year 7629!

# Right:
if utc_ts > 1_000_000_000_000:
    return utc_ts  # Already UTC, don't convert
```

### 2. Missing Sync Point

**Problem:** No sync point available for conversion.

```python
# Fetch data with time sync:
await client.sync_time()
await client.get_data()
client.save_sync_point()  # Don't forget this!
```

### 3. Stale Sync Point

**Problem:** Using old sync point after ring restart.

```python
# Ring uptime resets on restart
# Always capture fresh sync point before data fetch
```

---

## Validation

Check timestamps are reasonable:

```python
from datetime import datetime

def validate_timestamp(ts_ms: int) -> bool:
    """Check if timestamp is valid UTC milliseconds."""
    try:
        dt = datetime.fromtimestamp(ts_ms / 1000)
        # Should be between 2020 and 2030
        return 2020 <= dt.year <= 2030
    except (ValueError, OSError):
        return False
```

### Quick Sanity Check

| Timestamp | Interpretation |
|-----------|----------------|
| `1768331460260` | 2026-01-13 20:11 ✓ |
| `2222080` | Ring deciseconds (61.7h uptime) |
| `5555123456789012` | Invalid (year 178000+) ✗ |

---

## Usage Examples

### Load Data with Correct Timestamps

```python
from oura.data.reader import RingDataReader

# Recommended: Load with events file for accurate timestamps
reader = RingDataReader.from_events(
    'input_data/ring_data.pb',
    'input_data/ring_events.txt'
)

# Access data with UTC timestamps
for ts, hr in zip(reader.heart_rate.timestamps, reader.heart_rate.ibi_ms):
    dt = datetime.fromtimestamp(ts / 1000)
    bpm = 60000 / hr if hr > 0 else 0
    print(f"{dt}: {bpm:.0f} BPM")
```

### Get Sleep Times

```python
sleep = reader.sleep
bedtime = datetime.fromtimestamp(sleep.timestamps[0] / 1000)
waketime = datetime.fromtimestamp(sleep.timestamps[-1] / 1000)
print(f"Slept: {bedtime} to {waketime}")
```

---

## See Also

- [Processing Flow](processing.md) - Event parsing pipeline
- [BLE Layer](ble-layer.md) - Data fetch from ring
- [Events Reference](../events/_index.md) - Event type definitions
