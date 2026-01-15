# Parser Data Loss Analysis

## Problem Statement

When parsing raw ring events, only 2-3 nights of sleep data appear in the output, despite the raw events file containing weeks of data.

**Expected**: All sleep nights from the raw events
**Actual**: Only the most recent 2-3 nights

---

## Root Causes Found

Through reverse engineering `libringeventparser.so` using Ghidra, we identified **two root causes**:

### 1. RING_START_IND Events Clear Session Data

**What happens:**
- `RING_START_IND` (event tag `0x41`) signals the ring powered on or restarted
- The parser calls `Session::clear()` every time this event is encountered
- `Session::clear()` **deletes all accumulated sleep data**

**The code (decompiled):**
```c
if (event_type == 0x41) {  // RING_START_IND
    // ... process ring start ...

    // ALWAYS clear the session - THIS WIPES ALL DATA!
    if (session != NULL) {
        Session::clear(session);
    }
}
```

**What Session::clear() deletes:**
- Sleep period accumulator buffer
- Heart rate / HRV data buffers
- Motion / accelerometer data
- Temperature readings
- All session state flags

**Impact:**
- Our raw events file had **70 RING_START_IND events**
- Session gets cleared 70 times!
- Only data after the LAST clear survives

**Proof:**
| Test | RING_START Events | Nights Output |
|------|-------------------|---------------|
| Original data | 70 | 2 nights |
| Removed RING_START | 0 | 3 nights |

---

### 2. Missing TIME_SYNC After Factory Reset

**What TIME_SYNC does:**
- `TIME_SYNC_IND` (event tag `0x42`) establishes time mapping
- It tells the parser: "ring_time X = UTC time Y"
- Without it, the parser cannot convert ring timestamps to real dates

**The problem after factory reset:**

```
BEFORE Reset (Dec 8 - Jan 10):
├── ring_time: 500,000 - 3,400,000
├── TIME_SYNC events: 134 ✓
└── Parser can convert timestamps ✓

FACTORY RESET (Jan 11):
└── ring_time counter resets to 0

AFTER Reset (Jan 11 - Jan 15):
├── ring_time: 0 - 500,000 (new epoch!)
├── TIME_SYNC events: 0 ✗
└── Parser CANNOT convert timestamps!
```

**Why no TIME_SYNC after reset:**
- TIME_SYNC is created when the ring syncs with the Oura app
- After factory reset, the ring wasn't synced until Jan 13-15
- Jan 11-12 data exists but has no time reference

**What happens without TIME_SYNC:**
```c
if (time_mapping == NULL) {
    // Queue events, waiting for TIME_SYNC
    queued_events.push(event);
}

if (event_type == RING_START && time_mapping == NULL) {
    // Delete all queued events!
    queued_events.clear();
}
```

Events without TIME_SYNC get queued, then deleted when RING_START arrives.

---

## Data Analysis

### Event Distribution

```
Total events: 102,359

Pre-reset (ring_time > 500,000):  82,954 events
Post-reset (ring_time ≤ 500,000): 19,405 events

TIME_SYNC events (all pre-reset): 134
RING_START_IND events: 70
```

### Sleep Data by Source

```
API_SLEEP_PERIOD_INFO:   0 events (old format)
API_SLEEP_PERIOD_INFO_2: 3,072 events (new format)
```

All sleep data uses the `_2` format (tag `0x6a`), which the parser does handle.

---

## Timeline Example

```
Dec 8-Jan 10:  Pre-reset data with TIME_SYNC
               → Can be processed, but RING_START clears it

Jan 11:        Factory reset (ring_time → 0)

Jan 11-12:     Post-reset, NO TIME_SYNC
               → Data exists but can't be time-mapped
               → Gets deleted when RING_START seen

Jan 13-15:     Post-reset, TIME_SYNC exists (from app sync)
               → Data can be processed ✓
               → This is what we see in output
```

---

## Solutions

### Solution 1: Remove RING_START_IND Events

Filter out `RING_START_IND` (tag `0x41`) events before parsing:

```python
# In preprocessing
if '|0x41|' in line or 'RING_START_IND' in line:
    continue  # Skip this event
```

**Result:** Prevents Session::clear() from being called.

### Solution 2: Add Synthetic TIME_SYNC for Post-Reset Data

If you know when the reset happened, add a TIME_SYNC event:

```python
# ring_time 0 = Jan 11 00:00 UTC
jan11_utc_sec = 1736553600  # Jan 11, 2026 00:00:00 UTC

# Create TIME_SYNC event
# Format: tag(0x42) + len + ring_time(4 LE) + utc_sec(4 BE) + extra
synthetic_time_sync = "0|0x42|API_TIME_SYNC_IND|420d00000000{:08x}0000000004".format(
    int.from_bytes(jan11_utc_sec.to_bytes(4, 'big'), 'big')
)
```

### Solution 3: Process Pre/Post Reset Data Separately

1. Split events by ring_time threshold (500,000)
2. Use appropriate sync point for each epoch
3. Merge results

---

## Reverse Engineering Details

### Tools Used

- **Ghidra 11.4**: Static analysis and decompilation
- **aarch64-linux-gnu-objdump**: Symbol extraction
- **QEMU**: Running ARM64 binary on x86

### Key Functions Found

| Function | Address | Purpose |
|----------|---------|---------|
| `parse_events` | 0x355ea8 | Main event processing loop |
| `Session::clear` | 0x36a470 | Clears all session data |
| `parse_api_sleep_period_info` | 0x381f08 | Parses sleep events |
| `TimeResolver::process_api_time_sync_ind` | - | Handles TIME_SYNC |

### Session::clear() Memory Layout

```
Offset   Purpose              Action
──────────────────────────────────────
0x008    Processing state     → 0
0x094    Has-data flag        → 0
0x0c0    Sleep-detected       → 0
0x0e0    Night-started        → 0
0x0f8    Processing-complete  → 0
0x108    Time series buffer   → DELETE
0x198    Sleep accumulator    → DELETE
0x1c0    Feature buffer       → DELETE
0x1f0    Temperature buffer   → DELETE
0x208    Motion buffer        → DELETE
0x220    HRV buffer           → DELETE
```

---

## Summary

| Issue | Cause | Fix |
|-------|-------|-----|
| Only 2-3 nights | RING_START clears data | Remove RING_START events |
| Missing Jan 11-12 | No TIME_SYNC after reset | Add synthetic TIME_SYNC |

The parser is designed for incremental syncing (new data only), not batch processing of historical dumps. These behaviors are intentional for normal use but cause data loss when processing large event files.
