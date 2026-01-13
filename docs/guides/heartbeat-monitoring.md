# Oura Ring Gen 3 - Heartbeat Monitoring Guide

**Verified:** From live capture sessions with Frida tracing
**Last Updated:** 2026-01-12

---

## Overview

**Type:** Request-Response with Streaming
**Transport:** BLE GATT Notifications
**Data Rate:** ~1 Hz (one packet per heartbeat)

### BLE Connection Details

```
Service UUID:        98ed0001-a541-11e4-b6a0-0002a5d5c51b
Write Characteristic: 98ed0002-a541-11e4-b6a0-0002a5d5c51b
Notify Characteristic: 98ed0003-a541-11e4-b6a0-0002a5d5c51b
```

---

## Complete Protocol Flow

### PHASE 1: Initialization (3 Request-Response Pairs)

**Step 1: Query Feature Status**
```
App → Ring:  2f 02 20 02
Ring → App:  2f 06 21 02 01 11 02 00
                     ^^
                     ACK (0x20 + 1 = 0x21)
```

**Step 2: Enable Heartbeat Mode**
```
App → Ring:  2f 03 22 02 03
Ring → App:  2f 03 23 02 00
                     ^^
                     ACK (0x22 + 1 = 0x23)
```

**Step 3: Subscribe to Stream**
```
App → Ring:  2f 03 26 02 02
Ring → App:  2f 03 27 02 00
                     ^^
                     ACK (0x26 + 1 = 0x27)
```

### PHASE 2: Continuous Heartbeat Stream

After receiving the final ACK, the ring **immediately begins streaming** heartbeat data:

```
Ring → App: 2f 0f 28 02 11 02 00 00 01 04 00 00 00 00 35 0d 7f
Ring → App: 2f 0f 28 02 11 02 00 00 fb 13 00 00 00 00 35 0d 7f
Ring → App: 2f 0f 28 02 11 02 00 00 f8 11 00 00 00 00 35 0d 7f
... (continues at ~1Hz)
```

### PHASE 3: Stop Streaming

**Stop Command:**
```
App → Ring:  2f 03 22 02 01
                        ^^
                        Changed from 03 → 01 (disable)
Ring → App:  2f 03 23 02 00
```

Notifications stop immediately after this ACK.

---

## Heartbeat Packet Format (17 bytes)

```
Offset:  0   1   2   3   4   5   6   7   8      9      10  11  12  13  14  15  16
Data:   2f  0f  28  02  XX  02  00  00 [IBI_L] [IBI_H] 00  00  00  00  YY  ZZ  7f
        │   │   │                      └─────┬─────┘
        │   │   └─ Packet type (0x28)   Inter-Beat Interval
        │   └─ Length (15 bytes)          (12-bit little-endian)
        └─ Prefix (0x2f)
```

**Field Details:**
| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Prefix | 0x2f (extended format) |
| 1 | 1 | Length | 0x0f (15 bytes payload) |
| 2 | 1 | Command | 0x28 (heartbeat notification) |
| 3 | 1 | Feature ID | 0x02 (heart rate) |
| 4 | 1 | Flags | Status flags |
| 5 | 1 | State | Feature state |
| 6-7 | 2 | Sequence | Packet sequence number (LE) |
| 8-9 | 2 | IBI | Inter-beat interval in ms (12-bit LE) |
| 10-15 | 6 | Reserved | Reserved bytes |
| 16 | 1 | Trailer | 0x7f |

---

## IBI Extraction & BPM Calculation

### Extract IBI (bytes 8-9)

```c
// C/Python
ibi_ms = ((byte[9] & 0x0F) << 8) | (byte[8] & 0xFF);
```

```java
// Java (from Oura source)
int ibi = ((data[1] & 15) << 8) | (data[0] & 255);
this.ibi = ibi > 2000 ? null : Integer.valueOf(ibi);
```

### Calculate BPM

```c
bpm = 60000 / ibi_ms;
```

### Example Calculation

```
Packet: 2f 0f 28 02 11 02 00 00 01 04 00 00 00 00 35 0d 7f
                                ^^^^^ ^^^^^
Bytes[8-9]: 0x01 0x04

ibi = ((0x04 & 0x0F) << 8) | (0x01 & 0xFF)
    = (4 << 8) | 1
    = 1024 + 1
    = 1025 ms

bpm = 60000 / 1025 = 58.5 ≈ 59 BPM
```

---

## Command Reference

| Command | Parameters | ACK | Purpose |
|---------|-----------|-----|---------|
| `2f 02 20 02` | - | `2f 06 21 02 [state]` | Query feature status |
| `2f 03 22 02 03` | `03` = enable | `2f 03 23 02 00` | Enable heartbeat mode |
| `2f 03 22 02 01` | `01` = disable | `2f 03 23 02 00` | Disable heartbeat mode |
| `2f 03 26 02 02` | `02` = subscribe | `2f 03 27 02 00` | Start streaming |

**Feature ID:** `0x02` = Heart Rate (CAP_DAYTIME_HR)

---

## Timing Characteristics

- Heartbeat notifications arrive at ~1 Hz (once per heartbeat)
- IBI values typically range 600-1500ms (40-100 BPM)
- No delay between final ACK and first heartbeat
- Stream continues indefinitely until stop command

---

## Implementation Checklist

### Starting Heartbeat Monitoring

- [ ] Connect to BLE service `98ed0001-a541-11e4-b6a0-0002a5d5c51b`
- [ ] Enable notifications on characteristic `98ed0003`
- [ ] **Authenticate first** (if required - see authentication protocol)
- [ ] Send `2f 02 20 02`, wait for ACK (`2f 06 21...`)
- [ ] Send `2f 03 22 02 03`, wait for ACK (`2f 03 23 02 00`)
- [ ] Send `2f 03 26 02 02`, wait for ACK (`2f 03 27 02 00`)
- [ ] Begin collecting `2f 0f 28` notifications

### Processing Heartbeats

- [ ] Filter notifications: prefix = `2f 0f 28`
- [ ] Extract bytes [8-9]
- [ ] Parse as 12-bit little-endian: `((b[9] & 0x0F) << 8) | b[8]`
- [ ] Validate IBI is reasonable (400-2000 ms)
- [ ] Calculate BPM: `60000 / ibi_ms`

### Stopping Heartbeat Monitoring

- [ ] Send `2f 03 22 02 01`, wait for ACK
- [ ] Notifications stop immediately

---

## Python Example

```python
import asyncio
from bleak import BleakClient

SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
WRITE_UUID = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
NOTIFY_UUID = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"

def parse_heartbeat(data: bytes) -> tuple[int, float]:
    """Parse heartbeat notification, return (ibi_ms, bpm)"""
    if len(data) < 10 or data[0:3] != bytes([0x2f, 0x0f, 0x28]):
        return None, None

    ibi_ms = ((data[9] & 0x0F) << 8) | data[8]
    if ibi_ms < 400 or ibi_ms > 2000:
        return ibi_ms, None

    bpm = 60000 / ibi_ms
    return ibi_ms, bpm

async def start_heartbeat(client: BleakClient):
    """Send start sequence"""
    commands = [
        bytes([0x2f, 0x02, 0x20, 0x02]),      # Query status
        bytes([0x2f, 0x03, 0x22, 0x02, 0x03]), # Enable mode
        bytes([0x2f, 0x03, 0x26, 0x02, 0x02]), # Subscribe
    ]
    for cmd in commands:
        await client.write_gatt_char(WRITE_UUID, cmd)
        await asyncio.sleep(0.1)

async def stop_heartbeat(client: BleakClient):
    """Send stop command"""
    await client.write_gatt_char(WRITE_UUID,
        bytes([0x2f, 0x03, 0x22, 0x02, 0x01]))
```

---

## Troubleshooting

### No Heartbeat Data Received

1. **Check ring is on finger** - Ring sensors need skin contact
2. **Wait for sensors to activate** - Takes 30-60 seconds after wearing
3. **Check authentication** - Must authenticate after factory reset
4. **Verify notification subscription** - Must enable CCCD on `98ed0003`

### Invalid IBI Values

- IBI > 2000 ms is filtered as invalid by Oura app
- IBI < 400 ms indicates possible motion artifact
- High variability may indicate poor sensor contact

### Unsolicited Notifications

You may receive `1f 04 20 ...` packets - these are status/acknowledgment messages, not heartbeat data. Filter by checking prefix `2f 0f 28`.

---

## Source Code References

**IBI Class:** `com/ouraring/ourakit/domain/IBI.java:101`
```java
int i4 = ((data[1] & 15) << 8) | (data[0] & 255);
this.ibi = i4 > 2000 ? null : Integer.valueOf(i4);
```

**BPM Calculation:** `com/ouraring/oura/pillars/data/daytimehr/LiveHeartRateMeasurer.java:155`
```java
return Double.valueOf(60000 / ibiValue.intValue());
```

**Byte Extraction:** `com/ouraring/ourakit/domain/FeatureSubscriptionEvent.java:39`
```java
new IBI(Arrays.copyOfRange(response, 8, 10))
```

---

*Merged from: heartbeat_complete_flow.md + heartbeat_replication_guide.md*
