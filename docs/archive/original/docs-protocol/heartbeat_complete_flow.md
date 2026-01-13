# Oura Ring Gen 3 - Complete Heartbeat Protocol Flow

**Date:** 2025-11-04
**Verified from:** `/home/picke/reverse_oura/analysis/frida_oura_capture_v3.log` (lines 28-113)

---

## Protocol Summary

**Type:** Request-Response with Streaming
**Transport:** BLE GATT Notifications
**Service:** `98ed0001-a541-11e4-b6a0-0002a5d5c51b`
**Write Characteristic:** `98ed0002-a541-11e4-b6a0-0002a5d5c51b`
**Notify Characteristic:** `98ed0003-a541-11e4-b6a0-0002a5d5c51b`

---

## Complete Flow

### PHASE 1: Initialization (3 Request-Response Pairs)

**Step 1: Setup Command**
```
App → Ring (WRITE 98ed0002):  2f 02 20 02
Ring → App (NOTIFY 98ed0003): 2f 06 21 02 01 11 02 00
                                      ^^
                                      ACK (0x20 + 1 = 0x21)
```

**Step 2: Enable Heartbeat Mode**
```
App → Ring (WRITE 98ed0002):  2f 03 22 02 03
Ring → App (NOTIFY 98ed0003): 2f 03 23 02 00
                                      ^^
                                      ACK (0x22 + 1 = 0x23)
```

**Step 3: Start Streaming**
```
App → Ring (WRITE 98ed0002):  2f 03 26 02 02
Ring → App (NOTIFY 98ed0003): 2f 03 27 02 00
                                      ^^
                                      ACK (0x26 + 1 = 0x27)
```

---

### PHASE 2: Continuous Heartbeat Stream

After receiving the final ACK (`2f 03 27 02 00`), the ring **immediately begins streaming** heartbeat data without further requests:

```
Ring → App (NOTIFY 98ed0003): 2f 0f 28 02 11 02 00 00 01 04 00 00 00 00 35 0d 7f
Ring → App (NOTIFY 98ed0003): 2f 0f 28 02 11 02 00 00 fb 13 00 00 00 00 35 0d 7f
Ring → App (NOTIFY 98ed0003): 2f 0f 28 02 11 02 00 00 f8 11 00 00 00 00 35 0d 7f
Ring → App (NOTIFY 98ed0003): 2f 0f 28 02 11 02 00 00 4b 22 00 00 00 00 35 0d 7f
... (continues at ~1Hz, one packet per heartbeat)
```

**Heartbeat Packet Format:**
```
Offset:  0   1   2   3   4   5   6   7   8      9      10  11  12  13  14  15  16
Data:   2f  0f  28  02  XX  02  00  00 [IBI_L] [IBI_H] 00  00  00  00  YY  ZZ  7f
        │   │   │                      └─────┬─────┘
        │   │   └─ Packet type          Inter-Beat Interval
        │   └─ Length (15 bytes)          (12-bit little-endian)
        └─ Prefix
```

**IBI Extraction:**
```c
ibi_ms = ((byte[9] & 0x0F) << 8) | (byte[8] & 0xFF);
bpm = 60000 / ibi_ms;
```

**Example Calculation:**
```
Packet: 2f 0f 28 02 11 02 00 00 01 04 00 00 00 00 35 0d 7f
Bytes[8-9]: 0x01 0x04

ibi = ((0x04 & 0x0F) << 8) | (0x01 & 0xFF)
    = (4 << 8) | 1
    = 1024 + 1
    = 1025 ms

bpm = 60000 / 1025 = 58.5 ≈ 59 BPM
```

---

### PHASE 3: Stop Streaming

**Stop Command:**
```
App → Ring (WRITE 98ed0002):  2f 03 22 02 01
                                         ^^
                                         Changed from 03 → 01
Ring → App (NOTIFY 98ed0003): 2f 03 23 02 00
                                      ^^
                                      ACK (0x22 + 1 = 0x23)
```

After receiving this ACK, heartbeat notifications **stop immediately**.

---

## Protocol Analysis

### Command Structure

**All commands follow this pattern:**
```
Byte[0]: 0x2f (prefix)
Byte[1]: Length (number of bytes following this)
Byte[2]: Command ID
Byte[3+]: Parameters
```

### ACK Pattern

**Ring acknowledges by:**
1. Echoing the prefix and length
2. Incrementing command ID by 1
3. Returning status/data bytes

**Examples:**
- Command `0x20` → ACK `0x21`
- Command `0x22` → ACK `0x23`
- Command `0x26` → ACK `0x27`

### Command Meanings (Observed)

| Command | Parameters | ACK | Purpose |
|---------|-----------|-----|---------|
| `2f 02 20 02` | - | `2f 06 21 02 [state]` | Setup/initialize |
| `2f 03 22 02 03` | `03` = enable | `2f 03 23 02 00` | Enable heartbeat mode |
| `2f 03 22 02 01` | `01` = disable | `2f 03 23 02 00` | Disable heartbeat mode |
| `2f 03 26 02 02` | - | `2f 03 27 02 00` | Start streaming |

**Note:** Command `0x22` with parameter `0x03` enables, parameter `0x01` disables.

---

## Timing Characteristics

**Observed in capture:**
- Heartbeat notifications arrive at ~1 Hz (once per heartbeat)
- IBI values range from ~1000ms to ~1500ms (40-60 BPM at rest)
- No delay between final ACK and first heartbeat
- Stream continues indefinitely until stop command

---

## Implementation Checklist

**Starting heartbeat monitoring:**
1. ✓ Connect to BLE service
2. ✓ Enable notifications on `98ed0003`
3. ✓ Send command `2f 02 20 02`, wait for ACK
4. ✓ Send command `2f 03 22 02 03`, wait for ACK
5. ✓ Send command `2f 03 26 02 02`, wait for ACK
6. ✓ Begin collecting `2f 0f 28` notifications

**Processing heartbeats:**
1. ✓ Filter notifications: prefix = `2f 0f 28`
2. ✓ Extract bytes [8-9]
3. ✓ Parse as 12-bit little-endian: `((b[9] & 0x0F) << 8) | b[8]`
4. ✓ Calculate BPM: `60000 / ibi_ms`

**Stopping heartbeat monitoring:**
1. ✓ Send command `2f 03 22 02 01`, wait for ACK
2. ✓ Notifications stop

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
