# Oura Ring Gen 3 - Heartbeat Communication Replication Guide

**Date:** 2025-11-04
**Ring MAC:** 4B:DD:91:1C:33:61
**Verified:** From clean capture session with Frida tracing

---

## 1. BLE Connection Setup

**Service UUID:**
```
98ed0001-a541-11e4-b6a0-0002a5d5c51b
```

**Characteristics:**
```
Command (Write):     98ed0002-a541-11e4-b6a0-0002a5d5c51b
Notification (Read): 98ed0003-a541-11e4-b6a0-0002a5d5c51b
```

**Steps:**
1. Pair with ring via standard BLE pairing
2. Connect to the service
3. Enable notifications on characteristic `98ed0003`

---

## 2. Start Heartbeat Sequence (VERIFIED)

Send these commands in order to **start** heartbeat monitoring:

**Command 1:**
```
Write to 98ed0002: 2f 02 20 02
Expected Response:  2f 06 21 02 [XX] [YY] [ZZ] [WW]
  (Bytes [4-7] vary based on ring state)
```

**Command 2:**
```
Write to 98ed0002: 2f 03 22 02 03
Expected Responses:
  - May receive: 1f 04 20 05 03 00 (acknowledgment)
  - Always:      2f 03 23 02 00    (confirmation)
```

**Command 3 (STARTS STREAMING):**
```
Write to 98ed0002: 2f 03 26 02 02
Expected Response:  2f 03 27 02 00
```

Heartbeat notifications begin immediately after Command 3 response.

---

## 3. Heartbeat Notifications

**Format:**
```
Offset:  0   1   2   3   4   5   6   7   8      9      10  11  12  13  14  15  16
Data:   2f  0f  28  02  XX  02  00  00 [IBI_L] [IBI_H] 00  00  00  00  YY  ZZ  7f
```

**IBI Extraction (Bytes 8-9):**
```
ibi_ms = ((byte[9] & 0x0F) << 8) | (byte[8] & 0xFF)
```

**BPM Calculation:**
```
bpm = 60000 / ibi_ms
```

**Example:**
```
Notification: 2f 0f 28 02 11 02 00 00 01 04 00 00 00 00 35 0d 7f
                                      ^^^^^ ^^^^^
Bytes[8-9]: 0x01 0x04

Calculation:
  ibi = ((0x04 & 0x0F) << 8) | (0x01 & 0xFF)
  ibi = (4 << 8) | 1
  ibi = 1024 + 1 = 1025 ms

  bpm = 60000 / 1025 = 58.5 ≈ 59 BPM
```

---

## 4. Stop Heartbeat (VERIFIED)

**Command:**
```
Write to 98ed0002: 2f 03 22 02 01
Expected Response:  2f 03 23 02 00
```

Heartbeat notifications stop after this command.

---

## 5. Additional Protocol Notes

**Status Query (observed but not required):**
```
Write: 0c 00
Response: 0d 06 [XX] 00 00 00 [YY] 0f
  (XX and YY vary - possibly status/battery)
```

This command appears during sessions but does NOT start or stop heartbeats. It's likely a status check or keepalive.

**Unsolicited Notifications:**

You may receive `1f 04 20 ...` packets at various times - these appear to be status or acknowledgment messages from the ring.

---

## 6. Implementation Checklist

To replicate the heartbeat functionality:

- [ ] BLE connection to service `98ed0001-a541-11e4-b6a0-0002a5d5c51b`
- [ ] Subscribe to notifications on `98ed0003-a541-11e4-b6a0-0002a5d5c51b`
- [ ] Send 3-command start sequence
- [ ] Listen for `2f 0f 28` notifications
- [ ] Extract bytes 8-9 from each notification
- [ ] Parse as 12-bit little-endian value
- [ ] Calculate BPM = 60000 / IBI_ms
- [ ] Send `2f 03 22 02 01` to stop

---

## 7. Source Code References

**IBI Parsing:** `com/ouraring/ourakit/domain/IBI.java:101`
**BPM Calculation:** `com/ouraring/oura/pillars/data/daytimehr/LiveHeartRateMeasurer.java:155`
**Byte Extraction:** `com/ouraring/ourakit/domain/FeatureSubscriptionEvent.java:39`
