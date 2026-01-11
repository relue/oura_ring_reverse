# Oura Ring BLE Protocol - Discovered

**Date:** 2025-11-03
**Ring MAC:** 4B:DD:91:1C:33:61
**Method:** Frida Gadget + SweetBlue library hooks

---

## BLE Service & Characteristics

**Primary Service UUID:**
```
98ed0001-a541-11e4-b6a0-0002a5d5c51b
```

**Characteristic - Command/Write:**
```
UUID: 98ed0002-a541-11e4-b6a0-0002a5d5c51b
Properties: Write
```

**Characteristic - Notification/Response:**
```
UUID: 98ed0003-a541-11e4-b6a0-0002a5d5c51b
Properties: Read, Write, Notify
```

---

## Heartbeat Protocol (DECODED)

### Notification Packets

**Format 1: Status (0d 06 63)**
```
0d 06 63 00 00 00 8d 0f
```
- Prefix: `0x0d`
- Byte [2]: Always `0x63` (99 decimal) - NOT actual BPM
- Purpose: Unknown (status/mode indicator)

**Format 2: IBI Heartbeat (2f 0f 28)**
```
Offset:  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16
Data:   2f  0f  28  02  11  02  00  00 [IBI_L] [IBI_H] ...
                                       ^^^^^^^ ^^^^^^^
                                       byte 8  byte 9
```

- Prefix: `0x2f 0x0f 0x28`
- **Bytes [8-9]: IBI (Inter-Beat Interval) in milliseconds**
- Format: 12-bit little-endian value
  - Low byte: `data[8]` (bits 0-7)
  - High byte: `data[9]` (bits 8-11, lower 4 bits only)

### BPM Calculation (Verified from App Source)

**Extraction (`FeatureSubscriptionEvent.java:39`):**
```java
new IBI(Arrays.copyOfRange(response, 8, 10))  // Extract bytes 8-9
```

**IBI Parsing (`IBI.java:101`):**
```java
int ibi = ((data[1] & 0x0F) << 8) | (data[0] & 0xFF);
// ibi = ((byte[9] & 0x0F) << 8) | (byte[8] & 0xFF)
```

**BPM Calculation (`LiveHeartRateMeasurer.java:155`):**
```java
bpm = 60000 / ibi;  // IBI is in milliseconds
```

**Complete Example:**
```
Packet: 2f 0f 28 02 01 02 00 00 6c 04 00 00 00 00 3c 0d 7f
                                ^^^^^
Bytes[8-9]: 0x6c 0x04

Extraction:
  ibi = ((0x04 & 0x0F) << 8) | (0x6c & 0xFF)
  ibi = (4 << 8) | 108
  ibi = 1024 + 108 = 1132 ms

BPM Calculation:
  bpm = 60000 / 1132 = 53 BPM
```

---

**Status:** Heartbeat protocol fully decoded. Live decoder available at `/home/picke/reverse_oura/analysis/frida_scripts/live-heartbeat-decoder.js`
