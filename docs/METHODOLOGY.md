# How We Reverse Engineered the Oura Ring

**A Complete Methodology Guide**

This document explains how each piece of information in this project was discovered, with references to the original Oura app source code. Suitable for presentations, education, and reproducibility.

---

## Table of Contents

1. [Overview: The Approach](#overview-the-approach)
2. [Phase 1: APK Acquisition & Decompilation](#phase-1-apk-acquisition--decompilation)
3. [Phase 2: BLE Protocol Discovery](#phase-2-ble-protocol-discovery)
4. [Phase 3: Command Structure Analysis](#phase-3-command-structure-analysis)
5. [Phase 4: Event Format Reverse Engineering](#phase-4-event-format-reverse-engineering)
6. [Phase 5: Protobuf Schema Extraction](#phase-5-protobuf-schema-extraction)
7. [Phase 6: Native Library Analysis](#phase-6-native-library-analysis)
8. [Phase 7: ML Model Decryption](#phase-7-ml-model-decryption)
9. [Phase 8: Security Key Analysis](#phase-8-security-key-analysis)
10. [Phase 9: Dynamic Instrumentation (Frida)](#phase-9-dynamic-instrumentation-frida)
11. [Phase 10: Live Verification](#phase-10-live-verification)
12. [Summary: Discovery Methods](#summary-discovery-methods)

---

## Overview: The Approach

### The Challenge

The Oura Ring Gen 3 communicates over Bluetooth Low Energy (BLE) using a proprietary protocol. The official app is obfuscated, uses native libraries, and encrypts its ML models. Our goal: fully document the protocol to enable independent analysis.

### Tools Used

| Tool | Purpose |
|------|---------|
| **JADX 1.5.1** | Java/Kotlin decompilation |
| **apktool** | APK unpacking |
| **Frida** | Dynamic instrumentation |
| **QEMU** | ARM64 emulation for native libs |
| **tree-sitter** | Large file parsing |
| **Wireshark/nRF Connect** | BLE traffic capture |
| **Python + Bleak** | BLE client implementation |

### Key Insight

> The Oura app is a treasure trove. Every protocol detail, encryption key, and algorithm is embedded in the APK - you just have to know where to look.

---

## Phase 1: APK Acquisition & Decompilation

### What We Did

1. Downloaded Oura APK from APKPure (v6.14.0, 252MB)
2. Extracted the split APKs (base + config.xxxhdpi + config.arm64_v8a)
3. Decompiled with JADX

### Commands Used

```bash
# Verify APK signature
apksigner verify --print-certs Oura_6.14.0.apk

# Extract metadata
aapt dump badging Oura_6.14.0.apk

# Decompile (took ~15 minutes)
jadx -d decompiled/ --show-bad-code Oura_6.14.0.apk
```

### What We Found

| Metric | Value |
|--------|-------|
| Total Classes | 51,333 |
| Native Libraries | 34 (127MB) |
| ML Models | 28 (encrypted) |
| Language | 100% Kotlin |

### Key Packages Discovered

```
com.ouraring.ourakit/           # BLE operations (THIS IS THE GOLD)
com.ouraring.ringeventparser/   # Event parsing (109K lines!)
com.ouraring.pytorch/           # ML model loading
com.ouraring.core.utils/        # Encryption utilities
```

**Source Reference:** Decompiled to `_large_files/decompiled/sources/`

---

## Phase 2: BLE Protocol Discovery

### How We Found the UUIDs

We searched for "UUID" in the decompiled code:

```java
// Found in: com/ouraring/ourakit/ring/RingConstants.java
public static final UUID SERVICE_UUID =
    UUID.fromString("98ed0001-a541-11e4-b6a0-0002a5d5c51b");
public static final UUID WRITE_CHARACTERISTIC =
    UUID.fromString("98ed0002-a541-11e4-b6a0-0002a5d5c51b");
public static final UUID NOTIFY_CHARACTERISTIC =
    UUID.fromString("98ed0003-a541-11e4-b6a0-0002a5d5c51b");
```

### How We Found the Command Format

By examining the base operation class:

```java
// Found in: com/ouraring/ourakit/operations/RingOperation.java
public abstract class RingOperation<T> {
    protected static final byte REQUEST_TAG = 0x2f;  // Extended format prefix
    protected static final int DEFAULT_TIMEOUT = 60000;  // 60 seconds

    // Response validation pattern
    protected boolean isValidResponse(byte[] response) {
        return response[2] == (getRequestTag() + 1);  // Response = request + 1
    }
}
```

**Key Insight:** The response tag is always the request tag + 1. For example:
- Request `0x20` → Response `0x21`
- Request `0x22` → Response `0x23`

**Source Reference:** `com/ouraring/ourakit/operations/RingOperation.java`

---

## Phase 3: Command Structure Analysis

### How We Catalogued All Commands

We listed all classes in the operations package:

```bash
ls decompiled/sources/com/ouraring/ourakit/operations/
# Found 36 operation classes!
```

### Example: Decoding GetFeatureStatus

```java
// Found in: com/ouraring/ourakit/operations/GetFeatureStatus.java
public class GetFeatureStatus extends RingOperation<FeatureStatusResponse> {
    private static final byte EXTENDED_TAG = 0x20;

    @Override
    public byte[] getRequest() {
        return new byte[] {
            REQUEST_TAG,          // 0x2f
            0x02,                 // Length
            EXTENDED_TAG,         // 0x20
            featureCapabilityId   // e.g., 0x02 for heart rate
        };
    }
}
```

**Resulting Protocol:**
```
Request:  2f 02 20 02  (Get heart rate feature status)
Response: 2f 06 21 02 01 11 02 00  (Status with mode, state, sensors)
```

### Complete Command Map

We built the map by examining each operation class's `getRequestTag()` and `EXTENDED_TAG`:

| Command | Class | Request | Response |
|---------|-------|---------|----------|
| GetFeatureStatus | GetFeatureStatus.java | 0x20 | 0x21 |
| SetFeatureMode | SetFeatureMode.java | 0x22 | 0x23 |
| SetFeatureSubscription | SetFeatureSubscription.java | 0x26 | 0x27 |
| GetEvent | GetEvent.java | 0x10 | 0x11 |
| Authenticate | Authenticate.java | 0x2D | 0x2E |
| ResetMemory | ResetMemory.java | 0x1A | 0x1B |

**Source Reference:** `com/ouraring/ourakit/operations/*.java` (36 files)

---

## Phase 4: Event Format Reverse Engineering

### How We Found Event Types

We examined the ring event parser:

```java
// Found in: com/ouraring/ringeventparser/data/RingEventType.java
public enum RingEventType {
    API_RING_START_IND(0x41),
    API_TIME_SYNC_IND(0x42),
    API_IBI_EVENT(0x44),
    API_TEMP_EVENT(0x46),
    API_MOTION_EVENT(0x47),
    API_SLEEP_PERIOD_INFO(0x48),
    // ... 63+ event types up to 0x83
}
```

### How We Decoded the 0x6A Sleep Event

This was tricky because 0x6A uses a **custom binary format**, not Protobuf:

```java
// Found in: com/ouraring/ringeventparser/message/SleepPeriodInfoValue.java
public class SleepPeriodInfoValue {
    private long timestamp;           // Offset 0-3 (deciseconds!)
    private float avgHr;              // Offset 4
    private float hrTrend;            // Offset 5
    private float avgIBI;             // Offset 6-7
    private float stdIBI;             // Offset 8-9
    private float avgBreathingRate;   // Offset 10-11
    private float stdBreathingRate;
    private int motionCount;
    private int sleepState;           // 0=awake, 1=light, 2=deep, 3=REM
    private float cvPPGSignalAmplitude;
}
```

### Critical Discovery: Deciseconds

We noticed timestamps didn't match. Analysis of two TIME_SYNC responses:

```
Response 1: Ring time = 174547, Phone UTC = 1731353088000
Response 2: Ring time = 177799, Phone UTC = 1731353414000

Time diff: 326 seconds
Ring diff: 3252 units
Ratio: 3252 / 326 = ~10x

CONCLUSION: Ring time is in DECISECONDS (0.1 second units), not seconds!
```

**The Formula:**
```python
event_utc_ms = sync_utc_ms - ((sync_ring_decisec - event_ring_decisec) * 100)
```

**Source Reference:** `com/ouraring/ourakit/operations/SyncTime.java`, `com/ouraring/ringeventparser/message/SleepPeriodInfoValue.java`

---

## Phase 5: Protobuf Schema Extraction

### The Challenge

The native library `libringeventparser.so` outputs raw Protobuf bytes, but without the `.proto` schema, we can't decode field names or types.

### How We Found the Schema

The schema is embedded in Java via `newMessageInfo()` calls. We found it in the massive 109,000-line `Ringeventparser.java`:

```java
// Found in: com/ouraring/ringeventparser/Ringeventparser.java (line ~50000)
public final class IbiAndAmplitudeEvent extends v3 {
    public static final int TIMESTAMP_FIELD_NUMBER = 1;
    public static final int IBI_FIELD_NUMBER = 2;
    public static final int AMPLITUDE_FIELD_NUMBER = 3;

    private long timestamp_;
    private h4 ibi_ = h4.emptyIntList();      // repeated int32
    private g4 amplitude_ = g4.emptyFloatList(); // repeated float
}
```

### The Extraction Pipeline

**Step 1: Parse with tree-sitter** (handles 109K lines in 2 seconds)
```python
import tree_sitter_java
parser = tree_sitter_java.Parser()
tree = parser.parse(open("Ringeventparser.java").read().encode())
```

**Step 2: Extract field numbers**
```python
# Regex pattern for FIELD_NUMBER constants
pattern = r'(\w+)_FIELD_NUMBER\s*=\s*(\d+)'
# Found 962 fields across 144 message types
```

**Step 3: Resolve obfuscated types**
```python
TYPE_MAP = {
    'k4': 'repeated int64',    # emptyLongList()
    'h4': 'repeated int32',    # emptyIntList()
    'g4': 'repeated float',    # emptyFloatList()
    'l4': 'repeated message',  # emptyProtobufList()
    'v3': 'message base',      # GeneratedMessageLite
    'd4': 'enum base',         # ProtocolMessageEnum
}
```

**Step 4: Generate proto3**
```protobuf
// Generated: ringeventparser.proto (2,070 lines)
message IbiAndAmplitudeEvent {
    int64 timestamp = 1;
    repeated int32 ibi = 2;
    repeated float amplitude = 3;
}
```

### Results

| Metric | Count |
|--------|-------|
| Message types | 144 |
| Enum types | 42 |
| Total fields | 962 |
| Enum values | 553 |
| Event oneof alternatives | 109 |

**Source Reference:** `com/ouraring/ringeventparser/Ringeventparser.java` (4.3MB)

---

## Phase 6: Native Library Analysis

### The Challenge

The event parsing happens in native code (`libringeventparser.so`), not Java. We needed to run this ARM64 library on x86_64.

### How We Analyzed the Library

```bash
# List exported symbols
nm -D libringeventparser.so | grep -i parse

# Found:
# RingEventParser::parse_events(const uint8_t*, uint32_t, uint32_t*)
# RingEventParser::create_protobuf(rep::RingData*)
```

### How We Ran It (QEMU User-Mode Emulation)

```bash
# 1. Create Android sysroot from device
adb pull /system/lib64/ ./android_root/system/lib64/
adb pull /system/bin/linker64 ./android_root/system/bin/

# 2. Compile bridge with Android NDK (NOT glibc!)
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang++ \
    -o parser_bridge parser_bridge.cpp -lringeventparser

# 3. Run with QEMU
qemu-aarch64 -L ./android_root \
    -E LD_LIBRARY_PATH=/system/lib64 \
    ./parser_bridge ring_events.bin > output.pb
```

### Critical Discovery: Parse Events One-by-One

The parser fails with concatenated events. Each event must be parsed individually:

```cpp
// WRONG: Parse all events at once
parser.parse_events(all_events, total_size, &count);  // FAILS

// CORRECT: Parse each event separately
for (each event in events) {
    parser.parse_events(event_data, event_size, &count);  // WORKS
}
```

**Source Reference:** `lib/arm64-v8a/libringeventparser.so` (Build ID: d54406c2942ab5593375114583f1b6096a599882)

---

## Phase 7: ML Model Decryption

### How We Found the Keys

We searched for "encrypt" and "decrypt" in the decompiled code:

```java
// Found in: com/ouraring/pytorch/PytorchModelFactory.java
String keyLabel = "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0";
byte[] key = Base64.decode(encryptionKeyHandler.getKey(keyLabel));

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(key, "AES"),
            new GCMParameterSpec(128, iv));
```

### Where Were the Keys Stored?

```json
// Found in: resources/res/raw/secrets.json
[
  {
    "label": "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0",
    "key": "kmElv6o7FUVdIB5/7+e1yrkIz27ojzfJ1CwZPTvTfpg="
  }
]
```

### The Encryption Format

```
File: [12-byte IV][ciphertext][16-byte GCM tag]

Algorithm: AES-256-GCM
Key Size: 256 bits (32 bytes)
IV/Nonce: 12 bytes
Auth Tag: 128 bits (16 bytes)
```

### Decryption Code

```python
from Crypto.Cipher import AES
import base64

KEY = base64.b64decode("kmElv6o7FUVdIB5/7+e1yrkIz27ojzfJ1CwZPTvTfpg=")

def decrypt_model(encrypted_path):
    data = open(encrypted_path, 'rb').read()
    iv = data[:12]
    ciphertext = data[12:-16]
    tag = data[-16:]

    cipher = AES.new(KEY, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

### Models Decrypted

| Category | Models | Examples |
|----------|--------|----------|
| Sleep | 4 | sleepstaging, sleepnet |
| Heart Rate | 6 | whr, awhr, dhrv, halite |
| Cardiovascular | 3 | cva, cva_calibrator |
| Activity | 4 | automatic_activity_detection, step_counter |
| Stress | 3 | stress_resilience, cumulative_stress |
| Other | 8 | illness_detection, pregnancy, meal_timing |

**Total: 28 models, 41MB decrypted**

**Source Reference:** `com/ouraring/pytorch/PyTorchModelType.java`, `resources/res/raw/secrets.json`

---

## Phase 8: Security Key Analysis

### How We Found the API Keys

```xml
<!-- Found in: resources/res/values/strings.xml -->
<string name="segment_writeKey">Y09Ds+pT+A46TKL9PLU0q3nFmZLH8XtIt8ofSKvOXo6x5WRexGcM7KsUXxkMt6VG</string>
<string name="braze_key">TE7Y3IZr1QLJ6ElqvHW8wA4w2yKrnQhOfPwGssj7vCXHGMKwbeoEbfEVSlUaLWGP</string>
```

These are encrypted. The decryption happens via:

```java
// Found in: com/ouraring/core/utils/l.java
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
return new String(cipher.doFinal(encryptedBytes));
```

### Critical Distinction: SDK Key vs API Key

We traced how the Braze key is used:

```java
// Found in: com/ouraring/oura/model/manager/BrazeManager.java:624
BrazeConfig.Builder().setApiKey(decryptedBrazeKey)
```

This is **SDK initialization**, not REST API authentication. The key is an app identifier, not a server-side API key.

**Implication:** Attackers cannot send push notifications or export data - they can only pollute analytics.

**Source Reference:** `com/ouraring/oura/analytics/segment/q.java`, `com/ouraring/oura/model/manager/BrazeManager.java`

---

## Phase 9: Dynamic Instrumentation (Frida)

### Why We Needed Frida

Some behaviors can't be understood from static analysis alone. We needed to observe the app at runtime.

### Non-Root Injection Method

We patched the APK to include Frida Gadget:

```smali
# Modified: LauncherActivity.smali (onCreate method)
.method public onCreate(Landroid/os/Bundle;)V
    # INJECTED: Load Frida Gadget before original code
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    # Original onCreate code follows...
```

### What We Hooked

```javascript
// Frida script: trace-all-operations.js
Java.perform(function() {
    var RingOperation = Java.use("com.ouraring.ourakit.operations.RingOperation");

    RingOperation.getRequest.implementation = function() {
        var request = this.getRequest();
        console.log("[→] " + this.getClass().getName() + ": " + bytes2hex(request));
        return request;
    };
});
```

### Key Discoveries from Frida

1. **Factory Reset Flow:**
   ```
   ResetMemory.getRequest() → 0x1a 0x01 0x01
   DbRingConfiguration.setAuthKey(null)
   BluetoothDevice.removeBond()
   ```

2. **BLE Scan Configuration:**
   ```
   ScanMode: LOW_LATENCY (2)
   ReportDelay: 0ms (immediate)
   Service Filter: 98ed0001-a541-11e4-b6a0-0002a5d5c51b
   ```

**Source Reference:** `frida_scripts/trace-all-operations.js`

---

## Phase 10: Live Verification

### The Ultimate Test

We captured a complete overnight sleep session:

```
Duration: 9 hours
Events captured: 4,794
Event types: 15 different types
Data size: 682KB (protobuf)
```

### Event Distribution

| Event Type | Tag | Count | Purpose |
|------------|-----|-------|---------|
| SLEEP_PERIOD_INFO_2 | 0x6A | 549 | Minute-by-minute sleep |
| IBI_AND_AMPLITUDE | 0x60 | 1,847 | Heart beats |
| MOTION_EVENT | 0x47 | 892 | Movement |
| TEMP_EVENT | 0x46 | 456 | Temperature |
| HRV_EVENT | 0x5D | 312 | Heart rate variability |

### Decoded Sample

```
Event 0x6A #247:
  UTC: 2026-01-12 03:47:00
  Heart Rate: 58 BPM
  Sleep State: Deep (2)
  Motion Count: 0
  Breathing Rate: 14.2 breaths/min
```

---

## Summary: Discovery Methods

| Component | How We Found It | Source File(s) |
|-----------|-----------------|----------------|
| **BLE UUIDs** | Searched for "UUID" in decompiled code | RingConstants.java |
| **Command Format** | Analyzed RingOperation base class | RingOperation.java |
| **36 Commands** | Listed all operation classes | operations/*.java |
| **63 Event Types** | Examined RingEventType enum | RingEventType.java |
| **Sleep Format** | Analyzed SleepPeriodInfoValue class | SleepPeriodInfoValue.java |
| **Deciseconds Bug** | Compared TIME_SYNC responses | SyncTime.java |
| **Protobuf Schema** | Parsed 109K-line Java with tree-sitter | Ringeventparser.java |
| **Native Parsing** | QEMU user-mode emulation | libringeventparser.so |
| **ML Encryption** | Found secrets.json + cipher code | PytorchModelFactory.java, secrets.json |
| **API Keys** | Extracted encrypted strings | strings.xml, l.java |
| **Runtime Behavior** | Frida instrumentation | Patched APK + hooks |

---

## Reproducibility

To reproduce this analysis:

1. **Get the APK:** Download Oura app from APKPure
2. **Decompile:** `jadx -d output/ Oura.apk`
3. **Search:** Use grep/ripgrep to find key classes
4. **Extract Schema:** Run our tree-sitter extractor on Ringeventparser.java
5. **Run Native:** Set up QEMU with Android sysroot
6. **Decrypt Models:** Use secrets.json key with AES-GCM
7. **Verify:** Capture live data from a ring

**All tools and scripts are in this repository.**

---

## Lessons Learned

1. **Start with the obvious:** Class names, constants, and enums are rarely obfuscated
2. **Follow the data flow:** Trace from UI → business logic → protocol
3. **Native code isn't magic:** QEMU lets you run ARM libraries anywhere
4. **Keys are usually nearby:** Encryption keys tend to be in the same APK
5. **Live verification is essential:** Static analysis can mislead - always test

---

*This methodology document accompanies the Oura Ring reverse engineering project.*
*Last Updated: 2026-01-12*
