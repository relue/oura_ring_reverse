# Native Libraries in the Oura APK

This document provides a comprehensive analysis of the native libraries found in the Oura Ring Android application, including methods for running them on Linux and extracting their functionality.

**Last updated:** 2026-01-12

---

## Table of Contents

1. [Overview](#overview)
2. [libringeventparser.so](#libringeventparserso)
   - [Purpose](#purpose)
   - [JNI Interface](#jni-interface)
   - [QEMU User-Mode Emulation Setup](#qemu-user-mode-emulation-setup)
   - [Running the Native Parser](#running-the-native-parser)
3. [libsecrets.so](#libsecretsso)
   - [Purpose](#purpose-1)
   - [Exported Functions](#exported-functions)
   - [Runtime String Decryption](#runtime-string-decryption)
   - [Code References](#code-references)
4. [Other Native Libraries](#other-native-libraries)
5. [Integration Examples](#integration-examples)

---

## Overview

The Oura Ring Android application includes several native ARM64 libraries in the APK under `lib/arm64-v8a/`. The two primary libraries of interest for reverse engineering are:

| Library | Size | Purpose |
|---------|------|---------|
| `libringeventparser.so` | ~500KB | Protobuf parsing for ring BLE events |
| `libsecrets.so` | 8.6KB | API key obfuscation and retrieval |
| `libprotobuf-lite.so` | ~200KB | Google Protocol Buffers runtime |

These libraries are compiled for ARM64 (aarch64) Android using the Android NDK. Running them on x86_64 Linux requires QEMU user-mode emulation with an Android sysroot.

---

## libringeventparser.so

### Purpose

`libringeventparser.so` is the core native library responsible for parsing raw Bluetooth Low Energy (BLE) events from the Oura Ring and converting them into Protocol Buffer (protobuf) messages containing health data.

**Data flow:**
```
Raw BLE hex data --> libringeventparser.so --> Protobuf --> Health metrics
```

**Extracted health metrics include:**
- Heart Rate (HR) and Inter-Beat Intervals (IBI)
- Heart Rate Variability (HRV/RMSSD)
- Temperature readings
- SpO2 measurements
- Motion/activity data

### JNI Interface

The library exports C++ class methods with mangled names. Key symbols discovered via `nm -D`:

```bash
nm -D libringeventparser.so | grep -i parse
```

**Key exported symbols:**
```
_ZN15RingEventParserC1Ev                    # RingEventParser::RingEventParser()
_ZN15RingEventParser12parse_eventsEPKhjPj   # RingEventParser::parse_events(const uint8_t*, uint32_t, uint32_t*)
_ZN15RingEventParser15create_protobufEPN3rep8RingDataE  # RingEventParser::create_protobuf(rep::RingData*)
_ZN7SessionC1ERK12s_RepOptions             # Session::Session(s_RepOptions const&)
_ZN15RingEventParser11set_sessionEP7Session # RingEventParser::set_session(Session*)
_ZNK3rep8RingData12ByteSizeLongEv          # rep::RingData::ByteSizeLong() const
```

**Class structure (reverse-engineered):**
```cpp
class RingEventParser {
public:
    RingEventParser();
    void set_session(Session* session);
    void parse_events(const uint8_t* data, uint32_t length, uint32_t* events_received);
    void create_protobuf(rep::RingData* output);
};

class Session {
public:
    Session(const s_RepOptions& options);
};
```

### QEMU User-Mode Emulation Setup

Running the ARM64 Android library on x86_64 Linux requires careful setup:

#### Prerequisites

```bash
# Install QEMU user-mode (Arch/Manjaro)
sudo pacman -S qemu-user qemu-user-static

# Install QEMU user-mode (Debian/Ubuntu)
sudo apt install qemu-user qemu-user-static

# Android NDK (for compiling bridge program)
# Download from developer.android.com or use Android Studio
# Example path: ~/Android/Sdk/ndk/29.0.14206865
```

#### Creating the Android Sysroot

Extract required files from a rooted Android device:

```bash
mkdir -p android_root/system/bin android_root/system/lib64

# Pull Android's dynamic linker (CRITICAL)
adb pull /system/bin/linker64 android_root/system/bin/
chmod +x android_root/system/bin/linker64

# Pull Bionic libraries
adb pull /system/lib64/libc.so android_root/system/lib64/
adb pull /system/lib64/libm.so android_root/system/lib64/
adb pull /system/lib64/libdl.so android_root/system/lib64/
adb pull /system/lib64/liblog.so android_root/system/lib64/
adb pull /system/lib64/libc++.so android_root/system/lib64/
```

**Final sysroot structure:**
```
android_root/
└── system/
    ├── bin/
    │   └── linker64          # Android's dynamic linker
    └── lib64/
        ├── libc.so           # Bionic libc
        ├── libm.so           # Bionic libm
        ├── libdl.so          # Bionic libdl
        ├── liblog.so         # Android logging
        ├── libc++.so         # Android C++ runtime
        ├── libprotobuf-lite.so  # From Oura APK
        └── libringeventparser.so # From Oura APK
```

#### Compiling the Bridge Program

The bridge program MUST be compiled with Android NDK (not glibc cross-compiler):

```bash
NDK=/path/to/android-ndk
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
CC=$TOOLCHAIN/bin/aarch64-linux-android35-clang

$CC -Wall -g -O2 parser_bridge.c -o parser_bridge_android -ldl
```

**Verify correct linking:**
```bash
file parser_bridge_android
# CORRECT: interpreter /system/bin/linker64, for Android 35
# WRONG:   interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0
```

#### Key Implementation Details

**Loading libraries:**
```c
void* proto_handle = dlopen("libprotobuf-lite.so", RTLD_NOW | RTLD_GLOBAL);
void* parser_handle = dlopen("libringeventparser.so", RTLD_NOW);
```

**Creating Session with all features enabled:**
```c
void* session = calloc(1, 8192);
void* options = malloc(256);
memset(options, 0xFF, 256);  // CRITICAL: Enable all parsing modes
session_ctor(session, options);
set_session(parser, session);
```

**Parsing events (must be done one-by-one):**
```c
// CORRECT: Parse each event individually
for (size_t i = 0; i < event_count; i++) {
    uint32_t events_received = 0;
    parse_events(parser, events[i].data, events[i].len, &events_received);
}

// WRONG: Concatenating events produces minimal output
```

### Running the Native Parser

**Execute with QEMU:**
```bash
cd native_parser

env -i HOME=$HOME PATH=/usr/bin:/bin \
  qemu-aarch64 -L ./android_root \
  -E LD_LIBRARY_PATH=/system/lib64 \
  ./parser_bridge_android ring_events.txt \
  > ring_data.pb 2>parse.log

# Check results
cat parse.log | tail -20
ls -la ring_data.pb  # Should be ~682KB for typical sleep data
```

**Expected output (parse.log):**
```
Loading libraries...
  Libraries loaded OK
=== Parsing 4794 events (88331 bytes) ONE BY ONE ===
  Parsed 4794 events
=== Serializing RingData ===
  RingData::ByteSizeLong: 682957 bytes
  SUCCESS! Writing 682957 bytes to stdout
```

#### Troubleshooting

| Problem | Error Message | Solution |
|---------|---------------|----------|
| Wrong compiler | `invalid ELF header` | Use Android NDK, not glibc cross-compiler |
| Missing linker64 | `No such file or directory` | Extract linker64 from Android device |
| Host libs leaking | `EM_X86_64 instead of EM_AARCH64` | Use `env -i` for clean environment |
| Empty protobuf | 6 bytes output | Set s_RepOptions to 0xFF |
| "session is nullptr" | Error in stderr | Create Session object |
| Concatenated parsing fails | 6 bytes output | Parse events one-by-one |

---

## libsecrets.so

### Purpose

`libsecrets.so` is a small native library (8.6KB) that stores and decodes hardcoded API keys using custom encoding and SHA256 hashing. It provides obfuscated storage for sensitive credentials that would otherwise be visible in Java bytecode.

**Primary functions:**
1. **API Key** - Used for backend API authentication and AES encryption
2. **Fallback Key** - Used for OAuth/HAAPI authentication flows

**File details:**
- **Size:** 8.6KB
- **Type:** ELF 64-bit ARM64 shared library
- **Build ID:** c0319f0315cfe89ae7e26c76479b791af7cf3675
- **Compiler:** Android Clang 18.0.1

### Exported Functions

#### getapiKey
```c
jstring Java_com_ouraring_core_utils_Secrets_getapiKey(JNIEnv* env, jobject obj, jstring packageName)
```

- **Called from:** `com.ouraring.core.utils.l.java` (Crypto class)
- **Purpose:** Returns main API key for backend authentication to `cloud.ouraring.com`
- **Package validation:** Expects `"com.ouraring.core.utils"`

#### getfallbackKey
```c
jstring Java_com_ouraring_core_utils_Secrets_getfallbackKey(JNIEnv* env, jobject obj, jstring packageName)
```

- **Called from:** `com.ouraring.core.model.auth.moiv2.HaapiConfigProvider.java`
- **Purpose:** Returns OAuth 2.0 client secret for Curity Identity Server (HAAPI)
- **Package validation:** Expects `"com.ouraring.core.utils"`

### Runtime String Decryption

The library uses a multi-step process to decode keys at runtime:

#### Step 1: Package Name Validation
```c
// Validates calling package matches expected value
const char* expected = "com.ouraring.core.utils";
```

This prevents repackaged apps or third-party code from extracting keys.

#### Step 2: Custom Decoding
Hardcoded obfuscated strings in the binary:
```
Tp8G"(@JTU~Zdy(l!4O\/#V8
Kq4T7,jL,~
sQ_hAVRP
...
```

These are processed by an internal `customDecode()` function.

#### Step 3: SHA256 Processing
The decoded string may be further transformed with SHA256 hashing before being returned as a Java String.

#### Internal Functions
```c
// SHA256 implementation
void SHA256::init()
void SHA256::update(const uint8_t* data, size_t len)
void SHA256::final(uint8_t* hash)

// Obfuscation
void customDecode(char* encoded)
void getOriginalKey(char* buffer, int length, jstring packageName, JNIEnv* env)
```

### Code References

#### API Key Usage (AES Encryption)

**File:** `com/ouraring/core/utils/l.java`

```java
// Lazy initialization of secrets
private static final Lazy<Secrets> secrets = lazy(() -> new Secrets());
private static final Lazy<String> secretKey = lazy(() ->
    secrets.getValue().getapiKey("com.ouraring.core.utils")
);

// AES Cipher setup
private static final Lazy<Cipher> cipher = lazy(() -> {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    byte[] keyBytes = secretKey.getValue().getBytes(UTF_8);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
    return cipher;
});

// Decrypt function
public static String decrypt(String encrypted) {
    byte[] decoded = Base64.getDecoder().decode(encrypted);
    synchronized (Cipher.class) {
        return new String(cipher.getValue().doFinal(decoded), UTF_8);
    }
}
```

#### OAuth Key Usage (HAAPI)

**File:** `com/ouraring/core/model/auth/moiv2/HaapiConfigProvider.java`

```java
// HAAPI driver initialization with fallback key
se.curity.identityserver.haapi.android.driver.b driver =
    new se.curity.identityserver.haapi.android.driver.b(
        new Secrets().getfallbackKey("com.ouraring.core.utils")
    );
```

### Key Extraction Methods

#### Method 1: Frida Hook (Recommended)
```javascript
Java.perform(() => {
    const Secrets = Java.use("com.ouraring.core.utils.Secrets");

    Secrets.getapiKey.implementation = function(pkg) {
        const key = this.getapiKey(pkg);
        console.log("[*] API Key:", key);
        return key;
    };

    Secrets.getfallbackKey.implementation = function(pkg) {
        const key = this.getfallbackKey(pkg);
        console.log("[*] Fallback Key:", key);
        return key;
    };
});
```

#### Method 2: Static Disassembly
1. Load libsecrets.so in Ghidra/IDA
2. Analyze `Java_com_ouraring_core_utils_Secrets_getapiKey`
3. Trace to hardcoded data section
4. Reverse `customDecode` algorithm
5. Extract and decode keys

#### Security Assessment

**Strengths:**
- Keys stored in native code (not Java bytecode)
- Custom encoding (not plain Base64)
- Package name validation
- SHA256 additional transformation

**Weaknesses:**
- Keys are hardcoded in binary
- Reversible with Frida hooking or disassembly
- Static obfuscation (not device-specific)
- Package name check easily bypassed

---

## Other Native Libraries

### libprotobuf-lite.so

Google's Protocol Buffers runtime library used by `libringeventparser.so` for serialization.

- **Source:** Bundled with Oura APK
- **Usage:** Must be loaded with `RTLD_GLOBAL` before `libringeventparser.so`
- **Required for:** `SerializeToArray()`, `ByteSizeLong()`, protobuf message handling

### Additional Libraries (from APK)

The Oura APK may include other native libraries depending on version:
- **libflutter.so** - Flutter framework (if Flutter is used)
- **librealm-jni.so** - Realm database native bindings
- **libsqlcipher.so** - SQLCipher encrypted database (if used)

---

## Integration Examples

### Example 1: Complete BLE Event Parsing Pipeline

```bash
#!/bin/bash
# parse_ring_data.sh - Parse captured BLE events

ANDROID_ROOT="./android_root"
PARSER="./parser_bridge_android"
INPUT="$1"
OUTPUT="${INPUT%.txt}.pb"

env -i HOME=$HOME PATH=/usr/bin:/bin \
  qemu-aarch64 -L "$ANDROID_ROOT" \
  -E LD_LIBRARY_PATH=/system/lib64 \
  "$PARSER" "$INPUT" > "$OUTPUT" 2>parse.log

echo "Parsed $(wc -c < "$OUTPUT") bytes to $OUTPUT"
```

### Example 2: Python Protobuf Decoder

```python
#!/usr/bin/env python3
# decode_ring_data.py - Decode protobuf output

import sys
from ring_data_pb2 import RingData  # Generated from .proto

def decode_ring_data(pb_file):
    with open(pb_file, 'rb') as f:
        data = RingData()
        data.ParseFromString(f.read())

    print(f"Heart Rate samples: {len(data.heart_rate_samples)}")
    print(f"Temperature samples: {len(data.temperature_samples)}")
    print(f"HRV measurements: {len(data.hrv_measurements)}")

    return data

if __name__ == "__main__":
    decode_ring_data(sys.argv[1])
```

### Example 3: Frida Script for Key Extraction

```javascript
// extract_keys.js - Extract API keys at runtime
Java.perform(() => {
    console.log("[*] Hooking Secrets class...");

    const Secrets = Java.use("com.ouraring.core.utils.Secrets");

    Secrets.getapiKey.implementation = function(pkg) {
        const key = this.getapiKey(pkg);
        console.log("[API_KEY] " + key);
        return key;
    };

    Secrets.getfallbackKey.implementation = function(pkg) {
        const key = this.getfallbackKey(pkg);
        console.log("[FALLBACK_KEY] " + key);
        return key;
    };
});
```

**Usage:**
```bash
frida -U -f com.ouraring.oura -l extract_keys.js
```

### Example 4: Combined Workflow

```bash
# 1. Capture BLE events (via btsnoop or custom capture)
# 2. Parse with native library
./parse_ring_data.sh ring_events.txt

# 3. Decode protobuf
python3 decode_ring_data.py ring_events.pb

# 4. Extract API keys (on device)
frida -U com.ouraring.oura -l extract_keys.js
```

---

*Merged from: qemu_native_protobuf.md + libsecrets_analysis.md*
