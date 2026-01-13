# Running Oura's Native libringeventparser.so on Linux with QEMU

This document describes how we successfully ran Oura's ARM64 Android native library (`libringeventparser.so`) on an x86_64 Linux machine using QEMU user-mode emulation, and extracted health data (heart rate, temperature, HRV, etc.) from raw BLE ring events.

## Table of Contents

1. [Goal](#goal)
2. [The Problem](#the-problem)
3. [Key Discoveries](#key-discoveries)
4. [Solution Architecture](#solution-architecture)
5. [Step-by-Step Setup](#step-by-step-setup)
6. [The Bridge Program](#the-bridge-program)
7. [Running the Parser](#running-the-parser)
8. [Troubleshooting Journey](#troubleshooting-journey)
9. [Lessons Learned](#lessons-learned)

---

## Goal

Parse raw BLE events captured from an Oura Ring 4 using Oura's own native parsing library, without needing an Android device or the Oura app.

```
Raw BLE hex data → libringeventparser.so → Protobuf → Health metrics
```

---

## The Problem

Oura's `libringeventparser.so` is an ARM64 Android native library. Running it on x86_64 Linux presents several challenges:

1. **Architecture mismatch**: Library is ARM64, host is x86_64
2. **Android vs Linux**: Library is built for Android (Bionic libc), not Linux (glibc)
3. **Dynamic linker**: Android uses `/system/bin/linker64`, Linux uses `/lib/ld-linux-aarch64.so.1`
4. **C++ ABI**: Library uses Android's libc++ with specific name mangling
5. **No documentation**: Function signatures must be reverse-engineered

---

## Key Discoveries

### Discovery 1: QEMU User-Mode Can Run ARM64 Binaries

QEMU's user-mode emulation (`qemu-aarch64`) can run ARM64 binaries on x86_64 by:
- Translating ARM64 instructions to x86_64
- Intercepting syscalls and translating them to host syscalls
- Using `-L <sysroot>` to redirect library paths

**How we found this**: Standard knowledge of QEMU capabilities.

### Discovery 2: glibc Cross-Compilation Doesn't Work

Initial attempt: Compile bridge with `aarch64-linux-gnu-gcc` (glibc cross-compiler).

**Result**: Failed with "invalid ELF header" errors.

```
protobuf: /lib/libm.so: invalid ELF header
```

**Why it failed**:
- Our binary used glibc's dynamic linker (`/lib/ld-linux-aarch64.so.1`)
- The Oura libraries expect Bionic's linker and libc
- Mixing glibc and Bionic causes ABI incompatibilities

**How we found this**: Trial and error. The error message showed it was finding the wrong libc.

### Discovery 3: Must Use Android NDK to Compile

The bridge program must be compiled with Android NDK, not glibc cross-compiler.

**Key difference in binary headers**:
```bash
# glibc-compiled (WRONG):
interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0

# NDK-compiled (CORRECT):
interpreter /system/bin/linker64, for Android 35
```

**How we found this**: Checked binary with `file` command after NDK compilation.

### Discovery 4: Need Android Sysroot with linker64

QEMU needs a sysroot containing Android's dynamic linker and core libraries.

**Required files** (extracted from Android device):
```
android_root/
└── system/
    ├── bin/
    │   └── linker64          # Android's dynamic linker (CRITICAL)
    └── lib64/
        ├── libc.so           # Bionic libc
        ├── libm.so           # Bionic libm
        ├── libdl.so          # Bionic libdl
        ├── liblog.so         # Android logging
        ├── libc++.so         # Android C++ runtime
        ├── libprotobuf-lite.so  # Oura's protobuf (from APK)
        └── libringeventparser.so # Oura's parser (from APK)
```

**How we found this**:
1. QEMU's `-L` flag documentation
2. Error messages showing missing libraries
3. `adb pull` from a rooted Android device

### Discovery 5: Environment Variables Matter

The `LD_LIBRARY_PATH` must be cleared of host paths, otherwise Android's linker64 finds x86_64 libraries and fails.

**Error when host paths leak through**:
```
"/usr/NX/lib/libnxegl.so" is for EM_X86_64 (62) instead of EM_AARCH64 (183)
```

**Solution**: Use `env -i` to start with clean environment:
```bash
env -i HOME=$HOME PATH=/usr/bin:/bin qemu-aarch64 -L ./android_root ...
```

**How we found this**: The error message explicitly showed an x86_64 library being loaded.

### Discovery 6: C++ Method Signatures via nm

The library exports C++ class methods with mangled names. We used `nm` to find them:

```bash
nm -D libringeventparser.so | grep -i parse
```

**Key symbols found**:
```
_ZN15RingEventParserC1Ev                    # RingEventParser::RingEventParser()
_ZN15RingEventParser12parse_eventsEPKhjPj   # RingEventParser::parse_events(...)
_ZN15RingEventParser15create_protobufEPN3rep8RingDataE  # create_protobuf(RingData*)
_ZN7SessionC1ERK12s_RepOptions             # Session::Session(s_RepOptions const&)
```

**How we found this**: `nm -D` lists dynamic symbols; `c++filt` demangles them.

### Discovery 7: Session Object is Required

Initial parsing returned empty protobuf with error "REP session is nullptr!".

**Solution**: Create a Session object and attach it to the parser:
```c
void* session = calloc(1, 8192);
void* options = malloc(256);
memset(options, 0xFF, 256);  // Enable all features
session_ctor(session, options);
set_session(parser, session);
```

**How we found this**: Error message in stderr output from the library.

### Discovery 8: s_RepOptions Must Be Non-Zero

With zeroed options, parsing produced errors like "No DHR measurement ongoing".

Setting all bits to 1 (`0xFF`) enabled all parsing modes:
```c
memset(options, 0xFF, 256);  // Enable everything
```

**Result**: 682KB of protobuf output instead of 6 bytes!

**How we found this**: Trial and error. Zero options = 6 bytes output. 0xFF options = 682KB.

### Discovery 9: Events Must Be Parsed One-by-One

Java code concatenates events before calling native parser, but the C++ class API expects individual events:

```c
// WRONG: Concatenate all events, parse once → 6 bytes output
parse_events(parser, concat_buf, total_len, &received);

// CORRECT: Parse each event individually → 682KB output
for (int i = 0; i < event_count; i++) {
    parse_events(parser, events[i].data, events[i].len, &received);
}
```

**How we found this**: Compared output sizes between approaches.

### Discovery 10: RingData Methods Are in libringeventparser.so

Initially looked for `ByteSizeLong()` in `libprotobuf-lite.so` but it's actually in `libringeventparser.so`:

```bash
nm -D libringeventparser.so | grep ByteSizeLong
# _ZNK3rep8RingData12ByteSizeLongEv  ← rep::RingData::ByteSizeLong()
```

**How we found this**: Grep through both .so files for the symbol.

---

## Solution Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HOST (x86_64 Linux)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ring_events.txt (hex)                                          │
│       │                                                         │
│       ▼                                                         │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              QEMU User-Mode (qemu-aarch64)              │    │
│  │                                                         │    │
│  │   parser_bridge_android (ARM64 binary, NDK-compiled)    │    │
│  │         │                                               │    │
│  │         ├─→ dlopen("libringeventparser.so")             │    │
│  │         ├─→ dlopen("libprotobuf-lite.so")               │    │
│  │         │                                               │    │
│  │         ├─→ RingEventParser::RingEventParser()          │    │
│  │         ├─→ Session::Session(options_0xFF)              │    │
│  │         ├─→ parser.set_session(session)                 │    │
│  │         ├─→ for each event: parse_events(data, len)     │    │
│  │         ├─→ create_protobuf(ring_data)                  │    │
│  │         └─→ SerializeToArray() → stdout                 │    │
│  │                                                         │    │
│  │   Uses: android_root/system/bin/linker64                │    │
│  │         android_root/system/lib64/*.so                  │    │
│  └─────────────────────────────────────────────────────────┘    │
│       │                                                         │
│       ▼                                                         │
│  ring_data.pb (682KB protobuf)                                  │
│       │                                                         │
│       ▼                                                         │
│  Python decoder → Health metrics (HR, temp, HRV, etc.)          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Setup

### Prerequisites

```bash
# Install QEMU user-mode and Android NDK
sudo pacman -S qemu-user qemu-user-static  # Arch/Manjaro
# or
sudo apt install qemu-user qemu-user-static  # Debian/Ubuntu

# Android NDK (download from developer.android.com or use Android Studio)
# We used: ~/Android/Sdk/ndk/29.0.14206865
```

### 1. Extract Android Sysroot

From a rooted Android device or emulator:

```bash
mkdir -p android_root/system/bin android_root/system/lib64

# Pull linker64 (CRITICAL)
adb pull /system/bin/linker64 android_root/system/bin/

# Pull Bionic libraries
adb pull /system/lib64/libc.so android_root/system/lib64/
adb pull /system/lib64/libm.so android_root/system/lib64/
adb pull /system/lib64/libdl.so android_root/system/lib64/
adb pull /system/lib64/liblog.so android_root/system/lib64/
adb pull /system/lib64/libc++.so android_root/system/lib64/

# Make linker64 executable
chmod +x android_root/system/bin/linker64
```

### 2. Copy Oura Libraries

From the Oura APK (`lib/arm64-v8a/`):

```bash
cp libringeventparser.so android_root/system/lib64/
cp libprotobuf-lite.so android_root/system/lib64/
```

### 3. Compile Bridge with NDK

```bash
NDK=/path/to/android-ndk
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
CC=$TOOLCHAIN/bin/aarch64-linux-android35-clang

$CC -Wall -g -O2 parser_bridge.c -o parser_bridge_android -ldl
```

Verify the binary uses Android's linker:
```bash
file parser_bridge_android
# Should show: interpreter /system/bin/linker64, for Android 35
```

### 4. Run the Parser

```bash
env -i HOME=$HOME PATH=/usr/bin:/bin \
  qemu-aarch64 -L ./android_root \
  -E LD_LIBRARY_PATH=/system/lib64 \
  ./parser_bridge_android ring_events.txt \
  > ring_data.pb 2>parse.log
```

---

## The Bridge Program

Key parts of `parser_bridge.c`:

### Loading Libraries

```c
void* proto_handle = dlopen("libprotobuf-lite.so", RTLD_NOW | RTLD_GLOBAL);
void* parser_handle = dlopen("libringeventparser.so", RTLD_NOW);
```

### Getting Function Pointers

```c
// C++ mangled names
parser_ctor_t parser_ctor = dlsym(parser_handle, "_ZN15RingEventParserC1Ev");
parse_events_t parse_events = dlsym(parser_handle, "_ZN15RingEventParser12parse_eventsEPKhjPj");
create_protobuf_t create_pb = dlsym(parser_handle, "_ZN15RingEventParser15create_protobufEPN3rep8RingDataE");
session_ctor_t session_ctor = dlsym(parser_handle, "_ZN7SessionC1ERK12s_RepOptions");
set_session_t set_session = dlsym(parser_handle, "_ZN15RingEventParser11set_sessionEP7Session");
```

### Creating Session with All Features Enabled

```c
void* session = calloc(1, 8192);
void* options = malloc(256);
memset(options, 0xFF, 256);  // CRITICAL: Enable all parsing modes
session_ctor(session, options);
set_session(parser, session);
```

### Parsing Events One-by-One

```c
for (size_t i = 0; i < event_list->count; i++) {
    uint32_t events_received = 0;
    parse_events(parser, event_list->events[i].data,
                 event_list->events[i].len, &events_received);
}
```

### Serializing Output

```c
ringdata_ctor(ring_data, NULL, 0);  // Create RingData protobuf
create_pb(parser, ring_data);        // Fill with parsed data
size_t size = ringdata_bytesize(ring_data);
uint8_t* output = malloc(size);
serialize(ring_data, output, size);  // Serialize to bytes
fwrite(output, 1, size, stdout);     // Output to stdout
```

---

## Running the Parser

### Quick Test

```bash
cd native_parser

env -i HOME=$HOME PATH=/usr/bin:/bin \
  qemu-aarch64 -L ./android_root \
  -E LD_LIBRARY_PATH=/system/lib64 \
  ./parser_bridge_android ../analysis_scripts/ring_events_20260112_092318.txt \
  > ring_data.pb 2>parse.log

# Check results
cat parse.log | tail -20
ls -la ring_data.pb  # Should be ~682KB
```

### Expected Output (parse.log)

```
Loading libraries...
  Libraries loaded OK
  RingEventParser::ctor: 0x7f...
  ...
=== Parsing 4794 events (88331 bytes) ONE BY ONE ===
  Parsed 0/4794 events, received=0 total
  Parsed 1000/4794 events, received=0 total
  ...
  DONE: parsed 4794 events
=== Serializing RingData ===
  RingData::ByteSizeLong: 682957 bytes
  SerializeToArray returned: 1
  SUCCESS! Writing 682957 bytes to stdout
```

---

## Troubleshooting Journey

### Problem → Solution Summary

| Problem | Error Message | Solution |
|---------|---------------|----------|
| Wrong compiler | `invalid ELF header` | Use NDK, not glibc cross-compiler |
| Missing linker64 | `No such file or directory` | Extract from Android device |
| Host libs leaking | `EM_X86_64 instead of EM_AARCH64` | Use `env -i` for clean environment |
| Empty protobuf | 6 bytes output | Set s_RepOptions to 0xFF |
| "session is nullptr" | Error in stderr | Create Session object |
| "No DHR measurement" | Error in stderr | Set options to 0xFF, not 0x00 |
| Concatenated parsing fails | 6 bytes output | Parse events one-by-one |

---

## Lessons Learned

1. **Android libraries need Android's linker**: Can't mix Bionic and glibc.

2. **NDK compilation is essential**: The binary must request `/system/bin/linker64`.

3. **Environment isolation matters**: Host library paths cause silent failures.

4. **Error messages are gold**: Library stderr output revealed Session requirement.

5. **Trial and error works**: 0x00 vs 0xFF options was discovered experimentally.

6. **nm + c++filt for C++ libraries**: Essential for finding method signatures.

7. **Check binary with `file`**: Quickly reveals linker and target platform.

8. **One-by-one vs batch**: The C++ class API differs from the JNI wrapper behavior.

---

## Files

| File | Purpose |
|------|---------|
| `parser_bridge.c` | C bridge program source |
| `parser_bridge_android` | Compiled ARM64 binary (NDK) |
| `android_root/` | Android sysroot with linker64 and libs |
| `ring_data.pb` | Output protobuf (682KB) |
| `parse.log` | Parser stderr output |

---

## Result

Successfully extracted from overnight sleep data:

- **Heart Rate**: 64.8 BPM average (1,188 IBI measurements)
- **HRV (RMSSD)**: 77.5 ms
- **Temperature**: 34.91°C - 35.71°C
- **Motion**: Activity level distributions
- **SpO2, Activity, and more**: All in the protobuf

Total protobuf output: **682,957 bytes** of health data from 4,794 raw BLE events.
