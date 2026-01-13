# Running Oura's libappecore.so via QEMU on x86 Linux

This document details how we successfully ran Oura's ARM64 Android native library (`libappecore.so`) on x86 Linux using QEMU user-mode emulation, specifically for IBI (Inter-Beat Interval) correction functionality.

## Table of Contents

1. [Prerequisites & Setup](#prerequisites--setup)
2. [Problem Statement](#problem-statement)
3. [Background: Why IBI Correction Matters](#background-why-ibi-correction-matters)
4. [Initial Attempts and Failures](#initial-attempts-and-failures)
5. [Key Discoveries from Disassembly](#key-discoveries-from-disassembly)
6. [The Working Solution](#the-working-solution)
7. [Implementation Details](#implementation-details)
8. [Usage](#usage)
9. [Technical Reference](#technical-reference)

---

## Prerequisites & Setup

> **Important:** The `android_root/` directory containing Android system libraries is NOT included in the git repository due to licensing. You must set it up manually.

### Required Software

Install on your Linux system:

```bash
# Debian/Ubuntu
sudo apt install qemu-user qemu-user-binfmt

# Arch Linux
sudo pacman -S qemu-user

# Fedora
sudo dnf install qemu-user
```

For compilation (optional, pre-built binary included):
```bash
# Download Android NDK from https://developer.android.com/ndk/downloads
# Or install via Android Studio SDK Manager
```

### Setting Up android_root/

The `android_root/` directory must contain Android ARM64 system libraries. You have several options:

#### Option 1: Extract from Android Device (Recommended)

```bash
# Connect Android device via ADB
adb root
adb pull /system/bin/linker64 android_root/system/bin/
adb pull /system/lib64/libc.so android_root/system/lib64/
adb pull /system/lib64/libm.so android_root/system/lib64/
adb pull /system/lib64/libdl.so android_root/system/lib64/
adb pull /system/lib64/libc++.so android_root/system/lib64/
adb pull /system/lib64/liblog.so android_root/system/lib64/
```

#### Option 2: Extract from Android Emulator

```bash
# Start Android emulator, then:
adb pull /system/bin/linker64 android_root/system/bin/
adb pull /system/lib64/libc.so android_root/system/lib64/
# ... same as above
```

#### Option 3: Extract from APK/System Image

Extract from an Android system image or factory image:
```bash
# Mount system.img and copy libraries
sudo mount -o ro system.img /mnt
cp /mnt/system/bin/linker64 android_root/system/bin/
cp /mnt/system/lib64/lib{c,m,dl,c++,log}.so android_root/system/lib64/
sudo umount /mnt
```

### Required Directory Structure

```
native_parser/android_root/
├── system/
│   ├── bin/
│   │   └── linker64              # Android dynamic linker (~1.4MB)
│   └── lib64/
│       ├── libc.so               # Android C library (~1.3MB)
│       ├── libm.so               # Math library (~218KB)
│       ├── libdl.so              # Dynamic loading (~14KB)
│       ├── libc++.so             # C++ runtime (~695KB)
│       ├── liblog.so             # Logging (~71KB)
│       ├── ld-android.so -> ../bin/linker64  # Symlink!
│       └── libappecore.so        # Oura's library (from APK)
```

### Getting libappecore.so

Extract from the Oura APK:
```bash
# Get APK (from device or APKMirror)
unzip oura-app.apk -d oura_extracted
cp oura_extracted/lib/arm64-v8a/libappecore.so android_root/system/lib64/
```

### Create Required Symlink

```bash
cd native_parser/android_root/system/lib64
ln -sf ../bin/linker64 ld-android.so
```

### Verify Setup

Use the helper script to check your setup:

```bash
cd native_parser
./setup_android_root.sh --check
```

Or manually verify:
```bash
# Check all files exist
ls -la android_root/system/bin/linker64
ls -la android_root/system/lib64/*.so

# Test QEMU can load the binary
cd native_parser
echo '1000000,1000,13000' | bash run_ibi_correction.sh 2>&1
```

### Quick Setup from Android Device

If you have an Android device connected via ADB:

```bash
cd native_parser
./setup_android_root.sh --from-device
```

This will automatically pull all required libraries.

### Recompiling the Bridge (Optional)

If you need to modify the bridge code:

```bash
# Find your NDK path
NDK_PATH="$HOME/Android/Sdk/ndk/27.0.12077973"

# Compile
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang \
    -O2 -Wall -fPIE -pie \
    -o ibi_correction_bridge_v9 \
    ibi_correction_bridge_v9.c \
    -ldl
```

---

## Problem Statement

We needed to run Oura's proprietary IBI correction algorithm from `libappecore.so` (an ARM64 Android library) on an x86 Linux machine. This library contains the exact algorithm Oura uses to clean and validate heart rate data before feeding it to their ML models like SleepNet.

**Challenges:**
- ARM64 binary on x86 host
- Android-specific dynamic linker and libc
- Complex callback mechanism for receiving corrected data
- No documentation on function signatures

---

## Background: Why IBI Correction Matters

Raw IBI data from the Oura ring contains artifacts:
- Motion artifacts during movement
- Signal noise
- Missing beats
- Ectopic beats (premature heartbeats)

Without correction, ML models produce unrealistic results. For example, SleepNet was outputting **69% Deep Sleep** (normal is 15-25%) because it was processing uncorrected IBI data with artifacts.

The IBI correction algorithm:
- Applies a 7-point median filter
- Detects and marks invalid beats
- Interpolates missing beats
- Outputs validity indicators for each beat

---

## Initial Attempts and Failures

### Attempt 1: Symbol Interposition (Failed)

We tried to intercept the internal `process_corrected_ibi` function by defining our own version with the same mangled C++ name:

```c
// Tried to intercept this symbol
void _Z21process_corrected_ibitt23rr_validity_indicator_tm(
    uint16_t ibi, uint16_t amplitude,
    rr_validity_indicator_t validity, uint64_t timestamp
) {
    // Store corrected data
}
```

**Why it failed:** The symbol is defined as `T` (TEXT) in the library, meaning it's an internal definition. Symbol interposition only works for `U` (undefined) symbols that are resolved at runtime. Internal calls within the library go directly to the internal implementation, bypassing any interposition.

### Attempt 2: Wrong Function Signature (Failed)

We assumed `ibi_correction` took a state parameter:

```c
// WRONG signature
typedef void (*ibi_correction_t)(void* state, uint16_t ibi, uint16_t amplitude, uint64_t timestamp);

// Called like this - WRONG
ibi_correct(state, ibis[i], amplitudes[i], timestamps[i]);
```

**Why it failed:** The library internally shuffles parameters and uses a global state. Our state pointer was being misinterpreted as the IBI value, causing completely scrambled output.

### Attempt 3: GNU Toolchain Compilation (Failed)

Compiled the bridge with `aarch64-linux-gnu-gcc`:

```bash
aarch64-linux-gnu-gcc -o bridge bridge.c -ldl
```

**Why it failed:** QEMU couldn't load the Android library because it tried to use the host's `/usr/aarch64-linux-gnu/lib/libm.so` instead of Android's. Error:
```
Failed to load: /usr/aarch64-linux-gnu/lib/libm.so: invalid ELF header
```

---

## Key Discoveries from Disassembly

### Discovery 1: The JNI Calling Convention

Analyzing `Java_com_ouraring_ecorelibrary_EcoreWrapper_nativeIbiCorrection`:

```asm
# JNI signature: nativeIbiCorrection(JNIEnv, this, ibi, amplitude, timestamp)
c0698:  mov w0, w2       # w0 = ibi (3rd JNI param)
c069c:  mov x2, x4       # x2 = timestamp (5th JNI param)
c06a4:  mov w1, w3       # w1 = amplitude (4th JNI param)
c06a8:  bl ibi_correction # call ibi_correction(ibi, amplitude, timestamp)
```

**Key insight:** `ibi_correction` takes only 3 parameters: `(ibi, amplitude, timestamp)`. There is NO state parameter!

### Discovery 2: Global State Management

In `ibi_correction_cpp`:

```asm
16ee18:  ldr x9, [x10, #3408]  # Load global state pointer
16ee30:  mov x0, x9            # Use global state (ignore any passed state)
16ee34:  str x8, [x9, #4280]   # Store timestamp in state
16ee38:  b rr_correction_run   # Call internal correction
```

The library maintains a **global state** internally. The state we allocate via `ibi_correction_alloc_state` becomes the global state when we call `ibi_correction_set_active_state`.

### Discovery 3: Callback Registration

In `ibi_correction_alloc_state_cpp`:

```asm
16ee78:  str x20, [x0, #4296]  # Store callback at offset 4296
16ee7c:  str x21, [x0, #4304]  # Store context at offset 4304
```

Signature: `ibi_correction_alloc_state(context, callback)`
- First parameter (x0) → stored at offset 4304 (context)
- Second parameter (x1) → stored at offset 4296 (callback)

### Discovery 4: Callback Invocation

In `process_corrected_ibi`:

```asm
16ed50:  ldr x9, [x8, #4296]       # Load callback pointer
16ed58:  stp x3, xzr, [sp, #8]     # Store timestamp at sp+8
16ed5c:  strh w0, [sp, #16]        # Store ibi at sp+16
16ed60:  ldr x0, [x8, #4304]       # Load context
16ed64:  strh w1, [sp, #18]        # Store amplitude at sp+18
16ed68:  add x1, sp, #0x8          # x1 = pointer to data struct
16ed6c:  strb w2, [sp, #20]        # Store validity at sp+20
16ed70:  blr x9                    # callback(context, data_ptr)
```

Callback signature: `callback(void* context, ibi_data_t* data)`

Data structure layout:
```c
typedef struct {
    uint64_t timestamp;   // offset 0
    uint16_t ibi;         // offset 8
    uint16_t amplitude;   // offset 10
    uint8_t validity;     // offset 12
} ibi_callback_data_t;
```

---

## The Working Solution

### 1. Android Root Filesystem

Created a minimal Android sysroot at `android_root/`:

```
android_root/
├── system/
│   ├── bin/
│   │   └── linker64          # Android dynamic linker
│   └── lib64/
│       ├── libc.so           # Android libc
│       ├── libm.so           # Android libm
│       ├── libdl.so          # Android libdl
│       ├── libc++.so         # Android C++ runtime
│       ├── ld-android.so -> ../bin/linker64
│       └── libappecore.so    # Oura's library
```

These libraries were extracted from an Android device or emulator.

### 2. Android NDK Compilation

Must compile with Android NDK, not GNU toolchain:

```bash
/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang \
    -O2 -Wall \
    -fPIE -pie \
    -o ibi_correction_bridge_v9 \
    ibi_correction_bridge_v9.c \
    -ldl
```

This produces a binary with:
- Android dynamic linker: `/system/bin/linker64`
- Android API level compatibility
- Correct ELF format for Android

### 3. Correct Function Signatures

```c
// Initialization
typedef void (*ibi_correction_init_t)(void);

// Allocate state: (context, callback) - NOT (callback, context)!
typedef void* (*ibi_correction_alloc_state_t)(void* context, void* callback);

// Set active state
typedef void (*ibi_correction_set_active_state_t)(void* state);

// Process IBI: NO STATE PARAMETER!
typedef void (*ibi_correction_t)(uint16_t ibi, uint16_t amplitude, uint64_t timestamp);

// Free state
typedef void (*ibi_correction_free_state_t)(void* state);
```

### 4. Callback Implementation

```c
typedef struct {
    uint64_t timestamp;
    uint16_t ibi;
    uint16_t amplitude;
    uint8_t validity;
    uint8_t padding[3];
} ibi_callback_data_t;

void our_ibi_callback(void* context, ibi_callback_data_t* data) {
    // Store or process the corrected data
    corrected_ts[count] = data->timestamp;
    corrected_ibi[count] = data->ibi;
    corrected_amp[count] = data->amplitude;
    corrected_validity[count] = data->validity;
    count++;
}
```

### 5. QEMU Execution

```bash
env -i \
    LD_LIBRARY_PATH="./android_root/system/lib64" \
    QEMU_LD_PREFIX="./android_root" \
qemu-aarch64 -L "./android_root" ./ibi_correction_bridge_v9
```

Key environment variables:
- `env -i` - Clear all environment (prevents interference)
- `LD_LIBRARY_PATH` - Where to find Android libraries
- `QEMU_LD_PREFIX` - Root for Android filesystem
- `-L` - QEMU's library search path

---

## Implementation Details

### Complete Bridge Code

See `native_parser/ibi_correction_bridge_v9.c` for the full implementation.

Key sequence:
```c
// 1. Initialize
ibi_init();

// 2. Allocate state with callback
void* state = ibi_alloc(NULL, (void*)our_ibi_callback);

// 3. Set as active state (makes it global)
ibi_set_state(state);

// 4. Process IBI samples - NO state parameter!
for (int i = 0; i < count; i++) {
    ibi_correct(ibis[i], amplitudes[i], timestamps[i]);
}

// 5. Cleanup
ibi_free(state);
```

### Validity Values

The callback receives a validity indicator:
- `0` = RR_VALID (or initial sample)
- `1` = RR_INVALID (questionable beat, but passed through)
- `2` = RR_INTERPOLATED (missing beat filled in)
- `3` = Unknown (observed in practice, possibly filled)

---

## Usage

### Runner Script

`run_ibi_correction.sh`:

```bash
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_ROOT="$SCRIPT_DIR/android_root"
BRIDGE="$SCRIPT_DIR/ibi_correction_bridge_v9"

exec env -i \
    LD_LIBRARY_PATH="$ANDROID_ROOT/system/lib64" \
    QEMU_LD_PREFIX="$ANDROID_ROOT" \
    qemu-aarch64 -L "$ANDROID_ROOT" "$BRIDGE" "$@"
```

### Input Format

CSV without header:
```
timestamp_ms,ibi_ms,amplitude
1000000,984,12969
1001000,992,13001
...
```

### Output Format

CSV with header:
```
timestamp,ibi,amplitude,validity
1000000,984,12969,0
1001000,992,13001,1
...
```

### Example

```bash
# From native_parser directory
bash run_ibi_correction.sh input.csv 2>/dev/null > output.csv

# Or pipe data
cat ibi_data.csv | bash run_ibi_correction.sh 2>/dev/null > corrected.csv
```

### Results

With 1000 real ring samples:
- **Input:** 1000 IBI samples
- **Output:** 995 corrected samples (5 lost to median filter edges)
- **Validity distribution:**
  - 977 valid (1)
  - 9 special (3)
  - 8 interpolated (2)
  - 1 initial (0)

---

## Technical Reference

### Library Symbols Used

| Symbol | Address | Purpose |
|--------|---------|---------|
| `ibi_correction_init` | 0x16ec90 | Initialize correction system |
| `ibi_correction_alloc_state` | 0x16ec98 | Allocate state with callback |
| `ibi_correction` | 0x16ec94 | Process single IBI sample |
| `ibi_correction_set_active_state` | 0x16ec9c | Set global active state |
| `ibi_correction_free_state` | 0x16eca0 | Free allocated state |
| `process_corrected_ibi` | 0x16ed1c | Internal callback dispatcher |
| `rr_correction_run` | 0x170a48 | Core correction algorithm |

### State Structure Offsets

| Offset | Size | Content |
|--------|------|---------|
| 4128 | 8 | Internal callback (vtable) |
| 4136 | 4 | Sample counter |
| 4148 | 4 | HR baseline (float) |
| 4160 | 2 | Current IBI |
| 4174 | 2 | Current amplitude |
| 4196 | 4 | Current validity |
| 4240 | 8 | Current timestamp |
| 4280 | 8 | Input timestamp |
| 4296 | 8 | External callback pointer |
| 4304 | 8 | External callback context |

### Dependencies

- QEMU user-mode emulation (`qemu-aarch64`)
- Android NDK (for compilation)
- Android system libraries (libc, libm, libdl, libc++)
- Android dynamic linker (linker64)

### Files

| File | Purpose |
|------|---------|
| `ibi_correction_bridge_v9.c` | Main bridge source |
| `ibi_correction_bridge_v9` | Compiled ARM64 binary |
| `run_ibi_correction.sh` | Convenience runner script |
| `android_root/` | Android sysroot for QEMU |

---

## Lessons Learned

1. **Always check JNI wrappers** - They reveal the true function signatures
2. **Symbol interposition doesn't work for internal calls** - Only external (U) symbols can be intercepted
3. **Android NDK is required** - GNU toolchain produces incompatible binaries
4. **Global state is common** - Many Android libraries use singleton patterns
5. **Disassembly is essential** - No other way to understand undocumented libraries
6. **Parameter order matters** - ARM64 calling convention: x0-x7 for first 8 params
7. **Clean environment for QEMU** - Use `env -i` to prevent library conflicts

---

## Future Work

- Wrap other libappecore functions (stress detection, activity analysis)
- Create Python bindings for easier integration
- Add support for batch processing of protobuf data
- Integrate with SleepNet pipeline for end-to-end sleep analysis
