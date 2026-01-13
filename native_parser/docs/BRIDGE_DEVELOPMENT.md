# Bridge Development Guide

How to create bridges that call native Oura library functions via QEMU.

## Overview

The Oura ring app uses `libappecore.so` (ARM64) for core calculations. We run these functions on x86 Linux using QEMU user-mode emulation with small C bridge programs.

```
Python → Bridge Binary (ARM64) → QEMU → libappecore.so → Results
```

## Working Bridges

| Bridge | Function | Status |
|--------|----------|--------|
| `ibi_correction_bridge_v9` | IBI correction with callbacks | ✅ Working |
| `daytime_hr_bridge` | Daytime heart rate processing | ✅ Working |
| `sleep_score_bridge` | Sleep score calculation | ✅ Working |

---

## Step 1: Find the Native Function

### List exported symbols

```bash
readelf -sW android_root/system/lib64/libappecore.so | grep "sleep_score"
```

### Demangle C++ names

```bash
# Get mangled name
readelf -sW android_root/system/lib64/libappecore.so | grep "sleep_score_calculate"
#  1992: 00000000000ec854   472 FUNC    GLOBAL DEFAULT   14 _Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi

# Demangle to see signature
c++filt '_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi'
# ecore_sleep_score_calculate_minutes(s_sleep_summary_4_t*, unsigned short, unsigned short, ...)
```

### Decode parameter types from mangled suffix

The suffix `tttthhhthshi` encodes parameter types:
- `t` = `unsigned short` (uint16_t)
- `h` = `unsigned char` (uint8_t)
- `s` = `short` (int16_t)
- `i` = `int`
- `j` = `unsigned int` (uint32_t)
- `P` = pointer

Example: `ttthhhthshi` means:
```c
func(uint16_t, uint16_t, uint16_t, uint8_t, uint8_t, uint8_t, uint16_t, uint8_t, int16_t, uint8_t, int)
```

---

## Step 2: Create the Bridge

### Basic template

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

// Define output struct (reverse engineer from function usage)
typedef struct {
    uint8_t data[64];
} output_struct_t;

// Function pointer type matching the native signature
typedef int (*native_func_t)(
    output_struct_t* output,
    uint16_t param1,
    uint16_t param2,
    // ... more params based on mangled signature
);

int main(int argc, char* argv[]) {
    // 1. Load library
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }

    // 2. Get function pointer using MANGLED name
    native_func_t func = (native_func_t)dlsym(handle,
        "_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi");

    if (!func) {
        fprintf(stderr, "Function not found\n");
        dlclose(handle);
        return 1;
    }

    // 3. Parse input from stdin
    int param1 = 0, param2 = 0;
    char line[256];
    if (fgets(line, sizeof(line), stdin)) {
        sscanf(line, "%d,%d", &param1, &param2);
    }

    // 4. Call native function
    output_struct_t output = {0};
    int result = func(&output, param1, param2);

    // 5. Output CSV to stdout
    printf("result,field1,field2\n");
    printf("%d,%d,%d\n", result, output.data[0], output.data[1]);

    dlclose(handle);
    return 0;
}
```

---

## Step 3: Compile for ARM64

```bash
# Using Android NDK
/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang \
    -O2 -fPIE -pie \
    -o my_bridge my_bridge.c \
    -ldl
```

---

## Step 4: Test with QEMU

```bash
echo "420,84,105,88" | \
    env -i PATH="$PATH" \
    LD_LIBRARY_PATH="$(pwd)/android_root/system/lib64" \
    qemu-aarch64 -L "$(pwd)/android_root" \
    ./my_bridge
```

---

## Case Study: Sleep Score Bridge

### 1. Found the function

```bash
readelf -sW libappecore.so | grep "sleep_score_calculate"
```

Found two variants:
- `ecore_sleep_score_calculate` - takes seconds
- `ecore_sleep_score_calculate_minutes` - takes minutes (simpler)

### 2. Decoded the signature

Mangled: `_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi`

Decoded:
```c
int ecore_sleep_score_calculate_minutes(
    s_sleep_summary_4_t* output,  // P19s_sleep_summary_4_t
    uint16_t total_min,           // t
    uint16_t deep_min,            // t
    uint16_t rem_min,             // t
    uint8_t efficiency,           // h
    uint8_t latency_min,          // h
    uint8_t wakeup_count,         // h
    uint16_t awake_sec,           // t
    uint8_t restless,             // h
    int16_t temp_dev,             // s
    uint8_t unknown,              // h
    int day_offset                // i
);
```

### 3. Discovered initialization requirement

Some functions need `ecore_sleep_score_init_limits()` called first to set up lookup tables:

```c
typedef void (*init_limits_t)(uint8_t);
init_limits_t init = dlsym(handle, "_Z29ecore_sleep_score_init_limitsh");
if (init) init(0);
```

### 4. Reverse engineered output struct

By testing with different inputs and examining output bytes:

```c
typedef struct {
    uint8_t data[64];
} s_sleep_summary_4_t;

// After calling the function:
// data[0] = total sleep contributor
// data[1] = unknown contributor
// data[2] = efficiency contributor
// data[3] = restfulness contributor
// data[4] = timing contributor
// data[5] = deep sleep contributor
// data[6] = latency contributor
```

### 5. Final bridge

See `sleep_score_bridge.c` for the complete implementation.

Input: `totalMin,deepMin,remMin,efficiency,latencyMin,wakeups,awakeSec,restless,tempDev`

Output: `sleepScore,totalContrib,contrib2,efficiencyContrib,restfulnessContrib,timingContrib,deepContrib,latencyContrib`

---

## Common Issues

### "Function not found"

Use the **mangled** C++ name, not the demangled name:
```c
// WRONG
dlsym(handle, "ecore_sleep_score_calculate_minutes");

// CORRECT
dlsym(handle, "_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi");
```

### "CANNOT LINK EXECUTABLE"

Clean environment to avoid x86 library conflicts:
```bash
env -i PATH="$PATH" LD_LIBRARY_PATH="..." qemu-aarch64 ...
```

### Output is all zeros

- Function may need initialization first
- Struct layout may be wrong
- Parameters may be in wrong order

### Scores seem inverted

- Check parameter order matches function signature
- Try the `_minutes` variant vs `_seconds` variant
- The return value might be the score, not struct field

---

## Adding to Python Wrapper

```python
def calculate_sleep_score(self, total_min: int, deep_min: int, ...) -> SleepScoreResult:
    input_csv = f"{total_min},{deep_min},...\n"
    stdout, stderr = self._run_bridge("sleep_score_bridge", input_csv)

    reader = csv.DictReader(StringIO(stdout))
    row = next(reader)

    return SleepScoreResult(
        score=int(row["sleepScore"]),
        ...
    )
```

---

## Tools

- `readelf -sW` - List symbols with full names
- `c++filt` - Demangle C++ names
- `nm -gC` - List symbols (may not work on stripped binaries)
- `strings` - Find string constants in binary
- QEMU user mode - Run ARM64 binaries on x86
