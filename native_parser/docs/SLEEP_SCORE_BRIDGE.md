# Sleep Score Bridge

How we created the sleep score bridge to call `ecore_sleep_score_calculate_minutes`.

## Function Discovery

### Found the function

```bash
readelf -sW android_root/system/lib64/libappecore.so | grep "sleep_score_calculate"
```

Found two variants:
- `ecore_sleep_score_calculate` - takes seconds
- `ecore_sleep_score_calculate_minutes` - takes minutes (simpler)

### Decoded the mangled name

Mangled: `_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi`

```bash
c++filt '_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi'
# ecore_sleep_score_calculate_minutes(s_sleep_summary_4_t*, unsigned short, unsigned short, ...)
```

### Parameter types from suffix

The suffix `tttthhhthshi` encodes types:
- `P19s_sleep_summary_4_t` = pointer to output struct
- `t` = `unsigned short` (uint16_t)
- `h` = `unsigned char` (uint8_t)
- `s` = `short` (int16_t)
- `i` = `int`

Full signature:
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

## Key Discovery: No ecore_init() Required

This function is **stateless** - it doesn't need the full library initialization that crashes. It only needs `ecore_sleep_score_init_limits()` to set up lookup tables.

## Bridge Implementation

### sleep_score_bridge.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

typedef struct {
    uint8_t data[64];
} s_sleep_summary_4_t;

typedef int (*sleep_score_calc_t)(
    s_sleep_summary_4_t* output,
    uint16_t total_min,
    uint16_t deep_min,
    uint16_t rem_min,
    uint8_t efficiency,
    uint8_t latency_min,
    uint8_t wakeup_count,
    uint16_t awake_sec,
    uint8_t restless,
    int16_t temp_dev,
    uint8_t unknown,
    int day_offset
);

typedef void (*init_limits_t)(uint8_t);

int main() {
    void* handle = dlopen("libappecore.so", RTLD_NOW);

    // Use MANGLED name - this was critical!
    sleep_score_calc_t calc = (sleep_score_calc_t)dlsym(handle,
        "_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi");

    init_limits_t init_limits = (init_limits_t)dlsym(handle,
        "_Z29ecore_sleep_score_init_limitsh");

    // Initialize lookup tables
    if (init_limits) init_limits(0);

    // Parse input, call function, output CSV
    // ... (see full source)
}
```

### Critical: Use Mangled Name

```c
// WRONG - returns NULL
dlsym(handle, "ecore_sleep_score_calculate_minutes");

// CORRECT - works
dlsym(handle, "_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi");
```

## Output Struct Layout

By testing with different inputs:

```c
// After calling the function:
output.data[0] = total sleep contributor
output.data[1] = unknown contributor
output.data[2] = efficiency contributor
output.data[3] = restfulness contributor
output.data[4] = timing contributor
output.data[5] = deep sleep contributor
output.data[6] = latency contributor
```

The function return value is the overall sleep score.

## Compilation

```bash
aarch64-linux-android31-clang -O2 -fPIE -pie \
    -o sleep_score_bridge sleep_score_bridge.c -ldl
```

## Running

```bash
echo "420,84,105,88,10,2,300,4,0" | \
    env -i PATH="$PATH" \
    LD_LIBRARY_PATH="$(pwd)/android_root/system/lib64" \
    qemu-aarch64 -L "$(pwd)/android_root" \
    ./sleep_score_bridge
```

Output:
```
sleepScore,totalContrib,contrib2,efficiencyContrib,restfulnessContrib,timingContrib,deepContrib,latencyContrib
52,63,61,73,1,1,87,33
```

## Input/Output Format

**Input (CSV):**
```
totalSleepMin,deepSleepMin,remSleepMin,efficiency,latencyMin,wakeUpCount,awakeSec,restlessPeriods,tempDeviation
```

**Output (CSV):**
```
sleepScore,totalContrib,contrib2,efficiencyContrib,restfulnessContrib,timingContrib,deepContrib,latencyContrib
```

## Python Integration

```python
def calculate_sleep_score(self, total_sleep_min: int, ...) -> SleepScoreResult:
    input_csv = f"{total_sleep_min},{deep_sleep_min},...\n"
    stdout, stderr = self._run_bridge("sleep_score_bridge", input_csv)

    reader = csv.DictReader(StringIO(stdout))
    row = next(reader)

    return SleepScoreResult(
        score=int(row["sleepScore"]),
        total_contrib=int(row["totalContrib"]),
        ...
    )
```

## Verification

| Input | Expected | Actual |
|-------|----------|--------|
| 8h excellent (480,120,120,95,...) | High score ~60+ | ✅ 60 |
| 7h good (420,84,105,88,...) | Medium score ~50 | ✅ 52 |
| 5h poor (300,45,60,70,...) | Low score ~35 | ✅ 36 |

Better sleep = higher score (verified correct behavior).

---

## Why This Works (Unlike Readiness/Activity)

The sleep score bridge was possible because `ecore_sleep_score_calculate_minutes` has **simple scalar parameters** - just pass integers directly.

**Readiness and Activity scores are different:**

| Score | Function | Input Type |
|-------|----------|------------|
| Sleep | `ecore_sleep_score_calculate_minutes` | Scalar parameters (int, short) |
| Readiness | `readiness_calculate` | Complex structs with nested objects |
| Activity | `activity_score_calculate_100` | Complex structs with arrays |

### Readiness Score Requires:
- `ReadinessScoreSleepInput` - 13 fields
- `PreviousDayInput` - activity from yesterday
- `Baseline` - personal baselines
- `ReadinessScoreHistoryInput` - historical data
- `RestModeInput` - rest mode state

### Activity Score Requires:
- `ActivityInput` - 20 fields including:
  - `byte[]` ringMet array
  - `byte[]` previousDayMet array
  - `RestModeInput` nested object
  - `ActivityHistoryInput[]` array
  - `SleepPeriodInitInput[]` array

These complex inputs would require reverse engineering the exact C struct layouts to match the Java objects, which is significantly more work than the simple sleep score bridge.
