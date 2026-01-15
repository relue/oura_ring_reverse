# Native Sleep Score Calculation

This document explains how the native Oura sleep score calculation works, from the ARM64 library to the Python wrapper and web UI.

## Overview

The sleep score calculation uses Oura's proprietary `libappecore.so` library, which is an ARM64 Android native library. We run it on x86_64 Linux using QEMU user-mode emulation through a C bridge binary.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Architecture                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Python (x86_64)          QEMU (ARM64 emulation)      Native ARM64  │
│  ┌──────────────┐         ┌─────────────────────┐    ┌────────────┐ │
│  │ oura_ecore.py│ ──────► │sleep_score_minutes  │───►│libappecore │ │
│  │              │  args   │     _ndk            │    │    .so     │ │
│  │ EcoreWrapper │ ◄────── │                     │◄───│            │ │
│  └──────────────┘  stdout └─────────────────────┘    └────────────┘ │
│         │                                                            │
│         ▼                                                            │
│  ┌──────────────┐                                                    │
│  │SleepAnalyzer │                                                    │
│  │ (sleep.py)   │                                                    │
│  └──────────────┘                                                    │
│         │                                                            │
│         ▼                                                            │
│  ┌──────────────┐                                                    │
│  │ FastAPI      │                                                    │
│  │ Backend      │                                                    │
│  └──────────────┘                                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Native Library Function

### Function Signature

The stateless sleep score function (demangled from C++ name mangling):

```
Mangled:   _Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi
Demangled: ecore_sleep_score_calculate_minutes(s_sleep_summary_4_t*,
           uint16, uint16, uint16, uint16,  // total, deep, rem, light (minutes)
           uint8, uint8, uint8,             // efficiency, latency_min, wakeup_count
           uint16,                          // awake_seconds
           uint8,                           // restless_periods
           int16,                           // temp_deviation (centidegrees)
           uint8,                           // got_up_count
           int32)                           // sleep_midpoint (seconds from midnight)
```

### Initialization Function

Before calling the score function, we initialize scoring limits:

```c
// Mangled: _Z29ecore_sleep_score_init_limitsh
void ecore_sleep_score_init_limits(uint8_t chronotype_factor);
```

The `chronotype_factor` (0-100) affects circadian timing scoring:
- `0` = Early bird (optimal midpoint ~10 PM)
- `50` = Neutral (optimal midpoint ~2 AM)
- `100` = Night owl (optimal midpoint ~6 AM)

We use `100` as default which corresponds to ~2:47 AM optimal sleep midpoint.

## Bridge Binary

### Source: `sleep_score_minutes.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

typedef struct { uint8_t data[64]; } output_t;
typedef int (*calc_t)(output_t*, uint16_t, uint16_t, uint16_t, uint16_t,
                      uint8_t, uint8_t, uint8_t, uint16_t, uint8_t,
                      int16_t, uint8_t, int);
typedef void (*init_t)(uint8_t);

int main(int argc, char* argv[]) {
    void* h = dlopen("libappecore.so", RTLD_NOW);
    calc_t calc = (calc_t)dlsym(h, "_Z35ecore_sleep_score_calculate_minutes...");
    init_t init = (init_t)dlsym(h, "_Z29ecore_sleep_score_init_limitsh");

    // Default values
    int total=420, deep=84, rem=105, light=231, eff=88, lat=10,
        wakeups=2, awake=300, restless=4, temp=0, gotup=0, midpoint=10800;

    // Parse command line argument (comma-separated)
    if (argc > 1) {
        sscanf(argv[1], "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
               &total, &deep, &rem, &light, &eff, &lat, &wakeups,
               &awake, &restless, &temp, &gotup, &midpoint);
    }

    // Initialize and calculate
    if (init) init(100);  // chronotype_factor = 100
    output_t out = {0};
    int score = calc(&out, total, deep, rem, light, eff, lat, wakeups,
                     awake, restless, temp, gotup, midpoint);

    // Output for Python wrapper
    printf("sleepScore\n%d\n", score);
    printf("contributors\n%d,%d,%d,%d,%d,%d\n",
           out.data[0], out.data[1], out.data[2],
           out.data[3], out.data[5], out.data[6]);
    printf("qualityFlag\n%d\n", out.data[4]);

    dlclose(h);
    return 0;
}
```

### Building with NDK

```bash
# Compile with Android NDK for ARM64
~/Android/Sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/\
aarch64-linux-android26-clang -o sleep_score_minutes_ndk sleep_score_minutes.c -ldl -O2
```

## Output Structure

The native function returns the overall score as the return value, and writes contributor scores to an output struct:

```
┌─────────────────────────────────────────────────────────┐
│              s_sleep_summary_4_t Output                 │
├──────────┬──────────────────────────────────────────────┤
│ Byte 0   │ total_sleep_contrib (0-100)                  │
│ Byte 1   │ deep_sleep_contrib (0-100)                   │
│ Byte 2   │ rem_sleep_contrib (0-100)                    │
│ Byte 3   │ efficiency_contrib (0-100)                   │
│ Byte 4   │ quality_flag (1=good, higher=deficits)       │
│ Byte 5   │ latency_contrib (0-100)                      │
│ Byte 6   │ disturbances_contrib (0-100)                 │
│ Byte 7+  │ (unused/reserved)                            │
└──────────┴──────────────────────────────────────────────┘
```

**Note**: Circadian/timing contributor is NOT returned separately. It is factored into the overall score via `init_limits()`. We use a fixed value of 80 for the UI.

## Input Parameters

### 1. Total Sleep (minutes)
- Source: `SleepAnalyzer.stage_durations.total_sleep`
- ML-derived from SleepNet model

### 2. Deep Sleep (minutes)
- Source: `SleepAnalyzer.stage_durations.deep`
- ML-derived from SleepNet model

### 3. REM Sleep (minutes)
- Source: `SleepAnalyzer.stage_durations.rem`
- ML-derived from SleepNet model (critical - raw protobuf doesn't have REM)

### 4. Light Sleep (minutes)
- Source: `SleepAnalyzer.stage_durations.light`
- ML-derived from SleepNet model

### 5. Efficiency (0-100%)
- Source: `SleepAnalyzer.stage_durations.efficiency`
- Calculated as: `(total_sleep / total_time_in_bed) * 100`

### 6. Latency (minutes)
- Source: `SleepAnalyzer._calculate_latency()`
- Time from bedtime_start to first non-awake epoch
- Uses bedtime_period from protobuf + ML stage timestamps

### 7. Wakeup Count
- Source: `SleepAnalyzer._estimate_wakeup_count()`
- Counts transitions from sleep to awake state

### 8. Awake Seconds
- Source: `SleepAnalyzer.stage_durations.awake * 60`
- Total time in awake state during sleep period

### 9. Restless Periods
- Source: `SleepAnalyzer._calculate_restless_periods()`
- Counts periods where `motion_count > 15` during bedtime
- Uses sleep_period_info from protobuf

### 10. Temperature Deviation (centidegrees)
- Source: `SleepAnalyzer._calculate_temp_deviation()`
- Highest temperature during sleep minus baseline (35.5°C)
- Multiplied by 100 for centidegrees
- Uses sleep_temp_event from protobuf

### 11. Got Up Count
- Currently fixed at 0 (TODO: extract from data)
- Would count times user physically got out of bed

### 12. Sleep Midpoint (seconds from midnight)
- Source: Calculated from bedtime_start and bedtime_end
- `midpoint = (start + end) / 2`, converted to seconds from midnight
- Used for circadian alignment scoring

## Python Wrapper

### EcoreWrapper Class

Location: `native_parser/oura_ecore.py`

```python
class EcoreWrapper:
    def calculate_sleep_score(
        self,
        total_sleep_min: int,
        deep_sleep_min: int,
        rem_sleep_min: int,
        light_sleep_min: int = None,
        efficiency: int = 85,
        latency_min: int = 10,
        wakeup_count: int = 2,
        awake_sec: int = 300,
        restless_periods: int = 4,
        temp_deviation: int = 0,
        got_up_count: int = 0,
        sleep_midpoint_sec: int = 10800,
    ) -> SleepScoreResult:
        """Calculate sleep score using native Oura library."""

        # Format as comma-separated string
        input_args = f"{total_sleep_min},{deep_sleep_min},..."

        # Run via QEMU with command line args
        stdout, stderr = self._run_bridge(
            "sleep_score_minutes_ndk",
            input_args,
            use_args=True  # IMPORTANT: avoids QEMU stdin bug
        )

        # Parse output
        return SleepScoreResult(...)
```

### QEMU Stdin Bug Workaround

There is a critical bug when piping data via stdin to QEMU:

```bash
# BROKEN - produces wrong results (Score=68 instead of 77)
echo "420,84,105,231,88,10,2,300,4,0,0,10800" | qemu-aarch64 ./bridge

# WORKING - correct results (Score=77)
qemu-aarch64 ./bridge "420,84,105,231,88,10,2,300,4,0,0,10800"
```

The library's state is somehow corrupted when stdin is piped. Solution: Pass data as command line argument using `use_args=True`.

## Integration with SleepAnalyzer

Location: `native_parser/oura/analysis/sleep.py`

```python
class SleepAnalyzer:
    @property
    def score(self) -> SleepScore:
        """Calculate sleep score with contributors."""
        if self._score is not None:
            return self._score

        durations = self.stage_durations  # ML-aware!

        try:
            from oura_ecore import EcoreWrapper
            ecore = EcoreWrapper()

            result = ecore.calculate_sleep_score(
                total_sleep_min=int(durations.total_sleep),
                deep_sleep_min=int(durations.deep),
                rem_sleep_min=int(durations.rem),  # ML REM!
                light_sleep_min=int(durations.light),
                efficiency=int(durations.efficiency),
                latency_min=self._calculate_latency(),
                wakeup_count=self._estimate_wakeup_count(),
                awake_sec=int(durations.awake * 60),
                restless_periods=self._calculate_restless_periods(),
                temp_deviation=self._calculate_temp_deviation(),
                got_up_count=0,
                sleep_midpoint_sec=sleep_midpoint_sec,
            )

            self._score = SleepScore(
                score=result.score,
                total_sleep=result.total_sleep_contrib,
                efficiency=result.efficiency_contrib,
                restfulness=result.disturbances_contrib,
                rem_sleep=result.rem_sleep_contrib,
                deep_sleep=result.deep_sleep_contrib,
                latency=result.latency_contrib,
                timing=80,  # Fixed - circadian baked into main score
            )
        except Exception:
            # Fallback to basic Python calculation
            self._score = self._calculate_basic_score()

        return self._score
```

## Backend API Integration

Location: `native_parser/webapp/backend/main.py`

The `/dashboard/sleep-stages` endpoint returns the native sleep score:

```python
@app.get("/dashboard/sleep-stages")
async def get_sleep_stages_dashboard(night: int = -1):
    reader = get_reader()
    sleep_analyzer = SleepAnalyzer(reader, night_index=night)

    # This triggers native calculation
    sleep_score = sleep_analyzer.score

    return SleepStagesDashboard(
        score=SleepScoreResponse(
            score=sleep_score.score,
            total_sleep=sleep_score.total_sleep,
            efficiency=sleep_score.efficiency,
            restfulness=sleep_score.restfulness,
            rem_sleep=sleep_score.rem_sleep,
            deep_sleep=sleep_score.deep_sleep,
            latency=sleep_score.latency,
            timing=sleep_score.timing,
        ),
        ...
    )
```

## Data Flow Example

```
1. User requests /dashboard/sleep-stages?night=-1

2. Backend creates SleepAnalyzer(reader, night_index=-1)

3. SleepAnalyzer.score property called:
   a. Loads SleepNet ML model (if available)
   b. Runs ML inference → stages, durations
   c. Calculates latency from bedtime_period + stages
   d. Calculates restless from motion_count
   e. Calculates temp deviation from sleep_temp_event

4. EcoreWrapper.calculate_sleep_score() called:
   a. Formats 12 parameters as comma-separated string
   b. Runs: qemu-aarch64 ./sleep_score_minutes_ndk "420,84,..."
   c. Bridge loads libappecore.so via dlopen
   d. Calls init_limits(100) + calculate_minutes(...)
   e. Prints score and contributors to stdout

5. Python parses stdout:
   sleepScore
   70
   contributors
   98,97,72,88,64,1
   qualityFlag
   1

6. Returns SleepScoreResult to SleepAnalyzer

7. SleepAnalyzer maps to SleepScore dataclass

8. Backend returns JSON to frontend
```

## File Structure

```
native_parser/
├── sleep_score_minutes.c          # C bridge source
├── sleep_score_minutes_ndk        # Compiled ARM64 binary
├── oura_ecore.py                  # Python wrapper
├── android_root/                  # QEMU sysroot
│   └── system/lib64/
│       └── libappecore.so         # Oura native library
├── oura/
│   └── analysis/
│       └── sleep.py               # SleepAnalyzer
└── webapp/
    └── backend/
        └── main.py                # FastAPI endpoints
```

## Troubleshooting

### "Bridge not found"
```bash
# Rebuild the binary
cd native_parser
~/Android/Sdk/ndk/.../aarch64-linux-android26-clang \
    -o sleep_score_minutes_ndk sleep_score_minutes.c -ldl -O2
```

### "libappecore.so not found"
```bash
# Extract from Oura APK
unzip oura.apk -d oura_extracted
cp oura_extracted/lib/arm64-v8a/libappecore.so android_root/system/lib64/
```

### Wrong scores (too low)
- Ensure using command line args, not stdin piping
- Check `use_args=True` in `_run_bridge()` call

### "qemu-aarch64 not found"
```bash
# Arch Linux
sudo pacman -S qemu-user

# Debian/Ubuntu
sudo apt install qemu-user qemu-user-binfmt
```

## Score Interpretation

| Score Range | Quality |
|-------------|---------|
| 85-100      | Optimal |
| 70-84       | Good    |
| 60-69       | Fair    |
| < 60        | Poor    |

| Contributor | Optimal Value | What It Measures |
|-------------|---------------|------------------|
| Total Sleep | 97-100        | 7-9 hours sleep  |
| Deep Sleep  | 97-100        | 15-20% of total  |
| REM Sleep   | 97-100        | 20-25% of total  |
| Efficiency  | 90-100        | >85% asleep      |
| Latency     | 90-100        | <15 min to sleep |
| Restfulness | 70-100        | Few disturbances |
| Timing      | 80 (fixed)    | Circadian align  |
