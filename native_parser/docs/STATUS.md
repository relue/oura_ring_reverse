# Native Parser Status

Current state of the Oura native library wrapper project.

## ✅ Working Bridges

| Bridge | Function | Input | Output | Status |
|--------|----------|-------|--------|--------|
| `ibi_correction_bridge_v9` | IBI correction with callbacks | CSV: ts,ibi,amp | CSV: ts,ibi,amp,validity | ✅ Fully working |
| `daytime_hr_bridge` | Daytime heart rate processing | CSV: ts,ibi,amp | CSV: ts,ibi,hr_bpm,quality | ✅ Working |
| `sleep_score_bridge` | Sleep score calculation | CSV: 9 sleep parameters | CSV: score + 7 contributors | ✅ Working |

## 🚧 Attempted (Blocked)

| Bridge | Function | Issue | Status |
|--------|----------|-------|--------|
| `readiness_score_bridge.c` | Readiness score calculation | SIGSEGV - Struct layout mismatch | ❌ Compiled but crashes |
| `nightly_temperature_bridge.c` | Nightly temperature | Stack corruption - JNI wrapper | ❌ Compiled but crashes |

## ⏸️ Pending (Complex Struct Work Required)

| Bridge | Function | Why Pending |
|--------|----------|-------------|
| `activity_score_bridge` | Activity score calculation | Requires 20-field struct with nested arrays |

---

## Why Sleep Score Worked

Sleep score bridge was successful because `ecore_sleep_score_calculate_minutes` has **simple scalar parameters**:

```c
int ecore_sleep_score_calculate_minutes(
    s_sleep_summary_4_t* output,  // output buffer
    uint16_t total_min,           // just an integer
    uint16_t deep_min,            // just an integer
    // ... 9 more simple integer parameters
);
```

**Input:** 9 integers
**Output:** 1 integer (score) + 7 bytes (contributors)
**Complexity:** Low - direct parameter passing

---

## Why Readiness/Activity Are Complex

### Readiness Score Requirements

```c
int readiness_calculate(
    s_ecore_readiness_output_t* output,
    s_ecore_readiness_input_t* input   // Complex nested struct!
);
```

The `s_ecore_readiness_input_t` struct contains:
1. **ReadinessScoreSleepInput** - 13 fields (sleep data)
2. **PreviousDayInput** - activity from previous day
3. **Baseline** - personal baseline values
4. **ReadinessScoreHistoryInput** - historical readiness scores
5. **RestModeInput** - rest mode state

Each of these is itself a complex struct with multiple fields.

### Activity Score Requirements

```c
int activity_score_calculate_100(
    activity_score_input_t* input,     // 20+ fields!
    activity_score_output_t* output,
    unsigned int day_number
);
```

The `activity_score_input_t` struct contains:
- 8 simple fields (timestamps, counts, scores)
- `byte[]` ringMet - MET values array
- `byte[]` previousDayMet - previous day's MET array
- `RestModeInput` - nested object
- `ActivityHistoryInput[]` - array of history objects
- `SleepPeriodInitInput[]` - array of sleep period objects

**Challenge:** Each nested struct and array needs exact memory layout matching.

---

## Technical Challenges

### 1. Struct Layout Matching

The C library expects exact struct layouts:
- Field order
- Field sizes
- Padding/alignment
- Nested struct layouts
- Array element layouts

**Wrong layout = crashes or incorrect results**

### 2. Missing Struct Definitions

We don't have the C header files from Oura. We're reverse engineering from:
- Java class definitions
- Function signatures from `readelf`
- Trial and error with QEMU

### 3. Initialization Requirements

Some functions need:
- `ecore_init()` - but this crashes (requires full context we don't have)
- Stateless alternatives work (like `ecore_sleep_score_calculate_minutes`)
- Readiness/activity may need initialization

---

## Current Approach

### For Sleep Score (✅ Success)
1. Found stateless function with scalar parameters
2. Decoded mangled C++ name to understand types
3. Created simple bridge with direct parameter passing
4. Tested and verified correct behavior

### For Readiness Score (🚧 In Progress)
1. ✅ Found function: `readiness_calculate`
2. ✅ Identified input requirements from Java
3. ✅ Created initial bridge with struct definitions
4. ⏸️ **Need to verify struct layout** - may require:
   - Testing with known inputs
   - Comparing with JNI layer behavior
   - Adjusting field order/padding

### For Activity Score (⏸️ Pending)
1. ✅ Found function: `activity_score_calculate_100`
2. ✅ Identified complex input requirements
3. ⏸️ Need to implement full struct hierarchy
4. ⏸️ Need to handle array serialization

---

## Lessons Learned

### What Makes a Function Wrappable?

**✅ Successfully Wrapped:**
- `ecore_sleep_score_calculate_minutes` - Scalar parameters only
- `ibi_correction/daytime_hr` - Callback-based with state management

**❌ Failed to Wrap:**
- `readiness_calculate` - Complex nested structs
- `natively_temperature` (JNI) - Requires JNI environment

### The Key Pattern

**Functions that work have either:**
1. **Simple scalar parameters** (int, short, etc.)
   - Example: `func(int*, int, int, int...)`
   - Can pass values directly from CSV

2. **Callback-based APIs** (like IBI correction)
   - Example: `alloc_state()`, `set_handler()`, `process()`
   - Can register C callbacks from bridge

**Functions that don't work:**
1. **Complex struct parameters**
   - Need exact C struct layout
   - Must match padding, alignment, field order
   - One byte off = crash

2. **JNI wrappers**
   - Require JNI environment setup
   - Can't call directly from C bridge
   - Need actual Java VM context

### Why Struct Matching Is Hard

```c
// What we guess from Java:
typedef struct {
    int64_t sleep_date;
    int day_number;
    int sleep_score;
    // ...
} readiness_input_t;

// What the library actually expects:
typedef struct {
    int64_t sleep_date;
    int32_t padding;  // Compiler adds this!
    int day_number;
    // Different field order?
    // Different padding?
    // Nested structs with their own layout?
} s_ecore_readiness_input_t;
```

One misaligned field = **SIGSEGV** or corrupted data.

---

## Next Steps

### Option 1: Complete Readiness Bridge
**Effort:** Medium
**Value:** High - readiness score is important

**Tasks:**
1. Compile `readiness_score_bridge.c` (need Android NDK)
2. Test with sample data
3. Debug struct layout issues
4. Iterate until correct output

**Estimated complexity:** Moderate - only 1 level of nesting

### Option 2: Implement Activity Bridge
**Effort:** High
**Value:** High - activity score is important

**Tasks:**
1. Define all nested struct types
2. Handle array serialization
3. Match exact memory layouts
4. Extensive testing

**Estimated complexity:** High - multiple nested objects and arrays

### Option 3: Find Other Simple Functions
**Effort:** Low
**Value:** Variable

Look for other stateless functions with scalar parameters:
- Temperature baseline calculation
- Breathing rate calculation
- SpO2 metrics
- MET classification

---

## Python Wrapper Status

Current `oura_ecore.py` provides:

```python
class EcoreWrapper:
    # ✅ Working methods
    def correct_ibi(data) -> List[IbiResult]
    def process_daytime_hr(data) -> List[HrResult]
    def calculate_sleep_score(...) -> SleepScoreResult

    # ⏸️ Placeholder methods (not yet implemented)
    def calculate_readiness_score(...) -> ReadinessScore
    def calculate_activity_score(...) -> ActivityScore
```

---

## Compilation Requirements

To compile bridges, need Android NDK:

```bash
# Install Android NDK
# https://developer.android.com/ndk/downloads

# Compile command
aarch64-linux-android31-clang -O2 -fPIE -pie \
    -o readiness_score_bridge readiness_score_bridge.c -ldl
```

Current bridges were compiled with NDK r27.

---

## Summary

**What Works:**
- ✅ IBI correction (stateless, callback-based) - **VERIFIED WORKING**
- ✅ Daytime HR (stateless, callback-based) - **VERIFIED WORKING**
- ✅ Sleep score (stateless, scalar parameters) - **VERIFIED WORKING**

**What Doesn't Work (Yet):**
- ❌ Readiness score - **CRASHES** (struct layout mismatch)
- ❌ Nightly temperature - **CRASHES** (JNI wrapper requires JVM)
- ⏸️ Activity score - Not attempted (very complex structs)

**Key Insight:**
- **Scalar parameters** → Easy to wrap ✅
- **Callback-based APIs** → Manageable with state ✅
- **Complex structs** → Requires exact memory layout ❌
- **JNI functions** → Requires Java VM context ❌

**Current Status:**
We have successfully wrapped the sleep score function by finding a variant with simple scalar parameters. Other score functions (readiness, activity) require complex struct inputs that we cannot easily match without the original C header files.

**Recommended Path Forward:**
1. ✅ Document findings (DONE)
2. Focus on improving existing bridges (sleep, IBI, HR)
3. Consider alternative approaches for readiness/activity:
   - Reverse engineer from compiled code with Ghidra
   - Implement score algorithms directly in Python (no native calls)
   - Use mock scores for testing purposes
