# Sleep Staging Model: 99% Implementation Difficulty Analysis

**Date:** 2026-01-12
**Objective:** Achieve exact parity with Oura's original sleep staging implementation

---

## Executive Summary

| Approach | Difficulty | Achievability | Notes |
|----------|------------|---------------|-------|
| **SleepNet (Deep Learning)** | **Medium** | **~95-99%** | Pure PyTorch, loads directly |
| SleepStaging (Traditional ML) | Hard | ~80-90% | Requires reverse engineering custom ops |
| Full Oura Pipeline | Very Hard | ~85-95% | Data collection + preprocessing gaps |

**Recommendation:** Use `sleepnet_1_0_0.pt` - it's a pure PyTorch model that loads without custom operators.

---

## Two Sleep Staging Approaches in Oura

### 1. SleepStaging Model (Traditional ML) - `sleepstaging_2_6_0.pt` (112 KB)

**Architecture:**
```
Raw Sensor Data → Feature Extraction → XGBoost/LightGBM Classifier → Sleep Stages
                  (36 HRV features)    (in libalgos.so)
```

**Blocking Issues:**
- Uses 5 custom operators in `libalgos.so` (5.5 MB ARM64 binary)
- `oura_ops::oura_sleep_classifier` - The actual classifier (embedded XGBoost/LightGBM)
- `oura_ops::oura_create_windows` - 30-second epoch windowing
- `oura_ops::oura_biquad_cascade` - IIR filter for HRV
- `oura_ops::oura_find_peaks` - R-peak detection
- `oura_ops::oura_find_indices` - Index lookup

**Difficulty to Reimplement:**

| Custom Op | Complexity | Can Reimplement? |
|-----------|------------|------------------|
| `oura_sleep_classifier` | **Very Hard** | No - weights embedded in binary |
| `oura_create_windows` | Easy | Yes - sliding window |
| `oura_biquad_cascade` | Medium | Yes - scipy.signal.sosfilt |
| `oura_find_peaks` | Easy | Yes - scipy.signal.find_peaks |
| `oura_find_indices` | Easy | Yes - np.searchsorted |

**The Classifier Problem:**
- 1.07 MB `.rodata` section contains embedded model weights
- No standard format (not ONNX, not JSON)
- Would require binary reverse engineering to extract

---

### 2. SleepNet Model (Deep Learning) - `sleepnet_1_0_0.pt` (4.5 MB)

**Architecture:**
```
Raw Sensor Data → Preprocessing → SE-Net CNN → Sleep Stages
                  (in model)      (1M params)   + Apnea + SpO2
```

**Key Finding: NO CUSTOM OPERATORS!**

```python
import torch
model = torch.jit.load('sleepnet_1_0_0.pt', map_location='cpu')
# SUCCESS! Loads without libalgos.so
```

**Model Stats:**
- Parameters: 1,075,955 (~1M)
- Architecture: Squeeze-Excitation CNN
- Self-contained: All preprocessing in PyTorch

---

## SleepNet Input Requirements (Exact)

From `input_validation.py`:

| Input | Shape | Dtype | Description |
|-------|-------|-------|-------------|
| `bedtime_input` | (2,) | float64 | [start_sec, end_sec] Unix timestamps |
| `ibi_input` | (N, 4) | float64 | [timestamp_sec, ibi_ms, ?, validity] |
| `acm_input` | (N, 2) | float64 | [timestamp_sec, motion_count] (0-30 range) |
| `temp_input` | (N, 2) | float64 | [timestamp_sec, temperature_celsius] (0-70°C) |
| `spo2_input` | (N, 2) | float64 | [timestamp_sec, spo2_percent] (0-110) |
| `scalars_input` | (5,) | float64 | [age, weight_kg, sex, ?, ?] |
| `tst_input` | (1,) | float64 | Total sleep time hint (0-900 minutes) |

**Validation Ranges:**
- Timestamps: 1262304000 - 7258118400 (2010-01-01 to 2200-01-01)
- IBI column 1: 0-inf (IBI in ms)
- IBI column 3: Must have at least one value = 1 (validity)
- Motion: 0-30 counts per epoch
- Temperature: 0-70°C
- SpO2: 0-110%
- Age: 5-140 years
- Weight: 0-200 kg
- Sex: -1 to 1 (normalized)

---

## SleepNet Output Format

Returns tuple of 5 tensors:
```python
(staging_outputs, apnea_outputs, spo2_outputs, output_metrics, debug_metrics)
```

**staging_outputs:** Sleep stage predictions
- 4 classes: Awake, Light, Deep, REM (30-second epochs)

**apnea_outputs:** Sleep apnea indicators

**spo2_outputs:** SpO2 predictions

---

## Data Collection Gap Analysis

### What We Can Collect from Ring (BLE Events)

| Data Type | Event | Format | Coverage |
|-----------|-------|--------|----------|
| IBI (Heart Rate) | 0x44 (IBI_EVENT) | timestamp + IBI | **Full** |
| Motion/Accelerometer | 0x47 (ACCELEROMETER_DATA) | raw 3-axis | **Full** |
| Temperature | 0x61 (DEVICE_STATUS) | ring temp | **Full** |
| Sleep Period | 0x6A (SLEEP_PERIOD_INFO) | 14-byte struct | **Full** |

### What We're Missing

| Data Type | Source | Gap |
|-----------|--------|-----|
| SpO2 | Gen 3 Hardware | Ring has sensor, event format unknown |
| Bedtime Window | App Logic | Need algorithm or user input |
| Demographics | User Profile | Need user to provide age/weight/sex |

---

## Implementation Roadmap for 99% Accuracy

### Phase 1: Data Collection (Ring → Raw Data)
- [x] BLE protocol documented
- [x] IBI event parsing (0x44)
- [x] Accelerometer event parsing (0x47)
- [x] Temperature from device status
- [ ] SpO2 event discovery (if Gen 3 supports it)

### Phase 2: Data Preprocessing
- [ ] Convert accelerometer to motion counts (aggregate to 30s epochs)
- [ ] Align all timestamps to 30-second epochs
- [ ] Handle missing data (NaN filling strategy)
- [ ] Apply same normalization as Oura

### Phase 3: Model Inference
```python
import torch

# Load model
model = torch.jit.load('sleepnet_1_0_0.pt', map_location='cpu')
model.eval()

# Prepare inputs (shapes must match exactly)
bedtime = torch.tensor([start_unix, end_unix], dtype=torch.float64)
ibi = torch.tensor(ibi_data, dtype=torch.float64)  # (N, 4)
acm = torch.tensor(motion_data, dtype=torch.float64)  # (N, 2)
temp = torch.tensor(temp_data, dtype=torch.float64)  # (N, 2)
spo2 = torch.tensor(spo2_data, dtype=torch.float64)  # (N, 2) or empty
scalars = torch.tensor([age, weight, sex, 0, 0], dtype=torch.float64)
tst = torch.tensor([0.0], dtype=torch.float64)

# Run inference
with torch.no_grad():
    staging, apnea, spo2_out, metrics, debug = model(
        bedtime, ibi, acm, temp, spo2, scalars, tst
    )
```

### Phase 4: Output Interpretation
- [ ] Map model outputs to sleep stages (Awake/Light/Deep/REM)
- [ ] Apply post-processing (smoothing, minimum epoch rules)
- [ ] Calculate sleep metrics (total sleep, efficiency, latency)

---

## Difficulty Breakdown

### Easy (Can Do Now)
1. Load `sleepnet_1_0_0.pt` - **Done**, works out of box
2. Understand input format - **Done**, documented above
3. Collect IBI data from ring - **Done**, 0x44 event
4. Collect motion data from ring - **Done**, 0x47 event
5. Collect temperature - **Done**, device status

### Medium (Need Work)
1. Convert accelerometer to motion counts
   - Need to understand Oura's aggregation formula
   - MAD (Median Absolute Deviation) calculation

2. Bedtime detection algorithm
   - Could use simple heuristic (user sets bedtime)
   - Or implement activity-based detection

3. SpO2 handling
   - If not available, may need to pass zeros
   - Test model behavior with empty SpO2

### Hard (Research Required)
1. Exact preprocessing parity
   - Feature scaling/normalization
   - Missing data handling
   - Edge cases (short sleeps, interruptions)

2. Demographics mapping
   - What are scalars[3] and scalars[4]?
   - Need to reverse engineer from app

---

## Achievable Accuracy Estimate

| Component | Our Implementation | Gap |
|-----------|-------------------|-----|
| Model weights | 100% (exact copy) | 0% |
| Input preprocessing | ~90-95% | 5-10% |
| Data collection | ~95% (no SpO2?) | 5% |
| Post-processing | ~95% | 5% |

**Overall: ~85-95% accuracy vs Oura app**

To reach 99%:
1. Need exact preprocessing logic (reverse engineer app)
2. Need SpO2 data or confirm it's optional
3. Need exact post-processing rules

---

## Alternative: Use Both Models

```
Ring Data → Feature Extraction → sleepstaging_2_6_0.pt (if we reimplement ops)
                              → sleepnet_1_0_0.pt (direct, works now)

→ Ensemble/Compare results
```

The `sleepnet` model is the newer, more accurate model (deep learning vs traditional ML). Oura likely uses it as the primary model now.

---

## Quick Start Code

```python
#!/usr/bin/env python3
"""Run sleep staging on collected ring data."""

import torch
import numpy as np

def run_sleep_staging(
    bedtime_start: float,  # Unix timestamp (seconds)
    bedtime_end: float,
    ibi_data: np.ndarray,  # (N, 4): [timestamp, ibi_ms, ?, validity]
    motion_data: np.ndarray,  # (N, 2): [timestamp, count]
    temp_data: np.ndarray,  # (N, 2): [timestamp, celsius]
    age: float,
    weight_kg: float,
    sex: float,  # Normalized -1 to 1
):
    """Run SleepNet inference."""

    model = torch.jit.load('sleepnet_1_0_0.pt', map_location='cpu')
    model.eval()

    # Convert to tensors
    bedtime = torch.tensor([bedtime_start, bedtime_end], dtype=torch.float64)
    ibi = torch.tensor(ibi_data, dtype=torch.float64)
    acm = torch.tensor(motion_data, dtype=torch.float64)
    temp = torch.tensor(temp_data, dtype=torch.float64)
    spo2 = torch.zeros((0, 2), dtype=torch.float64)  # Empty if not available
    scalars = torch.tensor([age, weight_kg, sex, 0.0, 0.0], dtype=torch.float64)
    tst = torch.tensor([0.0], dtype=torch.float64)

    with torch.no_grad():
        staging, apnea, spo2_out, metrics, debug = model(
            bedtime, ibi, acm, temp, spo2, scalars, tst
        )

    return {
        'sleep_stages': staging.numpy(),
        'apnea': apnea.numpy(),
        'spo2': spo2_out.numpy(),
        'metrics': metrics.numpy(),
    }
```

---

## Conclusion

**For 99% exact Oura implementation:**

1. **Use `sleepnet_1_0_0.pt`** - It's pure PyTorch, loads directly, and is the modern model
2. **Focus on data preprocessing** - This is where the remaining 1-15% gap exists
3. **Skip `sleepstaging_2_6_0.pt`** - Requires reverse engineering `libalgos.so` (not worth it)
4. **Test with real data** - Collect a night of data and compare to Oura app results

The model itself is 100% extractable and usable. The challenge is matching Oura's data pipeline exactly.
