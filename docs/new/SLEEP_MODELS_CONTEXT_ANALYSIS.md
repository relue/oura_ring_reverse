# Sleep Staging Models: Architecture and Context Analysis

**Date:** 2026-01-12
**Source:** Decompiled Oura Android App

---

## Executive Summary

Oura uses **TWO parallel sleep analysis systems** that can run simultaneously:

| System | Model | Type | Purpose |
|--------|-------|------|---------|
| **NSSA** | `sleepstaging_2_6_0.pt` | Traditional ML | Legacy system, feature-based classification |
| **SleepNet** | `sleepnet_*.pt` | Deep Learning | Modern system, end-to-end neural network |

Feature flags (`PlatformNetworkExecutionTest`) control which system runs. Both can be enabled simultaneously for A/B testing.

---

## System 1: NSSA (Nexus Sleep Staging Algorithm)

### Model File
```
sleepstaging_2_6_0.pt (112 KB)
sleepstaging_2_5_3.pt (105 KB) - older version
```

### Architecture
```
┌─────────────────────────────────────────────────────────────────────┐
│                     NSSA Pipeline (Traditional ML)                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Raw Ring Data     Feature Extraction        Classification         │
│  ┌───────────┐    ┌──────────────────┐    ┌──────────────────┐     │
│  │ IBI       │───►│ 36+ HRV features │    │                  │     │
│  │ Accel     │───►│ Motion features  │───►│ oura_sleep_      │     │
│  │ Temp      │───►│ Temp features    │    │ classifier       │     │
│  └───────────┘    └──────────────────┘    │ (XGBoost/LightGBM)│     │
│                                           │ in libalgos.so   │     │
│                                           └────────┬─────────┘     │
│                                                    │               │
│                                                    ▼               │
│                                           Sleep Stages (1-4)       │
└─────────────────────────────────────────────────────────────────────┘
```

### Dependencies
- `libnexus_android.so` - Main processing engine
- `libalgos.so` (5.5 MB) - Contains custom operators
- `libtorch_cpu.so` - PyTorch Mobile

### Custom Operators (in `libalgos.so`)
```cpp
namespace nssaops {
    Tensor sleep_classifier(Tensor);      // XGBoost/LightGBM classifier
    Tensor create_windows(Tensor, double); // 30-second epoch windowing
    Tensor biquad_cascade(Tensor, Tensor); // IIR filter for HRV
    Tensor find_peaks(Tensor);            // R-peak detection
    Tensor find_indices(Tensor, Tensor);  // Index lookup
}
```

### Usage Context
From `NexusNative.java`:
```java
System.loadLibrary("nexus_android");

// Process ring events through Nexus engine
public native String processEventChunk(byte[] eventChunk);
public native int sendModelBytes(String modelName, byte[] modelBytes);
```

**NSSA runs via Nexus for:**
- Real-time sleep phase updates during sleep
- Legacy compatibility
- Backend comparison testing

---

## System 2: SleepNet (Deep Learning)

### Model Files
```
sleepnet_1_0_0.pt (4.5 MB)           - Standard Gen 3 model
sleepnet_moonstone_1_1_0.pt (4.5 MB) - Ring 4 (Moonstone) model
sleepnet_bdi_0_2_2.pt (1.4 MB)       - Sleep quality scoring
```

### Architecture
```
┌─────────────────────────────────────────────────────────────────────┐
│                   SleepNet Pipeline (Deep Learning)                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Raw Ring Data       Preprocessing        Neural Network            │
│  ┌───────────┐    ┌───────────────┐    ┌──────────────────┐        │
│  │ IBI (N,4) │───►│               │    │                  │        │
│  │ Accel(N,2)│───►│  PyTorch      │───►│  SE-Net CNN      │        │
│  │ Temp (N,2)│───►│  (in model)   │    │  1M+ parameters  │        │
│  │ SpO2(N,2) │───►│               │    │                  │        │
│  └───────────┘    └───────────────┘    └────────┬─────────┘        │
│                                                  │                  │
│  ┌───────────┐                                   │                  │
│  │ Demographics│─────────────────────────────────┘                  │
│  │ Bedtime    │                                                     │
│  └───────────┘                                                      │
│                                                                      │
│  Outputs:                                                            │
│  ├── staging_outputs: Sleep stages (30-sec epochs)                  │
│  ├── apnea_outputs: Sleep apnea indicators                          │
│  ├── spo2_outputs: SpO2 analysis                                    │
│  └── output_metrics: Sleep quality metrics                          │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Advantage: NO CUSTOM OPERATORS
```python
import torch
model = torch.jit.load('sleepnet_1_0_0.pt', map_location='cpu')
# SUCCESS - loads without any native libraries!
```

### Model Variants by Hardware

| Model | Hardware | Purpose |
|-------|----------|---------|
| `sleepnet_1_0_0.pt` | Oura Ring Gen 3 | Standard sleep analysis |
| `sleepnet_moonstone_1_1_0.pt` | Oura Ring 4 | Optimized for new sensors |
| `sleepnet_bdi_0_2_2.pt` | All rings | Sleep quality (BDI) scoring |

---

## Feature Flag Control

From `FeatureDefinitions.java`:

```java
public static final class PlatformNetworkExecutionTest {
    private final boolean enabled;
    private final boolean nssa;      // Enable NSSA system
    private final boolean sleepnet;  // Enable SleepNet system
}
```

### Possible Configurations

| enabled | nssa | sleepnet | Behavior |
|---------|------|----------|----------|
| true | true | false | NSSA only (legacy mode) |
| true | false | true | SleepNet only (modern mode) |
| true | true | true | Both systems (A/B testing) |
| false | * | * | Disabled |

---

## Processing Pipelines

### NSSA Pipeline (via Nexus)

```
SleepHandler
    └── NssaManager
        └── NexusNative.processEventChunk()
            └── libnexus_android.so
                └── libalgos.so (sleep_classifier)
                    └── sleepstaging_2_6_0.pt
```

Key files:
- `com/ouraring/oura/nssa/NssaManager*.java`
- `com/ouraring/oura/nssa/SleepHandler*.java`
- `com/ouraring/nexus/NexusNative.java`

### SleepNet Pipeline (Pure PyTorch)

```
SleepNetWorker
    └── SleepNetHandler.calculateSleepNet()
        └── SleepNetPytorchModel.forward()
            └── sleepnet_1_0_0.pt (or moonstone variant)
```

Key files:
- `com/ouraring/oura/sleep/sleepnet/work/SleepNetWorker.java`
- `com/ouraring/oura/sleep/sleepnet/SleepNetHandler.java`
- `com/ouraring/oura/sleep/sleepnet/model/SleepNetPytorchModel.java`

---

## Model Loading and Encryption

From `PyTorchModelType.java`:

```java
// All models are AES-256-GCM encrypted
private static final String CURRENT_KEY_LABEL = "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0";

// Model definitions
SLEEPNET: ("1.0.0", "sleepnet_1_0_0.pt.enc")
SLEEPNET_BDI: ("0.2.2", "sleepnet_bdi_0_2_2.pt.enc")
SLEEPNET_MOONSTONE: ("1.1.0", "sleepnet_moonstone_1_1_0.pt.enc")
SLEEPSTAGING: ("2.5.3", "sleepstaging_2_5_3.pt.enc")
// Plus SleepStaging32BitPytorchModel: ("2.6.0", "sleepstaging_2_6_0.pt.enc")
```

Decryption key location: `assets/secrets.json`
```json
{
  "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0": {
    "key": "kmElv6o7FUVdIB5/7+e1yrkIz27ojzfJ1CwZPTvTfpg="
  }
}
```

---

## Which Model to Use for Implementation?

### Recommendation: `sleepnet_1_0_0.pt`

| Factor | NSSA (sleepstaging) | SleepNet |
|--------|---------------------|----------|
| Loads without native libs | ❌ No | ✅ Yes |
| Self-contained | ❌ No | ✅ Yes |
| Modern architecture | ❌ Traditional ML | ✅ Deep Learning |
| Output detail | Basic stages | Stages + Apnea + SpO2 |
| Accuracy | Good | Better (1M+ params) |
| Difficulty to use | Hard | Easy |

### Quick Start with SleepNet

```python
import torch

# Load model
model = torch.jit.load('sleepnet_1_0_0.pt', map_location='cpu')
model.eval()

# Inputs (all float64):
# - bedtime_input: [start_sec, end_sec] - Unix timestamps
# - ibi_input: (N, 4) - [timestamp, ibi_ms, unknown, validity]
# - acm_input: (N, 2) - [timestamp, motion_count]
# - temp_input: (N, 2) - [timestamp, celsius]
# - spo2_input: (N, 2) - [timestamp, spo2%] or empty
# - scalars_input: (5,) - [age, weight_kg, sex, ?, ?]
# - tst_input: (1,) - total sleep time hint

# Run inference
staging, apnea, spo2, metrics, debug = model(
    bedtime, ibi, acm, temp, spo2, scalars, tst
)

# Output: staging is (num_epochs, 6)
# [timestamp, stage, prob_light, prob_deep, prob_rem, prob_awake]
```

---

## Data Flow in Oura App

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Oura App Data Flow                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Ring (BLE)                                                          │
│      │                                                               │
│      ▼                                                               │
│  Event Parser (libringeventparser.so)                               │
│      │                                                               │
│      ├──────────────────┬─────────────────────┐                     │
│      │                  │                     │                     │
│      ▼                  ▼                     ▼                     │
│  IBI Events (0x44)  Accel (0x47)    Sleep Period (0x6A)            │
│      │                  │                     │                     │
│      └──────────────────┴─────────────────────┘                     │
│                         │                                            │
│                         ▼                                            │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │            Feature Flag: PlatformNetworkExecutionTest    │        │
│  │                     nssa=? sleepnet=?                    │        │
│  └─────────────────────┬───────────────────────────────────┘        │
│                        │                                             │
│          ┌─────────────┴─────────────┐                              │
│          │                           │                              │
│          ▼                           ▼                              │
│  ┌───────────────┐          ┌───────────────┐                       │
│  │ NSSA          │          │ SleepNet      │                       │
│  │ (Nexus)       │          │ (PyTorch)     │                       │
│  │               │          │               │                       │
│  │ sleepstaging  │          │ sleepnet      │                       │
│  │ _2_6_0.pt     │          │ _1_0_0.pt     │                       │
│  └───────┬───────┘          └───────┬───────┘                       │
│          │                           │                              │
│          └─────────────┬─────────────┘                              │
│                        │                                             │
│                        ▼                                             │
│                Sleep Stages + Metrics                                │
│                        │                                             │
│                        ▼                                             │
│                  DbSleep (Realm DB)                                  │
│                        │                                             │
│                        ▼                                             │
│                   UI / Cloud                                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## References

### Source Files (Decompiled)
- `com/ouraring/pytorch/PyTorchModelType.java` - Model definitions
- `com/ouraring/nexus/NexusNative.java` - Native interface
- `com/ouraring/oura/sleep/sleepnet/work/SleepNetWorker.java` - SleepNet worker
- `com/ouraring/oura/nssa/` - NSSA implementation
- `com/ouraring/core/model/backend/FeatureDefinitions.java` - Feature flags

### Native Libraries
- `libalgos.so` - Custom operators (NSSA)
- `libnexus_android.so` - Nexus engine
- `libringeventparser.so` - Event parsing
- `libtorch_cpu.so` - PyTorch Mobile

### Model Files (Decrypted)
- `sleepstaging_2_6_0.pt` - NSSA classifier
- `sleepnet_1_0_0.pt` - SleepNet (Gen 3)
- `sleepnet_moonstone_1_1_0.pt` - SleepNet (Ring 4)
- `sleepnet_bdi_0_2_2.pt` - Sleep quality scoring
