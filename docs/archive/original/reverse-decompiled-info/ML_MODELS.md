# ML Models Reference

Quick reference for all PyTorch models in the Oura Ring app.

---

## Model Inventory (27 Models)

| Model | Version | File | Size | Purpose |
|-------|---------|------|------|---------|
| SLEEPNET | 1.0.0 | sleepnet_1_0_0.pt.enc | 4.6 MB | Ring 3 sleep staging |
| SLEEPNET_MOONSTONE | 1.1.0 | sleepnet_moonstone_1_1_0.pt.enc | 4.6 MB | Ring 4 sleep staging |
| SLEEPNET_BDI | 0.2.2 | sleepnet_bdi_0_2_2.pt.enc | 1.4 MB | Sleep breathing disturbance |
| SLEEP_STAGING | 2.5.3 | sleepstaging_2_5_3.pt.enc | 107 KB | Legacy sleep staging |
| SLEEP_STAGING_32BIT | 2.6.0 | sleepstaging_2_6_0.pt.enc | 114 KB | 32-bit sleep staging |
| WHR | 2.6.0 | whr_2_6_0.pt.enc | 4.2 MB | Workout HR v2 |
| WHR3 | 3.1.2 | whr_3_1_2.pt.enc | 4.2 MB | Workout HR v3 |
| CVA | 1.2.2 | cva_1_2_2.pt.enc | 1.4 MB | Cardiovascular age v1 |
| CVA2 | 2.0.3 | cva_2_0_3.pt.enc | 7.5 MB | Cardiovascular age v2 |
| CVA_CALIBRATOR | 1.2.3 | cva_calibrator_1_2_3.pt.enc | 16 KB | CVA calibration |
| STRESS_RESILIENCE | 2.1.4 | stress_resilience_2_1_4.pt.enc | 43 KB | Stress & resilience |
| DAYTIME_STRESS | 1.0.4 | stress_daytime_sensing_1_0_4.pt.enc | 11 KB | Daytime stress levels |
| CUMULATIVE_STRESS | 0.1.1 | cumulative_stress_0_1_1.pt.enc | 55 KB | 31-day cumulative stress |
| ILLNESS_DETECTION | 0.4.1 | illness_detection_0_4_1.pt.enc | 707 KB | Symptom radar |
| STEP_COUNTER | 1.2.0 | step_counter_1_2_0.pt.enc | 128 KB | Step counting |
| STEPS_MOTION_DECODER | 1.0.0 | steps_motion_decoder_1_0_0.pt.enc | 18 KB | Motion decoding |
| HALITE | 1.1.0 | halite_1_1_0.pt.enc | 4.0 MB | Hypertension detection |
| POPSICLE | 1.5.4 | popsicle_1_5_4.pt.enc | 1.2 MB | Unknown feature |
| DHRV_IMPUTATION | 1.0.3 | dhrv_imputation_1_0_3.pt.enc | 41 KB | Daytime HRV imputation |
| AWHR_IMPUTATION | 1.1.0 | awhr_imputation_1_1_0.pt.enc | 890 KB | Activity HR imputation |
| AWHR_PROFILE_SELECTOR | 0.0.1 | awhr_profile_selector_0_0_1.pt.enc | 117 KB | AWHR profile selection |
| ENERGY_EXPENDITURE | 0.0.10 | energy_expenditure_0_0_10.pt.enc | 1.4 MB | Calorie estimation |
| AUTOMATIC_ACTIVITY | 3.0.8 | automatic_activity_detection_3_0_8.pt.enc | 5.7 MB | Auto activity detection |
| DAILY_MEDIANS | 1.0.2 | daily_medians_1_0_2.pt.enc | 9 KB | Daily median baselines |
| SHORT_TERM_BASELINES | 1.0.1 | daily_short_term_baselines_1_0_1.pt.enc | 10 KB | Short-term baselines |
| MEAL_TIMING | 0.0.5 | meal_timing_0_0_5.pt.enc | 14 KB | Meal timing detection |
| PREGNANCY_BIOMETRICS | 0.4.0 | pregnancy_biometrics_0_4_0.pt.enc | 43 KB | Pregnancy tracking |

**Source:** `pytorch/PyTorchModelType.java:21-221`

---

## Model Encryption

All models are encrypted with AES-GCM.

### Encryption Scheme

```
File Format:
[12-byte IV] [encrypted data + 128-bit auth tag]

Decryption:
cipher = AES/GCM/NoPadding
iv = first 12 bytes
ciphertext = remaining bytes
tag_length = 128 bits
```

### Key Retrieval Flow

```
1. EncryptionKeyHandler.getKey(label)
   └─> Check local storage for key

2. If missing:
   KeyDeliveryModel.downloadKeys()
   └─> KeyDeliveryService API call
   └─> Save key with label

3. Fallback:
   Secrets.getfallbackKey(packageName)
   └─> Native call to libsecrets.so
```

### Current Key Label

```java
CURRENT_KEY_LABEL = "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0"
```

**Source:** `pytorch/PytorchModelFactory.java:37-68`

---

## Model Loading

### PytorchModelFactory

```java
// Decryption steps
1. Read IV (12 bytes) from encrypted file
2. Read remaining ciphertext
3. Get key from EncryptionKeyHandler
4. Decrypt with AES-GCM (128-bit tag)
5. Write to temp file
6. Load with PyTorch Module.load()
```

### Loading Sequence

```
PytorchModelFactory.getModel(type)
  └─> decryptToTempFile(type.filename, key)
  └─> Module.load(tempPath)
  └─> Create *PytorchModel wrapper
  └─> Delete temp file
```

**Source:** `pytorch/PytorchModelFactory.java`

---

## Model Input/Output Details

### SleepNet (Ring 3/4 Sleep Staging)

Complex sleep staging model with multiple tensor inputs.

**Wrapper:** `SleepNetPytorchModel`
**Input Class:** `com.ouraring.oura.sleep.sleepnet.model.b` (obfuscated)
**Output Class:** `com.ouraring.oura.sleep.sleepnet.model.l` (obfuscated)

**Note:** Execute method too complex for decompiler (3522 instructions).

### SleepNet BDI (Breathing Disturbance Index)

**Wrapper:** `SleepNetBdiPyTorchModel`

**Inputs:**
| Name | Type | Description |
|------|------|-------------|
| timestamps | double[2] | Start/end in seconds (÷1000) |
| ibi_data | List<double[4]> | IBI, amplitude, quality, duration |

**Outputs:** Breathing disturbance metrics

**Source:** `oura/sleep/bdi/model/SleepNetBdiPyTorchModel.java:124-135`

---

### Cardiovascular Age (CVA)

**Wrapper:** `CardiovascularAgePytorchModel`

**Constants:**
```java
DEMOGRAPHICS_SIZE = 4      // age, weight, height, sex?
PPG_SEGMENT_METRICS_SIZE = 11  // metrics per PPG segment
```

**Inputs:**
| Tensor | Shape | Description |
|--------|-------|-------------|
| ppg_segments | [N, segment_len] | PPG waveform segments |
| metrics_1 | [len] | Unknown |
| metrics_2 | [len] | Unknown |
| demographics | [1, 4] | User demographics |

**Outputs:** 5 tensors including segment metrics (chunked by 11)

**Source:** `oura/hearthealth/cardiovascularage/algo/CardiovascularAgePytorchModel.java:22-73`

---

### Daytime HRV Imputation

**Wrapper:** `DHrvImputationPytorchModel`

**Inputs (10 arrays):**
| Name | Annotation | Description |
|------|------------|-------------|
| skinTemperature | `skin_temperature` | Skin temp readings |
| ringMet | `ring_met` | Ring MET values |
| met | `met` | Activity MET |
| hr | `hr` | Heart rate |
| timestamp | `timestamp` | Timestamps |
| bedtimeStart | `bedtime_start` | Sleep start times |
| bedtimeEnd | `bedtime_end` | Sleep end times |
| dhrvBaseline | `dhrv_baseline` | HRV baseline |
| hrBaseline | `hr_baseline` | HR baseline |
| temperatureBaseline | `temperature_baseline` | Temp baseline |

**Output:** Single `dhrv` value (double)

**Source:** `oura/model/hrv/imputation/DHrvImputationPytorchModel.java:21-184`

---

### Stress & Resilience

**Wrapper:** `StressResiliencePytorchModel`

**Inputs:** 15 double arrays (obfuscated names a-o)

**Outputs:** 13 scalar values
- tuple[0-12]: Individual stress/resilience metrics

**Source:** `oura/resilience/model/pytorch/StressResiliencePytorchModel.java:29-38`

---

### Daytime Stress

**Wrapper:** `DaytimeStressPytorchModel`

**Inputs:** 7 double arrays (obfuscated)

**Outputs:** 8 scalar values (reordered from tuple indices 0,5,2,7,1,6,4,3)

Categories: Stressed / Engaged / Relaxed / Restored

**Source:** `oura/stress/model/DaytimeStressPytorchModel.java:29-37`

---

### Symptom Radar (Illness Detection)

**Wrapper:** `SymptomRadarPytorchModel`

**Inputs:** 20 double arrays (obfuscated a-t)

**Outputs:**
| Index | Description |
|-------|-------------|
| tuple[0] | Primary metric |
| tuple[1] | Secondary metric |
| tuple[2-8] | 7 component arrays |
| tuple[9-15] | 7 additional arrays |
| tuple[16] | Final metric 1 |
| tuple[17] | Final metric 2 |

**Source:** `oura/symptomradar/model/pytorch/SymptomRadarPytorchModel.java:34-63`

---

## Model Categories

### Sleep Analysis
| Model | Purpose |
|-------|---------|
| SLEEPNET | Main sleep staging (Ring 3) |
| SLEEPNET_MOONSTONE | Main sleep staging (Ring 4) |
| SLEEPNET_BDI | Breathing disturbance index |
| SLEEP_STAGING | Legacy staging algorithm |

### Heart & Cardiovascular
| Model | Purpose |
|-------|---------|
| CVA / CVA2 | Cardiovascular age estimation |
| CVA_CALIBRATOR | CVA calibration |
| WHR / WHR3 | Workout heart rate |
| AWHR_IMPUTATION | Activity HR filling |
| DHRV_IMPUTATION | Daytime HRV estimation |
| HALITE | Hypertension detection |

### Stress & Wellness
| Model | Purpose |
|-------|---------|
| STRESS_RESILIENCE | Overall stress & resilience |
| DAYTIME_STRESS | Real-time stress levels |
| CUMULATIVE_STRESS | 31-day stress accumulation |
| ILLNESS_DETECTION | Symptom radar |

### Activity & Movement
| Model | Purpose |
|-------|---------|
| STEP_COUNTER | Step counting |
| STEPS_MOTION_DECODER | Motion classification |
| AUTOMATIC_ACTIVITY | Auto workout detection |
| ENERGY_EXPENDITURE | Calorie estimation |

### Baselines & Utilities
| Model | Purpose |
|-------|---------|
| DAILY_MEDIANS | Daily baseline medians |
| SHORT_TERM_BASELINES | Short-term baselines |
| MEAL_TIMING | Meal detection |
| PREGNANCY_BIOMETRICS | Pregnancy tracking |
| POPSICLE | Unknown |

---

## PyTorch Runtime

### Native Libraries

```
libtorch_cpu.so (70 MB) - PyTorch CPU runtime
```

### Execution Pattern

```java
// All models follow this pattern
IValue[] inputs = createInputTensors(data);
IValue forward = module.forward(inputs);
IValue[] outputs = forward.toTuple();
// Parse outputs to domain objects
```

### Tensor Helper

```java
// Common utility for creating IValue arrays
k.k(double[][] arrays) -> IValue[]
```

**Source:** `oura/sleep/nssa/model/k.java`

---

## Key Discovery Notes

### NSSA System
The `libnexusengine.so` (16.5 MB) contains an alternative sleep analysis system called NSSA (Nexus Sleep Staging Algorithm). It appears to be a native C++ implementation separate from PyTorch models.

### Model Versioning
Models follow semantic versioning. The app may support multiple versions simultaneously (e.g., CVA 1.2.2 and CVA 2.0.3) for A/B testing or gradual rollout.

### Input Preprocessing
Most models expect:
- Timestamps in seconds (not milliseconds) - divide by 1000
- Normalized/scaled values
- Baselines precomputed from historical data

---

## File References

| Class | Location |
|-------|----------|
| PyTorchModelType | `pytorch/PyTorchModelType.java` |
| PytorchModelFactory | `pytorch/PytorchModelFactory.java` |
| Secrets | `core/utils/Secrets.java` |
| EncryptionKeyHandler | `core/model/backend/EncryptionKeyHandler.java` |
| KeyDeliveryModel | `core/model/backend/KeyDeliveryModel.java` |
| SleepNetPytorchModel | `oura/sleep/sleepnet/model/SleepNetPytorchModel.java` |
| CardiovascularAgePytorchModel | `oura/hearthealth/cardiovascularage/algo/CardiovascularAgePytorchModel.java` |
| DHrvImputationPytorchModel | `oura/model/hrv/imputation/DHrvImputationPytorchModel.java` |

---

**See also:** [NATIVE_LIBRARIES.md](NATIVE_LIBRARIES.md), [DATA_STRUCTURES.md](DATA_STRUCTURES.md), [DATA_FLOW_DETAILED.md](DATA_FLOW_DETAILED.md)
