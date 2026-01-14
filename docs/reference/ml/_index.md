# ML Models Reference

Documentation for all 27 PyTorch models in the Oura Ring app.

---

## Quick Navigation

| Topic | Doc | Description |
|-------|-----|-------------|
| Encryption | [encryption.md](encryption.md) | AES-GCM decryption process |
| SleepNet | [sleepnet.md](sleepnet.md) | Sleep staging model details |

---

## Model Inventory (27 Models)

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| SLEEPNET | 1.0.0 | 4.6 MB | Ring 3 sleep staging |
| SLEEPNET_MOONSTONE | 1.1.0 | 4.6 MB | Ring 4 sleep staging |
| SLEEPNET_BDI | 0.2.2 | 1.4 MB | Sleep breathing disturbance |
| SLEEP_STAGING | 2.5.3 | 107 KB | Legacy sleep staging |
| SLEEP_STAGING_32BIT | 2.6.0 | 114 KB | 32-bit sleep staging |
| WHR | 2.6.0 | 4.2 MB | Workout HR v2 |
| WHR3 | 3.1.2 | 4.2 MB | Workout HR v3 |
| CVA | 1.2.2 | 1.4 MB | Cardiovascular age v1 |
| CVA2 | 2.0.3 | 7.5 MB | Cardiovascular age v2 |
| CVA_CALIBRATOR | 1.2.3 | 16 KB | CVA calibration |
| STRESS_RESILIENCE | 2.1.4 | 43 KB | Stress & resilience |
| DAYTIME_STRESS | 1.0.4 | 11 KB | Daytime stress levels |
| CUMULATIVE_STRESS | 0.1.1 | 55 KB | 31-day cumulative stress |
| ILLNESS_DETECTION | 0.4.1 | 707 KB | Symptom radar |
| STEP_COUNTER | 1.2.0 | 128 KB | Step counting |
| STEPS_MOTION_DECODER | 1.0.0 | 18 KB | Motion decoding |
| HALITE | 1.1.0 | 4.0 MB | Hypertension detection |
| POPSICLE | 1.5.4 | 1.2 MB | Unknown feature |
| DHRV_IMPUTATION | 1.0.3 | 41 KB | Daytime HRV imputation |
| AWHR_IMPUTATION | 1.1.0 | 890 KB | Activity HR imputation |
| AWHR_PROFILE_SELECTOR | 0.0.1 | 117 KB | AWHR profile selection |
| ENERGY_EXPENDITURE | 0.0.10 | 1.4 MB | Calorie estimation |
| AUTOMATIC_ACTIVITY | 3.0.8 | 5.7 MB | Auto activity detection |
| DAILY_MEDIANS | 1.0.2 | 9 KB | Daily median baselines |
| SHORT_TERM_BASELINES | 1.0.1 | 10 KB | Short-term baselines |
| MEAL_TIMING | 0.0.5 | 14 KB | Meal timing detection |
| PREGNANCY_BIOMETRICS | 0.4.0 | 43 KB | Pregnancy tracking |

**Source:** `pytorch/PyTorchModelType.java:21-221`

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

### Native Library

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

---

## Source References

**Decompiled Classes:**
- `com.ouraring.pytorch.PyTorchModelType`
- `com.ouraring.pytorch.PytorchModelFactory`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── pytorch/
│   ├── PyTorchModelType.java
│   └── PytorchModelFactory.java
└── oura/
    ├── sleep/sleepnet/model/SleepNetPytorchModel.java
    ├── hearthealth/cardiovascularage/algo/CardiovascularAgePytorchModel.java
    └── model/hrv/imputation/DHrvImputationPytorchModel.java
```

**Model Files:**
```
_large_files/models/assets/
├── sleepnet_1_0_0.pt.enc
├── sleepnet_moonstone_1_1_0.pt.enc
├── cva_2_0_3.pt.enc
└── ... (27 encrypted models)
```

---

## See Also

- [Native Libraries](../native/_index.md) - PyTorch runtime
- [Encryption](encryption.md) - Model decryption
