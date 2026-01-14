# SleepNet Models

Sleep staging PyTorch models for Ring 3 and Ring 4.

---

## Model Variants

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| SLEEPNET | 1.0.0 | 4.6 MB | Ring 3 sleep staging |
| SLEEPNET_MOONSTONE | 1.1.0 | 4.6 MB | Ring 4 sleep staging |
| SLEEPNET_BDI | 0.2.2 | 1.4 MB | Breathing disturbance index |

---

## SleepNetPytorchModel

Complex sleep staging model with multiple tensor inputs.

**Wrapper:** `SleepNetPytorchModel`
**Input Class:** `com.ouraring.oura.sleep.sleepnet.model.b` (obfuscated)
**Output Class:** `com.ouraring.oura.sleep.sleepnet.model.l` (obfuscated)

**Note:** Execute method too complex for decompiler (3522 instructions).

---

## SleepNet BDI (Breathing Disturbance Index)

**Wrapper:** `SleepNetBdiPyTorchModel`

### Inputs

| Name | Type | Description |
|------|------|-------------|
| timestamps | double[2] | Start/end in seconds (÷1000) |
| ibi_data | List<double[4]> | IBI, amplitude, quality, duration |

### Outputs

Breathing disturbance metrics.

**Source:** `oura/sleep/bdi/model/SleepNetBdiPyTorchModel.java:124-135`

---

## Sleep Staging Output

Sleep stages are classified per 5-minute epoch:

| Stage | Code | Description |
|-------|------|-------------|
| Awake | A | User is awake |
| Light | L | Light sleep (N1/N2) |
| Deep | D | Deep sleep / SWS (N3) |
| REM | R | REM sleep stage |

**Output format:** String per 5-minute epoch
```
"LLLLLDDDLLLRRRRLLLL"
```

---

## Input Preprocessing

Most models expect:
- Timestamps in seconds (not milliseconds) - divide by 1000
- Normalized/scaled values
- Baselines precomputed from historical data

---

## Source References

**Decompiled Classes:**
- `com.ouraring.oura.sleep.sleepnet.model.SleepNetPytorchModel`
- `com.ouraring.oura.sleep.bdi.model.SleepNetBdiPyTorchModel`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/oura/sleep/
├── sleepnet/model/SleepNetPytorchModel.java
└── bdi/model/SleepNetBdiPyTorchModel.java
```

**Model Files:**
```
_large_files/models/assets/
├── sleepnet_1_0_0.pt.enc
├── sleepnet_moonstone_1_1_0.pt.enc
└── sleepnet_bdi_0_2_2.pt.enc
```

---

## See Also

- [Sleep Events](../events/sleep.md) - Sleep event data
- [Sleep Structures](../structures/sleep.md) - SleepInfo output
