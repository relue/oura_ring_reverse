# SpO2 Events

Blood oxygen saturation (SpO2) measurements and related data.

---

## Event Summary

| Tag | Hex | Event Name | Priority | Description |
|-----|-----|------------|----------|-------------|
| 111 | 0x6F | API_SPO2_EVENT | High | Blood oxygen saturation |
| 112 | 0x70 | API_SPO2_IBI_AND_AMPLITUDE_EVENT | High | SpO2 + IBI + amplitude |
| 119 | 0x77 | API_SPO2_COMBO_EVENT | High | Smoothed/filtered SpO2 |
| 120 | 0x78 | API_SPO2_DC_EVENT | Medium | SpO2 DC component |

---

## 0x6F - API_SPO2_EVENT (Primary)

**Source:** `com.ouraring.ringeventparser.message.Spo2Event`
**File:** `Spo2EventKt.java`
**Priority:** High - Blood oxygen saturation
**Frequency:** Periodic during sleep

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | beatOffset | int | Offset from beat |
| 3 | beatIndex | int | Index of the heartbeat |
| 4 | spo2Value | int | SpO2 percentage (0-100) |
| 5 | quality | uint32 | Measurement quality |
| 6 | flags | uint32 | Status flags |

### Normal SpO2 Ranges

| Range | Status |
|-------|--------|
| 95-100% | Normal |
| 90-94% | Low (may indicate issues) |
| < 90% | Very low (consult doctor) |

---

## 0x70 - API_SPO2_IBI_AND_AMPLITUDE_EVENT

**Priority:** High - SpO2 combined with IBI data

SpO2 measurement combined with IBI data from red/IR LEDs. Provides both blood oxygen and heart rate data in single event.

### LED Usage for SpO2

SpO2 is calculated using the ratio of red to infrared light absorption:

```
R = (AC_red / DC_red) / (AC_ir / DC_ir)
SpO2 = 110 - 25 * R  (approximate formula)
```

---

## 0x77 - API_SPO2_COMBO_EVENT (Smoothed)

**Priority:** High - Filtered SpO2 values

Contains smoothed/processed SpO2 values for better accuracy. Applies filtering to reduce noise and motion artifacts.

---

## 0x78 - API_SPO2_DC_EVENT

**Priority:** Medium - DC component data

SpO2 DC component values used in ratio calculation. DC represents the baseline (non-pulsatile) component of the PPG signal.

---

## SpO2 Measurement Process

```
1. Red and IR LEDs illuminate finger tissue
2. Photodetector measures reflected light
3. AC component (pulsatile) extracted from signal
4. DC component (baseline) extracted
5. Red/IR ratio calculated
6. SpO2 derived from calibration curve
7. Quality score assigned based on signal quality
```

---

## SpO2 Drop Detection

The app detects oxygen desaturation events (SpO2 drops):

### SpO2Drop Structure (from DATA_STRUCTURES.md)

| Field | Type | Description |
|-------|------|-------------|
| startTimeMillis | long | Drop start time |
| lowestTimeMillis | long | Time of lowest value |
| riseRate | float | Recovery rate |
| dropRate | float | Desaturation rate |
| duration | int | Duration (seconds) |
| depth | int | Depth (% points) |
| avgTemp | float | Temperature during drop |
| meanMotion | float | Motion during drop |
| medianPi | float | Perfusion index |
| dropProbability | float | ML probability |
| drop | boolean | Is valid drop? |

**Source:** `ecorelibrary/info/SpO2Drop.java`

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.message.Spo2Event`
- `com.ouraring.ringeventparser.Spo2EventKt`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ringeventparser/
│   ├── Spo2EventKt.java
│   └── message/
│       └── Spo2Event.java
└── ecorelibrary/
    └── info/
        ├── SpO2Info.java
        └── SpO2Drop.java
```

**Related:**
- `ecorelibrary/info/SpO2Info.java` - SpO2 output structure
- `ecorelibrary/info/SpO2Drop.java` - Drop event structure (20 fields)

---

## See Also

- [Data Structures](../structures/vitals.md) - SpO2Info, SpO2Drop structures
- [Heart Events](heart.md) - IBI data combined with SpO2
