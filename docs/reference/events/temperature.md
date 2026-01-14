# Temperature Events

7-sensor temperature data from the Oura Ring.

---

## Event Summary

| Tag | Hex | Event Name | Priority | Description |
|-----|-----|------------|----------|-------------|
| 70 | 0x46 | API_TEMP_EVENT | High | Temperature (7 sensors) |
| 92 | 0x5C | API_SLEEP_TEMP_EVENT | Medium | Temperature during sleep |
| 97 | 0x61 | API_TEMP_PERIOD_EVENT | Medium | Temperature period summary |
| 117 | 0x75 | API_TEMP_EVENT_2 | Medium | Extended temperature data |

---

## 0x46 - API_TEMP_EVENT (Primary)

**Source:** `com.ouraring.ringeventparser.TempEventKt`
**File:** `TempValue.java:5-13`
**Priority:** High - Continuous temperature
**Frequency:** Continuous during wear

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Timestamps (ms) |
| 2 | temp1 | repeated float | Temperature sensor 1 (C) |
| 3 | temp2 | repeated float | Temperature sensor 2 (C) |
| 4 | temp3 | repeated float | Temperature sensor 3 (C) |
| 5 | temp4 | repeated float | Temperature sensor 4 (C) |
| 6 | temp5 | repeated float | Temperature sensor 5 (C) |
| 7 | temp6 | repeated float | Temperature sensor 6 (C) |
| 8 | temp7 | repeated float | Temperature sensor 7 (C) |

**Note:** Ring has 7 temperature sensors for accurate skin temperature measurement.

### Binary Format (13 bytes total)

```
Offset  Size  Field              Scaling
------  ----  -----              -------
0       1     Event ID (0x46)    -
1       1     Length             -
2       1     Format marker      0x0A
3-4     2     Timestamp/counter  uint16 LE
5-6     2     (reserved)         -
7-8     2     Temp sensor 1      / 100.0 (C)
9-10    2     Reference temp     / 100.0 (~32C)
11-12   2     Temp sensor 2      / 100.0 (C)
```

### Temperature Sensor Mapping (Daytime)

| Sensor | Typical Value | Description |
|--------|---------------|-------------|
| Temp1 | ~30C | Body-side sensor |
| Temp2 | ~31C | Reference sensor |
| Temp3 | ~26C | Ambient/external |
| Temp4-7 | Varies | Additional sensors |

### Live Capture Data

- **Initial capture:** 36 events verified
- **Sample values:** 30.05C, 31.00C, 25.71C (body, reference, ambient)
- **Overnight capture:** 314 events

---

## 0x5C - API_SLEEP_TEMP_EVENT

**Priority:** Medium - Sleep-specific temperature
**Frequency:** During detected sleep periods

### Temperature During Sleep

All 7 sensors typically read ~35C during sleep (finger skin temperature is higher due to reduced blood flow variation when resting).

---

## 0x75 - API_TEMP_EVENT_2 (Sleep Temperature)

**Priority:** Medium - Extended sleep temperature
**Format:** Custom binary (20 bytes total)

### Binary Format

```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     tag                0x75
1       1     len                18
2-5     4     timestamp          deciseconds LE
6-7     2     temp1              ~35C (body)
8-9     2     temp2              ~35C
...                              (7 temperature sensors total)
```

### Live Capture Data

69 events captured during overnight sleep. Higher precision temperature for sleep tracking.

---

## 0x61 - API_TEMP_PERIOD_EVENT

**Priority:** Medium - Temperature period summary

Aggregated temperature data over a time period.

### Live Capture Data

- **Initial capture:** 1 event with 30.08C average
- **Overnight capture:** 6 events

---

## Temperature Scaling

| Storage | Actual Value |
|---------|--------------|
| `*Centidegrees` | ÷ 100 (e.g., 3700 = 37.00°C) |
| uint16 raw | ÷ 100.0 |

---

## Temperature Baseline

Temperature deviation from baseline is used in Readiness score calculation:

| Field | Description |
|-------|-------------|
| `temperatureAverage` | Rolling average (centidegrees) |
| `temperatureDeviation` | Standard deviation |
| `highestTempCentidegrees` | Highest nightly temp |

**Source:** `ecorelibrary/baseline/Baseline.java`

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.TempEventKt`
- `com.ouraring.ringeventparser.message.TempValue`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ringeventparser/
│   ├── TempEventKt.java
│   └── message/
│       └── TempValue.java
└── ecorelibrary/
    └── baseline/Baseline.java
```

**Related:**
- `ecorelibrary/baseline/Baseline.java` - Temperature baseline calculations

---

## Open Questions

- [ ] Exact temperature sensor placement (which sensor is where on ring?)
- [ ] Temperature baseline calculation method details
- [ ] Relationship between 7 sensors and final temperature reading

---

## See Also

- [Sleep Events](sleep.md) - Sleep temperature events (0x5C)
- [Data Structures](../structures/vitals.md) - Baseline temperature fields
