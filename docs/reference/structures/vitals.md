# Vitals Data Structures

HR/HRV, SpO2, and temperature structures.

---

## IbiAndAmplitudeEvent

Raw IBI from ring vs corrected by native algorithm.

**Source:** `ecorelibrary/ibi/IbiAndAmplitudeEvent.java`

```java
// Raw from BLE (before correction)
IbiAndAmplitudeEvent.Raw {
    long timestamp          // Unix millis
    int ibi                 // Inter-beat interval (ms)
    int amplitude           // PPG signal amplitude
}

// After nativeIbiCorrection()
IbiAndAmplitudeEvent.Corrected {
    long timestamp
    int ibi
    int amplitude
    int validity            // 0-3 quality indicator
}
```

### Validity Values

| Value | Meaning |
|-------|---------|
| 0 | Invalid |
| 1 | Uncertain |
| 2 | Interpolated |
| 3 | Valid |

---

## HrHrvOutputInfo (14 fields)

Heart rate and HRV measurement output.

```java
HrHrvOutputInfo implements EcoreInfo {
    long timestampUtcSeconds
    int timeZoneMinutes
    int hr                          // Heart rate BPM
    int hrv                         // HRV (RMSSD) in ms
    int hrvScaled                   // Scaled HRV
    int sourceValue                 // LED source (enum)
    boolean restorative             // Is restorative time?
    int cqi                         // Contact quality index
    int pqi                         // PPG quality index
    int quality                     // Overall quality
    int hrvAccuracy                 // HRV accuracy (-1 = N/A)
    int measurementDurationMinutes
    int _ibiQuality                 // IBI quality (255 = N/A)
    HrHrvInputStatisticsInfo inputStatistics
}
```

---

## HrHrvOutputInfo.Source (8 values)

PPG LED source combinations.

| Value | Name | Description |
|-------|------|-------------|
| 0 | UNKNOWN | Unknown source |
| 1 | IR | Infrared LED |
| 2 | GREEN | Green LED |
| 3 | RED | Red LED |
| 4 | IR_AND_GREEN | IR + Green |
| 5 | IR_AND_RED | IR + Red |
| 6 | GREEN_AND_RED | Green + Red |
| 7 | IR_AND_GREEN_AND_RED | All three |

---

## SpO2Info (6 fields)

Blood oxygen measurement output.

```java
SpO2Info implements EcoreInfo {
    long timestampUtcMillis
    int timeZone
    int dataTypeEcoreValue      // SpO2EcoreDataType enum value
    int spo2AvgValue            // Average SpO2 %
    float spo2AvgQuality        // Quality score
    SpO2Drop drop               // Drop event details (optional)
}
```

---

## SpO2Drop (20 fields!)

Detailed SpO2 drop (desaturation) event.

**Source:** `ecorelibrary/info/SpO2Drop.java`

```java
SpO2Drop {
    // Timing
    long startTimeMillis
    long lowestTimeMillis

    // Drop characteristics
    float riseRate              // Recovery rate
    float dropRate              // Desaturation rate
    int duration                // Duration (seconds)
    int depth                   // Depth (% points)

    // Signal quality
    float dcDiffDropRate1, dcDiffDropRate2
    boolean peak

    // Context
    float avgTemp               // Temperature during drop
    float meanMotion            // Motion during drop
    float medianPi              // Perfusion index
    float dcCorr1, dcCorr2      // DC correlation

    // HR correlation
    float hrPeakPerc
    float pulseCount
    float hrDelta               // HR change during drop

    // Classification
    float dropThreshold
    float dropProbability       // ML probability
    boolean drop                // Is valid drop?
}
```

---

## PostProcessEventsResult

Result of event post-processing.

```java
PostProcessEventsResult {
    int ringTime        // Ring internal timestamp
    long utcTime        // UTC timestamp

    // Derived
    boolean timeMissing // True if both are 0
}
```

---

## DailyOutput

Simple daily scores output.

```java
DailyOutput {
    int sleepScore      // 0-100
    int readinessScore  // 0-100
}
```

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.ibi.IbiAndAmplitudeEvent`
- `com.ouraring.ecorelibrary.info.HrHrvOutputInfo`
- `com.ouraring.ecorelibrary.info.SpO2Info`
- `com.ouraring.ecorelibrary.info.SpO2Drop`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── ibi/IbiAndAmplitudeEvent.java
└── info/
    ├── HrHrvOutputInfo.java
    ├── SpO2Info.java
    └── SpO2Drop.java
```

---

## See Also

- [Heart Events](../events/heart.md) - IBI event sources
- [SpO2 Events](../events/spo2.md) - SpO2 event sources
