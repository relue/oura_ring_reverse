# OURA RING DATA REPORT
================================================================================
**Generated:** 2026-01-14 14:49:31
**Source:** input_data/ring_data.pb
**Size:** 66,262,720 bytes (66 MB)

## EXECUTIVE SUMMARY

| Metric                    | Value          |
|---------------------------|----------------|
| IBI (Heart Rate) Samples  |        493,272 |
| Green IBI Quality Samples |        183,215 |
| Sleep Period Samples      |         16,647 |
| Temperature Samples       |         42,899 |
| HRV 5-min Samples         |          1,690 |
| Motion Events             |         27,329 |
| Activity Info Events      |          2,126 |
| Bedtime Periods           |             13 |
| Measurement Quality       |         86,760 |
| Debug Events              |        235,796 |
| Total Raw Events          |        733,882 |

### Data Time Range
- **First:** 2026-01-12 00:08:18
- **Last:** 2026-01-14 09:17:24
- **Duration:** 57.2 hours (2.4 days)


---
## DETAILED DATA SECTIONS

### 1. IBI AND AMPLITUDE (Heart Rate)

| Field | Value |
|-------|-------|
| Samples | 493,272 |
| IBI Range | 322 - 2000 ms |
| Heart Rate Range | 30 - 186 BPM |
| Average Heart Rate | 60.6 BPM |
| Median Heart Rate | 58.8 BPM |
| Amplitude Range | 0 - 16256 |

### 2. GREEN IBI QUALITY (Daytime HR)

| Field | Value |
|-------|-------|
| Samples | 183,215 |
| IBI Range | 339 - 2000 ms |
| Validity Distribution | {0: 2207, 1: 90974, 2: 69763, 3: 20271} |
| Quality Range | 0 - 7 |

### 3. SLEEP PERIOD INFO

| Field | Value |
|-------|-------|
| Samples | 16,647 |
| Average HR Range | 51.0 - 87.0 (raw units) |
| Breathing Rate Range | 8.0 - 20.375 (raw units) |
| Sleep State 0 (awake) | 5,724 samples |
| Sleep State 1 (asleep) | 10,923 samples |
| Motion Count Range | 0 - 57 |

### 4. HRV EVENT (5-minute windows)

| Field | Value |
|-------|-------|
| Samples | 1,690 |
| RMSSD Range | 0 - 40 (raw units) |
| Average RMSSD | 20.9 (raw units) |
| HR 5min Range | 0 - 67 (raw units) |

### 5. TEMPERATURE DATA

#### Sleep Temperature
| Field | Value |
|-------|-------|
| Samples | 16,723 |
| Raw Value Range | 33.59000015258789 - 36.13999938964844 |
| Average | 35.2 |

#### Multi-Sensor Temperature
- **Temp1:** 42,899 samples, range 15.979999542236328 - 36.130001068115234
- **Temp2:** 42,899 samples, range 15.5 - 38.0
- **Temp3:** 42,899 samples, range 11.420000076293945 - 31.68000030517578
- **Temp4:** 42,899 samples, range nan - nan
- **Temp5:** 42,899 samples, range nan - nan
- **Temp6:** 42,899 samples, range nan - nan
- **Temp7:** 42,899 samples, range nan - nan

### 6. MOTION EVENTS

| Field | Value |
|-------|-------|
| Samples | 27,329 |
| Motion Seconds Range | 0 - 29 |
| Low Intensity Range | 0 - 31 |
| High Intensity Range | 0 - 30 |

**Orientation Distribution:**
- Orientation 4: 13,097 (47.9%)
- Orientation 3: 8,531 (31.2%)
- Orientation 1: 3,230 (11.8%)
- Orientation 2: 2,471 (9.0%)

### 7. ACTIVITY INFO

| Field | Value |
|-------|-------|
| Samples | 2,126 |
| Steps per Sample Range | 0 - 238 |
| **Total Steps** | **125,797** |

**MET Level Distribution:**
- MET Level 1: 4,910.399993419647 total

### 8. BEDTIME PERIODS

**Total Period Records:** 13
**Unique Periods:** 2

| # | Start | End | Duration |
|---|-------|-----|----------|
| 1 | 2026-01-12 00:01:12 | 2026-01-12 09:09:12 | 9.1h |
| 2 | 2026-01-14 00:11:26 | 2026-01-14 09:18:31 | 9.1h |

### 9. MEASUREMENT QUALITY

| Field | Value |
|-------|-------|
| Samples | 86,760 |
| CQI (Contact Quality) Range | -317 - 24 |
| PQI (PPG Quality) Range | 0 - 0 |

### 10. BATTERY INFO

| Field | Value |
|-------|-------|
| Samples | 5,997 |
| Battery Level Range | 85 - 100% |
| Voltage Range | 0 - 4181 mV |
| In Charger Events | 477 |

### 11. RING HARDWARE INFO

| Field | Value |
|-------|-------|
| Firmware Version | 2.7.6 |
| Ring Type | 6 (Gen 4) |
| Hardware Version | 39 |
| Ring Size | 10 |

### 12. BLE CONNECTION INFO

| Field | Value |
|-------|-------|
| Connection Events | 4,095 |
| Disconnection Events | 4,027 |
| Total TX Bytes | 243,296,352 |
| Total RX Bytes | 459,410 |

### 13. WEAR EVENTS

| Field | Value |
|-------|-------|
| Total Events | 1,223 |
| State Distribution | {3: 613, 1: 311, 8: 299} |

**Sample Wear Texts:**
- `b'22150'`
- `b'1560'`
- `b'1057'`
- `b'398'`
- `b'1401'`

### 14. STATE CHANGE EVENTS

| Field | Value |
|-------|-------|
| Total Events | 17,869 |

**State Distribution:**
- State 1: 3,926
- State 5: 3,472
- State 8: 3,142
- State 3: 3,111
- State 2: 1,342
- State 30: 1,278
- State 6: 1,198
- State 4: 400

### 15. MOTION PERIOD (30-second intervals)

| Field | Value |
|-------|-------|
| Period Events | 42,115 |
| Event Types | {0: 42115} |

### 16. PPG SCAN EVENTS

| Field | Value |
|-------|-------|
| Scan Starts | 1,529 |
| Scan Ends | 1,527 |
| Success Codes | {7: 124, 0: 1302, 3: 53, 5: 48} |

### 17. DEBUG/DIAGNOSTIC EVENTS SUMMARY

| Event Type | Count |
|------------|-------|
| Debug Messages | 235,796 |
| BLE Usage Stats | 17,939 |
| Sleep Statistics | 32,761 |
| Flash Usage | 17,939 |
| Fuel Gauge Stats | 13,314 |
| AFE Statistics | 14,822 |
| ACM Config Changes | 15,975 |
| PPG Quality Stats | 8,066 |
| AFE PPG Settings | 35,440 |
| Self-Test Events | 11,196 |

---

## ALL EVENT TYPES (COMPLETE LIST)

| Event Type | Count |
|------------|-------|
| ibi_and_amplitude_event | 493,272 |
| debug_event_ind | 235,796 |
| green_ibi_quality_event | 183,215 |
| meas_quality_event | 86,760 |
| temp_event | 42,899 |
| motion_period | 42,115 |
| debug_data_open_afe_ppg_settings_data | 35,440 |
| debug_data_sleep_statistics | 32,761 |
| motion_event | 27,329 |
| state_change_ind | 17,869 |
| debug_data_ble_usage_statistics | 17,939 |
| debug_data_flash_usage_statistics | 17,939 |
| debug_data_period_info_statistics | 17,938 |
| sleep_period_info | 16,647 |
| sleep_acm_period | 16,736 |
| sleep_temp_event | 16,723 |
| debug_data_acm_configuration_changed | 15,975 |
| debug_data_afe_statistics_values | 14,822 |
| debug_data_fuel_gauge_statistics | 13,314 |
| selftest_data_event | 11,196 |
| debug_data_ppg_signal_quality_stats | 8,066 |
| debug_data_hardware_test_pin_adc_check_data | 7,840 |
| debug_data_battery_level_changed | 5,997 |
| feature_session | 4,872 |
| ble_connection_ind_connected_extended | 4,095 |
| ble_connection_ind_disconnected_extended | 4,027 |
| ble_connection_ind_disconnected_extended2 | 4,027 |
| ble_connection_ind_disconnected_extended_link_quality | 4,027 |
| debug_data_fuel_gauge_logging_registers | 3,618 |
| activity_info_event | 2,126 |
| debug_data_charger_firmware_and_psn | 1,988 |
| hrv_event | 1,690 |
| scan_start | 1,529 |
| scan_end | 1,527 |
| debug_data_charging_end_statistics | 1,405 |
| debug_data_charging_end_statistics_continued | 1,405 |
| debug_data_field_test_information2 | 1,278 |
| debug_data_field_test_information3 | 1,278 |
| debug_data_hardware_test_start_values | 1,278 |
| wear_event | 1,223 |
| debug_data_hardware_test_result_values | 1,214 |
| debug_data_stack_usage_statistics | 1,015 |
| ring_start_ind | 1,012 |
| debug_data_ring_hw_information | 1,012 |
| debug_data_hardware_test_adjacent_pin_adc_check_data | 980 |
| debug_data_fuel_gauge_register_dump | 976 |
| temp_period | 921 |
| debug_data_event_sync_statistics | 860 |
| debug_data_event_sync_cache_statistics | 860 |
| debug_data_security_failure | 655 |
| debug_data_finger_detection | 385 |
| debug_data_ble_pairing_completed | 332 |
| debug_data_legacy_security_failure | 332 |
| time_sync_ind | 241 |
| debug_data_field_test_information1 | 134 |
| debug_data_field_test_information4 | 134 |
| debug_data_hardware_test_battery_dcir_test_data1 | 70 |
| debug_data_hardware_test_battery_dcir_test_data2 | 70 |
| alert_event | 17 |
| bedtime_period | 13 |
| debug_data_bond_information_removed | 1 |

---

## RAW EVENTS CONTAINER

The `events` field contains **733,882** raw event records.

---

## EXCEPTION LOG

```
Exception: Error parsing api_debug_data: No state available for AfeStatisticsValues event Part I!
 count: 1 first 0 last 0
Exception: Error parsing api_green_ibi_quality_event: No DHR measurement ongoing.
 count: 5782 first 0 last 0
Exception: Error parsing api_selftest_data_event: Invalid temp_crosscheck 2nd part length.
 count: 985 first 0 last 0
Exception: Error parsing api_selftest_data_event: Invalid selftest ID in selftest data subtype.
 count: 4823 first 0 last 0
```

---
*End of Report*
