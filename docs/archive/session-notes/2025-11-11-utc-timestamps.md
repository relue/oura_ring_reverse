# Session 2025-11-11: UTC Timestamp Implementation for Sleep Events

## Summary
Implemented complete UTC timestamp calculation for Oura Ring sleep events (0x6A) using TIME_SYNC protocol. Fixed critical bug where ring timestamps were incorrectly converted from deciseconds to seconds.

## Key Achievements

### 1. TIME_SYNC Protocol Implementation
- **Request (0x12)**: Sends 8 bytes UTC time (LE) + 1 byte timezone (30-min units)
- **Response (0x13)**: Receives ring time in **deciseconds** (not seconds!)
- Created "Sync Time" button that stores sync point persistently in SharedPreferences
- Ring has NO real-time clock - uses monotonic decisecond counter from boot/reset

### 2. UTC Calculation Formula
```kotlin
// Ring time is in DECISECONDS (0.1 second units)
val timeDiffDeciseconds = syncRingTimeDeciseconds - eventRingTimeDeciseconds
val eventUtcMillis = syncUtcTimeMillis - (timeDiffDeciseconds * 100)
```

### 3. Critical Bug Fix: Decisecond Units
**Problem**: Initially treated ring timestamps as seconds and multiplied by 10
- Event timestamp: 136559 (raw value from bytes 2-5)
- Incorrect: `136559 * 10 = 1,365,590` deciseconds (wrong!)
- Correct: `136559` deciseconds = 13655.9 seconds ✓

**Discovery Method**: Analyzed two TIME_SYNC responses 5min 26sec apart:
- Difference: 3252 units / 326 seconds = ~10x ratio
- Conclusion: Ring time is in deciseconds!

### 4. Data Browser Updates
- Event 0x6A now displays: `UTC Timestamp: 11.11.2025 19:41`
- Shows both deciseconds and seconds: `136559 decisec (13655.9 sec since ring boot)`
- TIME_SYNC data persists across app restarts (like auth key)

### 5. UI Improvements
- Reorganized buttons into 3 rows (max 4 buttons per row)
- Row 1: Connect, Auth, SyncTime, SetAuth
- Row 2: GetData, GetSleep, StartHB, StopHB
- Row 3: ShowData, Clear, FactoryReset

### 6. Event Collection
- Changed from 1 event to 20 events of type 0x6A (SLEEP_PERIOD_INFO_2)
- Events display newest first in browser

## Files Modified

### MainActivity.kt
- Added `PREF_SYNC_RING_TIME` and `PREF_SYNC_UTC_TIME` storage keys
- `saveTimeSyncPoint()`: Stores ring time (deciseconds) + UTC time (ms)
- `calculateUtcFromRingTime()`: Converts ring timestamp to UTC using sync point
- `formatUtcTimestamp()`: Formats as "d.M.yyyy HH:mm"
- TIME_SYNC response handler saves sync point automatically

### DataBrowserActivity.kt
- Added same UTC calculation functions
- Event 0x6A parsing now shows UTC timestamp first
- Display format: "UTC Timestamp: 11.11.2025 19:41"

### SleepPeriodInfoParser.kt
- Updated comments: `ringTimestamp` is in DECISECONDS (not seconds)
- Updated UTC conversion formula in comments

### activity_main.xml
- Reduced button heights from 32dp to 28dp
- Reduced text size from 10sp to 9sp
- Reduced padding for compact layout
- Reorganized into 3 rows with max 4 buttons each

## Technical Details

### Ring Timestamp System
- **No RTC**: Ring has no real-time clock
- **Monotonic counter**: Deciseconds since boot/factory reset
- **Synchronization**: TIME_SYNC pairs ring time with phone UTC
- **Persistence**: Last sync point stored in SharedPreferences

### Example Calculation
```
Event ring time: 136559 deciseconds
Sync ring time:  177799 deciseconds
Sync UTC time:   1731353414000 ms (11.11.2025 19:43:34)

Time difference: 177799 - 136559 = 41240 deciseconds
                = 4124 seconds = 68.73 minutes

Event UTC: 1731353414000 - (41240 * 100) = 1731349290000 ms
         = 11.11.2025 18:34:50
```

### Decompiled Code Analysis
Found in: `/home/picke/reverse_oura/analysis/decompiled/sources/`
- `com/ouraring/ringeventparser/message/TimeSyncIndValue.java`
- `com/ouraring/ourakit/operations/SyncTime.java`
- Native parser uses: `utcMillis = currentUTC - (currentRingTime - eventRingTime) * 100`

## Testing Results
- TIME_SYNC successful: Ring uptime shows ~5 hours (correct for today's reset)
- UTC timestamps in event browser match expected times
- Sync point persists across app restarts
- Events collected: 20x type 0x6A (SLEEP_PERIOD_INFO_2)

## Open TODOs

### High Priority
- [ ] **Create sleep stage chart visualization**
  - Parse 20 events of 0x6A data
  - Plot sleep stages over time (awake=0, light=1, deep/REM=2)
  - Show motion count, heart rate, HRV metrics
  - Display with UTC timestamps on X-axis

### Medium Priority
- [ ] Export sleep data to CSV/JSON format
- [ ] Implement other event parsers (0x42 TIME_SYNC_IND, 0x44 IBI_EVENT, etc.)
- [ ] Add date range filtering in event browser
- [ ] Calculate sleep session statistics (total sleep, stage percentages)

### Low Priority
- [ ] Add timezone display in event browser
- [ ] Implement event caching/database storage
- [ ] Add export functionality for parsed events

## Known Issues
None currently - UTC calculation verified and working correctly.

## Session Context
- **Date**: 2025-11-11 (November 11, 2025)
- **Current time during testing**: ~19:40 PM local time
- **Ring status**: Factory reset earlier today (~5 hours uptime)
- **Device**: fba13a79 (Android via ADB)
- **Build environment**: WSL2 Ubuntu, Android Studio project

## References
- Previous session: `SLEEP_PERIOD_INFO_MAPPING.md` - Verified 0x6A field mappings
- Decompiled sources: `~/reverse_oura/analysis/decompiled/`
- Project: `/home/picke/AndroidStudioProjects/reverseoura/`
