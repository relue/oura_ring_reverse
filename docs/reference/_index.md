# Technical Reference

All specifications extracted from Oura Ring app analysis.

---

## Quick Navigation

| Area | Files | What You'll Find |
|------|-------|------------------|
| [Events](events/_index.md) | 8 | 63 event types with field definitions |
| [BLE](ble/_index.md) | 5 | Protocol, auth, commands |
| [Native](native/_index.md) | 4 | JNI methods, library analysis |
| [Structures](structures/_index.md) | 5 | Data class definitions |
| [ML](ml/_index.md) | 3 | Model table, decryption, I/O |
| [Flow](flow/_index.md) | 4 | Data pipeline documentation |
| [Scores](scores/_index.md) | 4 | Score algorithms & contributors |

---

## By Topic

### Events (63 BLE Event Types)

| Category | Document | Event Tags |
|----------|----------|------------|
| Heart/PPG | [heart.md](events/heart.md) | 0x44, 0x5B, 0x5D, 0x60 |
| Sleep | [sleep.md](events/sleep.md) | 0x48, 0x4E, 0x66 |
| Activity | [activity.md](events/activity.md) | 0x47, 0x5A, 0x74 |
| SpO2 | [spo2.md](events/spo2.md) | 0x61-0x64 |
| Temperature | [temperature.md](events/temperature.md) | 0x43, 0x4A |
| Motion | [motion.md](events/motion.md) | 0x42, 0x4F, 0x77 |
| System | [system.md](events/system.md) | 0x41, 0x46, 0x50 |

### BLE Protocol

| Topic | Document | Description |
|-------|----------|-------------|
| Protocol | [protocol.md](ble/protocol.md) | Packet structure, UUIDs |
| Authentication | [auth.md](ble/auth.md) | GetAuthNonce, Authenticate |
| Data Sync | [sync.md](ble/sync.md) | GetEvent, RData protocol |
| Realtime | [realtime.md](ble/realtime.md) | Live HR streaming |

### Native Libraries

| Library | Document | Purpose |
|---------|----------|---------|
| libappecore.so | [ecore.md](native/ecore.md) | 68+ JNI methods |
| libringeventparser.so | [parser.md](native/parser.md) | Event parsing |
| libsecrets.so | [secrets.md](native/secrets.md) | Model decryption keys |

### Data Structures

| Category | Document | Key Classes |
|----------|----------|-------------|
| Sleep | [sleep.md](structures/sleep.md) | SleepInfo, SleepSummary |
| Readiness | [readiness.md](structures/readiness.md) | ReadinessScoreOutput |
| Activity | [activity.md](structures/activity.md) | ActInfo |
| Vitals | [vitals.md](structures/vitals.md) | HrHrvOutputInfo, SpO2Info |

### ML Models (27 Models)

| Topic | Document | Description |
|-------|----------|-------------|
| Inventory | [_index.md](ml/_index.md) | 27 models table |
| Encryption | [encryption.md](ml/encryption.md) | AES-GCM decryption |
| SleepNet | [sleepnet.md](ml/sleepnet.md) | Sleep staging models |

### Data Flow

| Layer | Document | Description |
|-------|----------|-------------|
| BLE | [ble-layer.md](flow/ble-layer.md) | Notification routing |
| Processing | [processing.md](flow/processing.md) | Parsing, scoring |
| UI | [ui.md](flow/ui.md) | ViewModel, Compose |

### Scores

| Score | Document | Contributors |
|-------|----------|--------------|
| Sleep | [sleep.md](scores/sleep.md) | 7 contributors |
| Readiness | [readiness.md](scores/readiness.md) | 8+ contributors |
| Activity | [activity.md](scores/activity.md) | 6 contributors |

---

## Source References

All documentation preserves reverse engineering traceability:

- **Package references:** ecorelibrary, ringeventparser, ourakit
- **Java source files:** 130+ .java file references
- **Native methods:** 84+ nativeXxx() method signatures
- **Decompiled paths:** _large_files/decompiled/sources/

---

## See Also

- [Main README](../README.md) - Documentation overview
- [Methodology](../METHODOLOGY.md) - How we found everything
- [Research](../research/) - Deep analysis documents
