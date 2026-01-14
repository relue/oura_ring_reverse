# Oura Ring Reverse Engineering Documentation

**Last Updated:** 2026-01-14

Complete documentation for reverse engineering the Oura Ring Gen 3/4 BLE protocol.

---

## Quick Find

| Looking for... | Go to |
|----------------|-------|
| Event type 0x48? | [reference/events/sleep.md](reference/events/sleep.md) |
| How to authenticate? | [reference/ble/auth.md](reference/ble/auth.md) |
| ML model decryption? | [reference/ml/encryption.md](reference/ml/encryption.md) |
| EcoreWrapper methods? | [reference/native/ecore.md](reference/native/ecore.md) |
| Sleep score contributors? | [reference/scores/sleep.md](reference/scores/sleep.md) |
| Data flow from ring to UI? | [reference/flow/_index.md](reference/flow/_index.md) |
| Set up the project | [getting-started/setup.md](getting-started/setup.md) |
| Understand how we found everything | [METHODOLOGY.md](METHODOLOGY.md) |

---

## Documentation Structure

### [Reference](reference/_index.md) - Technical Specifications

All specifications extracted from Oura Ring app analysis.

| Area | Files | What You'll Find |
|------|-------|------------------|
| [Events](reference/events/_index.md) | 8 | 63 event types with field definitions |
| [BLE](reference/ble/_index.md) | 5 | Protocol, auth, commands |
| [Native](reference/native/_index.md) | 4 | JNI methods, library analysis |
| [Structures](reference/structures/_index.md) | 5 | Data class definitions |
| [ML](reference/ml/_index.md) | 3 | Model table, decryption, I/O |
| [Flow](reference/flow/_index.md) | 4 | Data pipeline documentation |
| [Scores](reference/scores/_index.md) | 4 | Score algorithms & contributors |

### [Getting Started](getting-started/) - Setup & Basics
- [setup.md](getting-started/setup.md) - Project setup, requirements
- [python-client.md](getting-started/python-client.md) - Using the Python BLE client
- [troubleshooting.md](getting-started/troubleshooting.md) - Bluetooth issues and fixes

### [Guides](guides/) - How-To Tutorials
- [heartbeat-monitoring.md](guides/heartbeat-monitoring.md) - Real-time HR streaming
- [sleep-data.md](guides/sleep-data.md) - Sleep event format and UTC timestamps

### [Research](research/) - Deep Analysis
- [SLEEPNET_COMPLETE_PIPELINE.md](research/SLEEPNET_COMPLETE_PIPELINE.md) - Full SleepNet pipeline
- [SLEEPNET_INPUT_SPEC.md](research/SLEEPNET_INPUT_SPEC.md) - SleepNet input specification
- [SLEEPNET_INPUT_TRANSFORMATIONS.md](research/SLEEPNET_INPUT_TRANSFORMATIONS.md) - Input transformations
- [SLEEP_MODELS_CONTEXT_ANALYSIS.md](research/SLEEP_MODELS_CONTEXT_ANALYSIS.md) - Model context analysis
- [SLEEP_MODEL_DIFFICULTY_ANALYSIS.md](research/SLEEP_MODEL_DIFFICULTY_ANALYSIS.md) - Implementation difficulty

### [Reverse Engineering](reverse-engineering/) - Methodology
- [android-app.md](reverse-engineering/android-app.md) - APK analysis findings
- [frida.md](reverse-engineering/frida.md) - Frida instrumentation setup
- [native-libraries.md](reverse-engineering/native-libraries.md) - Native library analysis
- [protobuf-extraction.md](reverse-engineering/protobuf-extraction.md) - Schema extraction

### [Security](security/) - Keys & Third-Party
- [encryption-keys.md](security/encryption-keys.md) - API keys found in APK
- [third-party-services.md](security/third-party-services.md) - Braze, Segment analysis

### [Archive](archive/) - Original Files
- Original documentation preserved for reference

---

## Reading Order (New to Project)

1. **[Setup](getting-started/setup.md)** - Get the project running
2. **[BLE Protocol](reference/ble/protocol.md)** - Understand BLE basics
3. **[Authentication](reference/ble/auth.md)** - How to authenticate
4. **[Heartbeat Guide](guides/heartbeat-monitoring.md)** - Your first live data
5. **[Events Reference](reference/events/_index.md)** - What data the ring sends

---

## Key Technical Details

### BLE Connection
```
Service UUID:         98ed0001-a541-11e4-b6a0-0002a5d5c51b
Write Characteristic: 98ed0002-a541-11e4-b6a0-0002a5d5c51b
Notify Characteristic: 98ed0003-a541-11e4-b6a0-0002a5d5c51b
```

### Command Format
```
[0x2f][length][command][parameters...]
Response: command + 1
```

### Event Types
- `0x41-0x83` - 63+ event types
- Most use Protobuf encoding
- Some (0x6A, 0x46) use custom binary

### ML Models
- 27 PyTorch TorchScript models
- AES-256-GCM encrypted
- Key from native libsecrets.so

---

## Reference Directory

```
docs/reference/
├── _index.md               # Reference hub
├── events/                 # 63 BLE event types
│   ├── _index.md          # Master event table
│   ├── heart.md           # IBI, HRV, amplitude
│   ├── sleep.md           # Sleep periods, summaries
│   ├── activity.md        # Steps, MET, activity
│   ├── spo2.md            # Blood oxygen
│   ├── temperature.md     # 7-sensor temp
│   ├── motion.md          # Accelerometer, wear
│   └── system.md          # Ring start, sync, debug
├── ble/                    # BLE protocol
│   ├── _index.md          # Command table
│   ├── protocol.md        # Packet structure
│   ├── auth.md            # Authentication
│   ├── sync.md            # GetEvent, RData
│   └── realtime.md        # Live measurements
├── native/                 # Native libraries
│   ├── _index.md          # Library overview
│   ├── ecore.md           # EcoreWrapper (68+ methods)
│   ├── parser.md          # libringeventparser
│   └── secrets.md         # libsecrets
├── structures/             # Data classes
│   ├── _index.md          # Structure overview
│   ├── sleep.md           # SleepInfo, SleepSummary
│   ├── readiness.md       # ReadinessScoreOutput
│   ├── activity.md        # ActInfo
│   └── vitals.md          # HR/HRV, SpO2, IBI
├── ml/                     # ML models
│   ├── _index.md          # 27 models table
│   ├── encryption.md      # AES-GCM decryption
│   └── sleepnet.md        # SleepNet models
├── flow/                   # Data pipeline
│   ├── _index.md          # Flow overview
│   ├── ble-layer.md       # BLE communication
│   ├── processing.md      # Parsing, scoring
│   └── ui.md              # ViewModel, Compose
└── scores/                 # Score algorithms
    ├── _index.md          # Score overview
    ├── sleep.md           # 7 contributors
    ├── readiness.md       # 8+ contributors
    └── activity.md        # 6 contributors
```

---

## File Inventory

| Folder | Files | Purpose |
|--------|-------|---------|
| reference/ | 35 | Technical specifications |
| getting-started/ | 3 | Setup and basics |
| guides/ | 2 | Implementation guides |
| research/ | 6 | Deep analysis |
| reverse-engineering/ | 4 | RE methodology |
| security/ | 2 | Security findings |
| archive/ | 24+ | Original files |

---

## Contributing

When adding documentation:
1. Place in appropriate category folder
2. Update this README's navigation
3. Use consistent formatting
4. Include source file references

---

## See Also

- **Root README.md** - Project overview
- **native_parser/** - Protobuf schema and decryption tools
- **python_client/** - Working BLE client code
- **android_app/** - Android implementation
