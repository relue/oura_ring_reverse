# Oura Ring Reverse Engineering Documentation

**Last Updated:** 2026-01-12

Complete documentation for reverse engineering the Oura Ring Gen 3 BLE protocol.

---

## Quick Navigation

| I want to... | Go to |
|--------------|-------|
| **Understand how we found everything** | [**METHODOLOGY.md**](METHODOLOGY.md) |
| Set up the project | [getting-started/setup.md](getting-started/setup.md) |
| Understand the BLE protocol | [protocol/overview.md](protocol/overview.md) |
| Monitor heartbeat in real-time | [guides/heartbeat-monitoring.md](guides/heartbeat-monitoring.md) |
| Parse sleep data | [guides/sleep-data.md](guides/sleep-data.md) |
| Find command reference | [protocol/commands.md](protocol/commands.md) |
| See all event types | [protocol/events.md](protocol/events.md) |
| Learn about the ML models | [security/ml-models.md](security/ml-models.md) |

---

## Documentation Structure

### Getting Started
- [**setup.md**](getting-started/setup.md) - Project setup, requirements, transfer guide
- [**python-client.md**](getting-started/python-client.md) - Using the Python BLE client
- [**troubleshooting.md**](getting-started/troubleshooting.md) - Bluetooth issues and fixes

### Protocol Specification
- [**overview.md**](protocol/overview.md) - Complete BLE protocol documentation
- [**authentication.md**](protocol/authentication.md) - Auth flow (GetAuthNonce, Authenticate)
- [**commands.md**](protocol/commands.md) - All 36+ commands with formats
- [**events.md**](protocol/events.md) - All 63+ event types (0x41-0x83)

### Implementation Guides
- [**heartbeat-monitoring.md**](guides/heartbeat-monitoring.md) - Real-time HR streaming
- [**sleep-data.md**](guides/sleep-data.md) - Sleep event format and UTC timestamps

### Reverse Engineering
- [**android-app.md**](reverse-engineering/android-app.md) - APK analysis findings
- [**frida.md**](reverse-engineering/frida.md) - Frida instrumentation setup
- [**native-libraries.md**](reverse-engineering/native-libraries.md) - libringeventparser, libsecrets
- [**protobuf-extraction.md**](reverse-engineering/protobuf-extraction.md) - Schema extraction methods

### Security Analysis
- [**encryption-keys.md**](security/encryption-keys.md) - API keys found in APK
- [**ml-models.md**](security/ml-models.md) - PyTorch model decryption (28 models)
- [**third-party-services.md**](security/third-party-services.md) - Braze, Segment analysis

### Project Status
- [**current-progress.md**](status/current-progress.md) - Milestones and roadmap

### Archive
- [**archive/**](archive/) - Original documentation files preserved

---

## Reading Order (New to Project)

1. **[Setup](getting-started/setup.md)** - Get the project running
2. **[Protocol Overview](protocol/overview.md)** - Understand BLE basics
3. **[Authentication](protocol/authentication.md)** - How to authenticate
4. **[Heartbeat Guide](guides/heartbeat-monitoring.md)** - Your first live data
5. **[Events Reference](protocol/events.md)** - What data the ring sends

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
- 28 PyTorch TorchScript models
- AES-256-GCM encrypted
- Key in APK's `secrets.json`

---

## File Inventory

| Folder | Files | Purpose |
|--------|-------|---------|
| getting-started/ | 3 | Setup and basics |
| protocol/ | 4 | BLE specifications |
| guides/ | 2 | Implementation guides |
| reverse-engineering/ | 4 | RE methodology |
| security/ | 3 | Security findings |
| status/ | 1 | Project progress |
| archive/ | 24+ | Original files |

**Total:** ~220 KB of consolidated documentation (down from 341 KB)

---

## Contributing

When adding documentation:
1. Place in appropriate category folder
2. Update this README's navigation
3. Use consistent formatting
4. Include "Last Updated" date

---

## See Also

- **Root README.md** - Project overview
- **native_parser/** - Protobuf schema and decryption tools
- **python_client/** - Working BLE client code
- **android_app/** - Android implementation
