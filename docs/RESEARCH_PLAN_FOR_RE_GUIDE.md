# Research Plan: Deep Investigation Tasks

What we need to look at in detail to create comprehensive reversing documentation.

---

## 1. BLE Operations Investigation

**What to study:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/operations/
```

**Files to read completely:**
- [ ] `GetEvent.java` - How events are requested from ring
- [ ] `Authenticate.java` + `GetAuthNonce.java` - Auth handshake
- [ ] `SetRealtimeMeasurements.java` - Live HR mode activation
- [ ] `RingOperation.java` - Base class for all operations
- [ ] All `RData*.java` files - Ring data fetch protocol
- [ ] All `DFU*.java` files - Firmware update protocol

**Questions to answer:**
- What are all REQUEST_TAG / RESPONSE_TAG pairs?
- How does extended tagging work (0x2B, 0x2C, 0x2D, 0x2E)?
- What bitmasks control realtime measurement modes?

---

## 2. Event Types Investigation

**What to study:**
```
_large_files/decompiled/sources/com/ouraring/ringeventparser/
```

**Files to read completely:**
- [ ] `data/RingEventType.java` - All 63 event type enums
- [ ] `Ringeventparser.java` - Protobuf message definitions (large file - grep for message names)
- [ ] `IbiAndAmplitudeEventKt.java` - IBI event structure
- [ ] `SleepPeriodInfoKt.java` - Sleep period event
- [ ] `HrvEventKt.java` - HRV event structure
- [ ] `SpO2EventKt.java` - SpO2 event structure

**Questions to answer:**
- What fields does each event type contain?
- Which events are emitted during sleep vs awake?
- How do events relate to each other (timestamps, period IDs)?

---

## 3. Native Library Interface Investigation

**What to study:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
```

**Files to read completely:**
- [ ] `EcoreWrapper.java` - All 50+ native method declarations (read in chunks)
- [ ] `ibi/IbiAndAmplitudeEvent.java` - Raw vs Corrected IBI
- [ ] `info/SleepInfo.java` - Sleep calculation output (large - use grep)
- [ ] `baseline/Baseline.java` - Rolling baseline structure
- [ ] `readiness/ReadinessScoreOutput.java` - Readiness components
- [ ] `activity/ActivityScoreOutput.java` - Activity components

**Also run:**
```bash
nm -D libappecore.so | grep Java_  # List all JNI functions
nm -D libringeventparser.so | grep Java_
nm -D libsecrets.so  # Model decryption functions
```

**Questions to answer:**
- What are the input/output types for each native method?
- Which methods are stateful (require initialization)?
- How does IBI correction work (input raw, output corrected)?

---

## 4. ML Model Investigation

**What to study:**
```
_large_files/decompiled/sources/com/ouraring/pytorch/
_large_files/models/assets/
```

**Files to read completely:**
- [ ] `PytorchModelFactory.java` - Model loading and decryption
- [ ] `PyTorchModelType.java` - Model registry/enum
- [ ] `SleepStaging32BitPytorchModel.java` - Sleep staging model usage
- [ ] One example of each model type wrapper

**Questions to answer:**
- How are models encrypted (AES-GCM, key source)?
- What input tensors does SleepNet expect?
- How are model outputs interpreted?

---

## 5. Score Calculation Flow Investigation

**What to study:**
- Trace from raw events → processed scores

**Files to read:**
- [ ] `EcoreWrapper.calculateSleepScore()` call sites
- [ ] `EcoreWrapper.calculateReadinessScore()` call sites
- [ ] `EcoreWrapper.calculateBaseline()` call sites
- [ ] Classes that use `SleepInfo`, `ReadinessScoreOutput`

**Questions to answer:**
- What event types feed into sleep score?
- How is the baseline built over time?
- What are the contributor weights to readiness?

---

## 6. Data Flow Tracing

**Trace these paths:**

1. **Ring → Database:**
   - [ ] BLE notification → GetEvent → RingEventParser → DbRawEvent

2. **Database → Score:**
   - [ ] DbRawEvent → EcoreWrapper.nativeProcessEvents → SleepInfo

3. **Score → UI:**
   - [ ] SleepInfo → Repository → ViewModel → Compose UI

**Find entry points by searching:**
```bash
grep -r "nativeProcessEvents" decompiled/
grep -r "DbRawEvent" decompiled/
grep -r "SleepInfo" decompiled/ | head -50
```

---

## 7. Package Structure Mapping

**Packages to understand:**
- [ ] `com.ouraring.oura` - Main app (113 subpackages)
- [ ] `com.ouraring.ourakit` - BLE layer
- [ ] `com.ouraring.ecorelibrary` - Native algorithms
- [ ] `com.ouraring.ringeventparser` - Event parsing
- [ ] `com.ouraring.pytorch` - ML models
- [ ] `com.ouraring.pillars` - Feature pillars
- [ ] `com.ouraring.core.realm` - Database

**For each package, identify:**
- Main entry point class
- Key interfaces
- How it connects to other packages

---

## 8. Specific Unknowns to Resolve

Things we discovered but need deeper investigation:

- [ ] What is NSSA (libnexusengine.so)? Alternative to SleepNet?
- [ ] How do "feature sessions" work (0x6C event)?
- [ ] What triggers sleep period detection on the ring?
- [ ] How does the ring determine wear state?
- [ ] What's the difference between API_IBI_EVENT (0x44) and API_IBI_AND_AMPLITUDE_EVENT (0x60)?
- [ ] How are temperature baselines calculated?
- [ ] What is the CVA (Cardiovascular Age) input format?

---

## Research Order

Suggested sequence for investigation:

1. **First:** Event types (RingEventType.java) - foundation for everything
2. **Second:** BLE operations - how we talk to the ring
3. **Third:** Native methods (EcoreWrapper) - what processing happens
4. **Fourth:** Data structures (SleepInfo, Baseline) - what data looks like
5. **Fifth:** ML models - advanced feature extraction
6. **Last:** Full flow tracing - connect all pieces

---

## Output Format

For each investigated area, document:
- File locations
- Key class/method names
- Data formats (byte layouts, field meanings)
- Relationships to other components
- Any discovered constants or magic values
