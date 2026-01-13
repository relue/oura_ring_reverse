# New Documentation - Pending Integration

**Date:** 2026-01-12

This folder contains recently generated documentation about SleepNet ML models that needs to be integrated into the main documentation structure.

---

## Files to Integrate

| File | Target Location | Action |
|------|-----------------|--------|
| `SLEEP_MODELS_CONTEXT_ANALYSIS.md` | `security/ml-models.md` | Merge (architecture details) |
| `SLEEP_MODEL_DIFFICULTY_ANALYSIS.md` | `security/ml-models.md` | Merge (implementation guide) |
| `SLEEPNET_INPUT_SPEC.md` | NEW: `guides/sleepnet-usage.md` | Create new guide |
| `SLEEPNET_INPUT_TRANSFORMATIONS.md` | NEW: `guides/sleepnet-usage.md` | Create new guide |
| `SLEEPNET_COMPLETE_PIPELINE.md` | NEW: `guides/sleepnet-usage.md` | Create new guide |

---

## Summary of New Content

### SleepNet Model Analysis
- **Two parallel sleep systems**: NSSA (traditional ML) and SleepNet (deep learning)
- **SleepNet is pure PyTorch** - loads without custom operators
- **NSSA requires libalgos.so** - not portable

### Input Specification
All 7 SleepNet inputs documented:
1. `bedtime_input` - Sleep window (ms to sec transform)
2. `ibi_input` - Inter-beat intervals with validity (EcoreWrapper processing)
3. `acm_input` - Motion/accelerometer data
4. `temp_input` - Temperature data
5. `spo2_input` - SpO2 data (can be empty)
6. `scalars_input` - Demographics (age, weight, sex)
7. `tst_input` - Total sleep time hint

### Key Finding
**No ML preprocessing required** - all transformations are algorithmic:
- Timestamp conversions (ms/decisec to seconds)
- EcoreWrapper IBI validity (DSP, not ML)
- Age calculation from birth date

---

## Integration Notes

When integrating:
1. Update `docs/README.md` navigation to include SleepNet guide
2. Cross-reference from `security/ml-models.md`
3. Consider creating `guides/sleepnet-usage.md` as comprehensive guide
4. Original files remain in `native_parser/decrypted_models/` as source of truth

---

## Source Location

Original files: `/home/witcher/projects/oura_ring_reverse/native_parser/decrypted_models/`
