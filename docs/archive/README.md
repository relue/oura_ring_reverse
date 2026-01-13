# Documentation Archive

This folder contains the original documentation files that were consolidated into the new structure.

**Archived:** 2026-01-12

---

## Why Archive?

The original documentation had ~35% content duplication across files. These files were merged into consolidated documents while preserving all detail.

**Before:** 341 KB across 30 files
**After:** ~220 KB across 17 files (35% reduction)

---

## Archive Contents

### original/docs-protocol/
Original protocol documentation files:
- `auth_protocol_spec.md` → Merged into `protocol/authentication.md`
- `event_data_definition.md` → Merged into `protocol/events.md`
- `heartbeat_complete_flow.md` → Merged into `guides/heartbeat-monitoring.md`
- `OURA_RING_COMMANDS.md` → Merged into `protocol/commands.md`
- `oura_ring_complete_protocol.md` → Moved to `protocol/overview.md`
- `protocolknowledge.md` → Merged into `protocol/events.md`

### original/docs-analysis/
Original analysis and research files:
- `0x6a_format_analysis.md` → Merged into `guides/sleep-data.md`
- `api_key_usage_analysis.md` → Merged into `security/encryption-keys.md`
- `attacker_model_keys_v2.md` → Merged into `security/encryption-keys.md`
- `braze_segment_industry_vs_oura.md` → Moved to `security/third-party-services.md`
- `FACTORY_RESET_TRACING_ANALYSIS.md` → Merged into `reverse-engineering/frida.md`
- `final_protocol_infos.md` → Archived (redundant)
- `frida-gadget-ble-analysis.md` → Merged into `reverse-engineering/frida.md`
- `heartbeat_replication_guide.md` → Merged into `guides/heartbeat-monitoring.md`
- `libsecrets_analysis.md` → Merged into `reverse-engineering/native-libraries.md`
- `oura_ring_command_reference.md` → Merged into `protocol/commands.md`
- `protocol-analysis-plan.md` → Archived (planning document)
- `SESSION_2025-11-11_UTC_TIMESTAMPS.md` → Merged into `guides/sleep-data.md`

### original/development-scripts/
Original planning documents:
- `AUTOMATION_PLAN.md` → Merged into `status/current-progress.md`
- `NATIVE_PARSER_PLAN.md` → Merged into `status/current-progress.md`

### original/native-parser/
Original native parser documentation:
- `MODEL_DECRYPTION.md` → Moved to `security/ml-models.md`
- `PLAN_full_protobuf_extraction.md` → Merged into `reverse-engineering/protobuf-extraction.md`
- `protobuf_schema_extraction.md` → Merged into `reverse-engineering/protobuf-extraction.md`
- `qemu_native_protobuf.md` → Merged into `reverse-engineering/native-libraries.md`

### session-notes/
Exploratory session notes (historical reference):
- `final_protocol_infos.md` - Quick protocol reference (superseded)
- `2025-11-11-utc-timestamps.md` - UTC implementation session

---

## File Mapping

| Original File | New Location | Action |
|---------------|--------------|--------|
| OURA_RING_COMMANDS.md | protocol/commands.md | Merged |
| oura_ring_command_reference.md | protocol/commands.md | Merged |
| protocolknowledge.md | protocol/events.md | Merged |
| event_data_definition.md | protocol/events.md | Merged |
| heartbeat_complete_flow.md | guides/heartbeat-monitoring.md | Merged |
| heartbeat_replication_guide.md | guides/heartbeat-monitoring.md | Merged |
| 0x6a_format_analysis.md | guides/sleep-data.md | Merged |
| SESSION_UTC_TIMESTAMPS.md | guides/sleep-data.md | Merged |
| attacker_model_keys_v2.md | security/encryption-keys.md | Merged |
| api_key_usage_analysis.md | security/encryption-keys.md | Merged |
| frida-gadget-ble-analysis.md | reverse-engineering/frida.md | Merged |
| FACTORY_RESET_TRACING.md | reverse-engineering/frida.md | Merged |
| qemu_native_protobuf.md | reverse-engineering/native-libraries.md | Merged |
| libsecrets_analysis.md | reverse-engineering/native-libraries.md | Merged |
| protobuf_schema_extraction.md | reverse-engineering/protobuf-extraction.md | Merged |
| PLAN_full_protobuf_extraction.md | reverse-engineering/protobuf-extraction.md | Merged |
| AUTOMATION_PLAN.md | status/current-progress.md | Merged |
| NATIVE_PARSER_PLAN.md | status/current-progress.md | Merged |

---

## Recovering Original Content

All original files are preserved in their respective `original/` subfolders. Git history also maintains the complete history of each file.

If you need to reference original content:
```bash
# View archived file
cat docs/archive/original/docs-protocol/OURA_RING_COMMANDS.md

# Or check git history
git log --oneline docs/protocol/OURA_RING_COMMANDS.md
```

---

## Notes

- Original files were copied (not moved) to preserve git history
- The merged documents contain attribution notes at the bottom
- No information was lost - content was consolidated, not deleted
