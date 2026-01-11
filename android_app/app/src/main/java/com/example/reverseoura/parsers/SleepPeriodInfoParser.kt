package com.example.reverseoura.parsers

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Parser for Oura Ring event 0x6A (API_SLEEP_PERIOD_INFO_2)
 * Based on decompiled EventParser::parse_api_sleep_period_info from libringeventparser.so
 */
data class SleepPeriodInfo(
    val ringTimestamp: Long,          // Ring timestamp in DECISECONDS since ring boot/reset (bytes 2-5, uint32 LE)
                                      // To convert to UTC: utcMillis = syncUtcMillis - (syncRingTime - ringTimestamp) * 100
                                      // Requires TIME_SYNC event to get syncRingTime and syncUtcMillis
    // Mapped from C++ output array to protobuf fields
    val averageHr: Float,             // [0] → average_hr (field 2) - byte6 * 0.5
    val hrTrend: Float,               // [1] → hr_trend (field 3) - byte7 * 0.0625
    val mzci: Float,                  // [2] → mzci (field 4) - byte8 * 0.0625 - HRV: Maurer-Zywietz Cross Correlation Index
    val dzci: Float,                  // [3] → dzci (field 5) - byte9 * 0.0625 - HRV: Detrended Zywietz Cross Correlation Index
    val breath: Float,                // [4] → breath (field 6) - byte8 * 0.0625 (SAME as mzci!)
    val breathV: Float,               // [5] → breath_v (field 7) - byte9 * 0.0625 (SAME as dzci!)
    val motionCount: Float,           // [6] → motion_count (field 8) - byte12
    val sleepState: Int,              // [7] → sleep_state (field 9) - byte13 (0=awake, 1=light, 2=deep/REM)
    val cv: Float                     // [8] → cv (field 10) - bytes14-15 / 65536.0 - PPG signal quality
) {
    fun getSleepStateName(): String = when (sleepState) {
        0 -> "awake"
        1 -> "light"
        2 -> "deep/REM"
        else -> "unknown"
    }
}

object SleepPeriodInfoParser {
    /**
     * Parse event 0x6A data
     *
     * Format (16 bytes total):
     * - Byte 0: Event ID (0x6A)
     * - Byte 1: Length (14)
     * - Bytes 2-15: Payload (14 bytes)
     *   - Offset 0x06-0x09: uVar13 (4-byte packed value containing all heart rate metrics)
     *   - Offset 0x0A: bVar3 (unused - overwritten)
     *   - Offset 0x0B: bVar2 (unused - overwritten)
     *   - Offset 0x0C: bVar1 (motion seconds, 0-120)
     *   - Offset 0x0D: cVar5 (sleep state, 0-2)
     *   - Offset 0x0E-0x0F: uVar4 (variability metric)
     *
     * The decompiled code shows that ALL metrics come from uVar13 at offset 6:
     * - Bytes 6-9 are read as 32-bit int
     * - Each byte is extracted and scaled:
     *   - byte6 * 0.5 -> heartRateMetric0
     *   - byte7 * 0.0625 -> heartRateMetric1
     *   - byte8 * 0.0625 -> breathMetric1 (NOT from byte 10!)
     *   - byte9 * 0.0625 -> breathMetric2 (NOT from byte 11!)
     */
    fun parse(data: ByteArray): SleepPeriodInfo? {
        if (data.size != 16) {
            return null
        }

        // Verify event ID
        if (data[0] != 0x6A.toByte()) {
            return null
        }

        // Verify length
        val length = data[1].toInt() and 0xFF
        if (length != 14) {
            return null
        }

        val buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

        // Extract timestamp at offset 0x02 (4 bytes, uint32 LE)
        val timestamp = buffer.getInt(0x02).toLong() and 0xFFFFFFFFL

        // Extract fields based on decompiled code offsets
        // Note: offsets are from start of full packet (including event ID and length)

        // uVar13 at offset 0x06 (4 bytes) - contains ALL heart rate and breath metrics
        val uVar13 = buffer.getInt(0x06)
        val byte0 = (uVar13 and 0xFF).toUByte().toInt()           // byte 6
        val byte1 = ((uVar13 shr 8) and 0xFF).toUByte().toInt()   // byte 7
        val byte2 = ((uVar13 shr 16) and 0xFF).toUByte().toInt()  // byte 8
        val byte3 = ((uVar13 shr 24) and 0xFF).toUByte().toInt()  // byte 9

        // bVar1 (motion_seconds) at offset 0x0C
        val bVar1 = data[0x0C].toUByte().toInt()
        if (bVar1 > 120) {
            // Out of valid range
            return null
        }

        // cVar5 (sleep_state) at offset 0x0D
        val cVar5 = data[0x0D].toInt() // signed byte
        if (cVar5 < 0 || cVar5 > 2) {
            // Out of valid range
            return null
        }

        // uVar4 at offset 0x0E (2 bytes, unsigned short)
        val uVar4 = buffer.getShort(0x0E).toUShort().toInt()

        // Return parsed values mapped to protobuf field names
        return SleepPeriodInfo(
            ringTimestamp = timestamp,
            averageHr = byte0 * 0.5f,            // [0] average_hr
            hrTrend = byte1 * 0.0625f,           // [1] hr_trend
            mzci = byte2 * 0.0625f,              // [2] mzci (HRV)
            dzci = byte3 * 0.0625f,              // [3] dzci (HRV)
            breath = byte2 * 0.0625f,            // [4] breath (same as mzci!)
            breathV = byte3 * 0.0625f,           // [5] breath_v (same as dzci!)
            motionCount = bVar1.toFloat(),       // [6] motion_count
            sleepState = cVar5,                  // [7] sleep_state
            cv = uVar4 / 65536.0f                // [8] cv (PPG quality)
        )
    }

    /**
     * Parse and format as human-readable string
     */
    fun parseAndFormat(data: ByteArray): String {
        val info = parse(data) ?: return "Failed to parse SleepPeriodInfo"

        return buildString {
            appendLine("SleepPeriodInfo:")
            appendLine("  Ring Timestamp: ${info.ringTimestamp} seconds (since ring boot)")
            appendLine("  Sleep State: ${info.sleepState} (${info.getSleepStateName()})")
            appendLine("  Motion Count: ${info.motionCount}")
            appendLine("  Average HR: ${info.averageHr} bpm")
            appendLine("  HR Trend: ${info.hrTrend}")
            appendLine("  MZCI (HRV): ${info.mzci}")
            appendLine("  DZCI (HRV): ${info.dzci}")
            appendLine("  Breath: ${info.breath} breaths/min")
            appendLine("  Breath Variability: ${info.breathV}")
            appendLine("  CV (PPG Quality): ${info.cv}")
        }
    }
}
