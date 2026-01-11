package com.example.reverseoura

import com.example.reverseoura.parsers.SleepPeriodInfoParser
import org.junit.Test
import org.junit.Assert.*

class SleepPeriodInfoParserTest {

    @Test
    fun testParseSleepPeriodInfo_UsingKotlinParser() {
        // Test our Kotlin reimplementation against the example data
        // Data: 6a 0e ed 8d 00 00 9b 00 6d 50 6d 32 08 01 00 00
        val eventData = byteArrayOf(
            0x6a.toByte(), 0x0e.toByte(), 0xed.toByte(), 0x8d.toByte(),
            0x00.toByte(), 0x00.toByte(), 0x9b.toByte(), 0x00.toByte(),
            0x6d.toByte(), 0x50.toByte(), 0x6d.toByte(), 0x32.toByte(),
            0x08.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte()
        )

        val result = SleepPeriodInfoParser.parse(eventData)

        assertNotNull("Parser should successfully parse the event", result)
        result?.let { info ->
            // Expected values based on serialize_api_sleep_period_info mapping:
            // Input: 6a 0e ed 8d 00 00 9b 00 6d 50 6d 32 08 01 00 00
            // Bytes 2-5 (timestamp): 0x00008ded = 36333
            // Bytes 6-9 (uVar13): 9b 00 6d 50
            //   byte0 = 0x9b = 155 → [0] average_hr = 155 * 0.5 = 77.5
            //   byte1 = 0x00 = 0   → [1] hr_trend = 0 * 0.0625 = 0.0
            //   byte2 = 0x6d = 109 → [2] mzci = 109 * 0.0625 = 6.8125
            //   byte3 = 0x50 = 80  → [3] dzci = 80 * 0.0625 = 5.0
            //                       → [4] breath = 109 * 0.0625 = 6.8125 (same as mzci!)
            //                       → [5] breath_v = 80 * 0.0625 = 5.0 (same as dzci!)
            // Byte 12 (bVar1): 0x08 = 8 → [6] motion_count = 8.0
            // Byte 13 (cVar5): 0x01 = 1 → [7] sleep_state = 1
            // Bytes 14-15 (uVar4): 0x0000 = 0 → [8] cv = 0.0

            assertEquals("ringTimestamp", 36333L, info.ringTimestamp)
            assertEquals("average_hr", 77.5f, info.averageHr, 0.01f)
            assertEquals("hr_trend", 0.0f, info.hrTrend, 0.01f)
            assertEquals("mzci", 6.8125f, info.mzci, 0.01f)
            assertEquals("dzci", 5.0f, info.dzci, 0.01f)
            assertEquals("breath", 6.8125f, info.breath, 0.01f)           // same as mzci
            assertEquals("breath_v", 5.0f, info.breathV, 0.01f)           // same as dzci
            assertEquals("motion_count", 8.0f, info.motionCount, 0.01f)
            assertEquals("sleep_state", 1, info.sleepState)
            assertEquals("sleep_state name", "light", info.getSleepStateName())
            assertEquals("cv", 0.0f, info.cv, 0.01f)
        }
    }

    @Test
    fun testParseAndFormat() {
        val eventData = byteArrayOf(
            0x6a.toByte(), 0x0e.toByte(), 0xed.toByte(), 0x8d.toByte(),
            0x00.toByte(), 0x00.toByte(), 0x9b.toByte(), 0x00.toByte(),
            0x6d.toByte(), 0x50.toByte(), 0x6d.toByte(), 0x32.toByte(),
            0x08.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte()
        )

        val formatted = SleepPeriodInfoParser.parseAndFormat(eventData)

        assertTrue("Should contain sleep state", formatted.contains("Sleep State"))
        assertTrue("Should contain motion count", formatted.contains("Motion Count"))
        assertTrue("Should show motion value", formatted.contains("8.0"))
        assertTrue("Should show light sleep", formatted.contains("light"))
        assertTrue("Should contain average_hr", formatted.contains("Average HR"))
        assertTrue("Should contain HRV metrics", formatted.contains("MZCI"))
    }

    @Test
    fun testInvalidEventId() {
        val invalidData = byteArrayOf(
            0x6b.toByte(), 0x0e.toByte(), 0xed.toByte(), 0x8d.toByte(),
            0x00.toByte(), 0x00.toByte(), 0x9b.toByte(), 0x00.toByte(),
            0x6d.toByte(), 0x50.toByte(), 0x6d.toByte(), 0x32.toByte(),
            0x08.toByte(), 0x01.toByte(), 0x00.toByte(), 0x00.toByte()
        )

        val result = SleepPeriodInfoParser.parse(invalidData)
        assertNull("Should return null for wrong event ID", result)
    }

    @Test
    fun testInvalidLength() {
        val tooShort = byteArrayOf(0x6a.toByte(), 0x0e.toByte())

        val result = SleepPeriodInfoParser.parse(tooShort)
        assertNull("Should return null for data too short", result)
    }
}
