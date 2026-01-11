package com.example.reverseoura

import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.Spinner
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.example.reverseoura.parsers.SleepPeriodInfoParser

class DataBrowserActivity : AppCompatActivity() {

    private lateinit var summaryText: TextView
    private lateinit var eventListText: TextView
    private lateinit var backButton: Button
    private lateinit var eventTypeSpinner: Spinner
    private var selectedEventTag: Int? = null  // null = show all

    companion object {
        var eventData: List<ByteArray> = listOf()
        private const val PREFS_NAME = "OuraRingPrefs"
        private const val PREF_SYNC_RING_TIME = "sync_ring_time_deciseconds"
        private const val PREF_SYNC_UTC_TIME = "sync_utc_time_millis"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_data_browser)

        summaryText = findViewById(R.id.summaryText)
        eventListText = findViewById(R.id.eventListText)
        backButton = findViewById(R.id.backButton)
        eventTypeSpinner = findViewById(R.id.eventTypeSpinner)

        backButton.setOnClickListener {
            finish()
        }

        // Test native parser loading
        testNativeParser()

        setupSpinner()
        displayEvents()
    }

    private fun testNativeParser() {
        try {
            val parser = RingEventParser()
            android.util.Log.d("DataBrowser", "✓ Native parser initialized")

            if (eventData.isEmpty()) {
                android.util.Log.w("DataBrowser", "No events to parse")
                return
            }

            // Parse ALL captured events
            android.util.Log.d("DataBrowser", "Parsing ${eventData.size} total events...")
            val result = parser.parseEvents(eventData)

            android.util.Log.d("DataBrowser", "=".repeat(80))
            android.util.Log.d("DataBrowser", "NATIVE PARSER RESULT:")
            android.util.Log.d("DataBrowser", "Type: ${result?.javaClass?.name}")
            android.util.Log.d("DataBrowser", "ToString: $result")

            // Try to inspect the returned object
            if (result != null) {
                try {
                    if (result is Map<*, *>) {
                        android.util.Log.d("DataBrowser", "Result is a Map with ${result.size} keys:")
                        for ((key, value) in result) {
                            when (key) {
                                "resultObjectBytes" -> {
                                    if (value is ByteArray) {
                                        android.util.Log.d("DataBrowser", "  $key = ByteArray(${value.size} bytes)")
                                        // Print first 256 bytes in hex
                                        val hexStr = value.take(256).joinToString(" ") { "%02x".format(it) }
                                        android.util.Log.d("DataBrowser", "    First 256 bytes: $hexStr")

                                        // Save to file for analysis
                                        try {
                                            val file = java.io.File("/data/local/tmp/ringdata_object.bin")
                                            file.writeBytes(value)
                                            android.util.Log.d("DataBrowser", "    ✓ Saved to: ${file.absolutePath}")
                                        } catch (e: Exception) {
                                            android.util.Log.e("DataBrowser", "    Failed to save: ${e.message}")
                                        }
                                    } else {
                                        android.util.Log.d("DataBrowser", "  $key = $value")
                                    }
                                }
                                else -> android.util.Log.d("DataBrowser", "  $key = $value")
                            }
                        }
                    } else {
                        val methods = result.javaClass.methods
                        android.util.Log.d("DataBrowser", "Available methods (first 10):")
                        methods.take(10).forEach { method ->
                            android.util.Log.d("DataBrowser", "  - ${method.name}")
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.e("DataBrowser", "Error inspecting result: ${e.message}")
                }
            }
            android.util.Log.d("DataBrowser", "=".repeat(80))

        } catch (e: Exception) {
            android.util.Log.e("DataBrowser", "✗ Native parser failed: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun setupSpinner() {
        // Get unique event types from data
        val eventTypes = eventData
            .filter { it.isNotEmpty() }
            .map { it[0].toInt() and 0xFF }
            .distinct()
            .sorted()

        // Create spinner items with "All Events" first
        data class SpinnerItem(val tag: Int?, val label: String)
        val spinnerItems = mutableListOf<SpinnerItem>()
        spinnerItems.add(SpinnerItem(null, "All Events"))

        for (tag in eventTypes) {
            val name = getEventTypeName(tag)
            spinnerItems.add(SpinnerItem(tag, "0x%02x - %s".format(tag, name)))
        }

        // Setup adapter
        val adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            spinnerItems.map { it.label }
        )
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        eventTypeSpinner.adapter = adapter

        // Handle selection
        eventTypeSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                selectedEventTag = spinnerItems[position].tag
                displayEvents()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
                selectedEventTag = null
                displayEvents()
            }
        }
    }

    private fun displayEvents() {
        val output = StringBuilder()

        // Apply selected filter and reverse to show newest first
        val filteredEvents = eventData.filter { event ->
            if (event.isEmpty()) return@filter false
            val tag = event[0].toInt() and 0xFF
            selectedEventTag == null || tag == selectedEventTag
        }.reversed()  // Show newest events first

        val filterDesc = if (selectedEventTag == null) {
            "All event types"
        } else {
            "Filter: 0x%02x - %s".format(selectedEventTag, getEventTypeName(selectedEventTag!!))
        }

        println("╔════════════════════════════════════════════════════╗")
        println("║  DATA BROWSER ACTIVITY - SHOW DATA CLICKED        ║")
        println("╚════════════════════════════════════════════════════╝")
        println("  Total events in eventData: ${eventData.size}")
        println("  $filterDesc")
        println("  Filtered events: ${filteredEvents.size}")
        println("")

        output.append("═══════════════════════════════════════════════════\n")
        output.append("   EVENT BROWSER - $filterDesc\n")
        output.append("═══════════════════════════════════════════════════\n")
        output.append("Total events: ${eventData.size} | Showing: ${filteredEvents.size}\n\n")

        // Count events by type (from filtered events)
        val eventCounts = mutableMapOf<Int, Int>()
        for (event in eventData) {
            if (event.isNotEmpty()) {
                val tag = event[0].toInt() and 0xFF
                eventCounts[tag] = (eventCounts[tag] ?: 0) + 1
            }
        }

        output.append("Event Summary:\n")
        for ((tag, count) in eventCounts.toSortedMap()) {
            val name = getEventTypeName(tag)
            output.append("  0x%02x (%3d): %-30s x%d\n".format(tag, tag, name, count))
        }
        output.append("\n")

        val summaryLine = if (selectedEventTag == null) {
            "Showing: ${filteredEvents.size} events | ${eventCounts.size} types"
        } else {
            "Showing: ${filteredEvents.size} of ${eventData.size} events"
        }
        summaryText.text = summaryLine

        // Log event summary to logcat
        android.util.Log.d("DataBrowser", "╔═══════════════════════════════════════════════════╗")
        android.util.Log.d("DataBrowser", "║  EVENT BROWSER SUMMARY                            ║")
        android.util.Log.d("DataBrowser", "╚═══════════════════════════════════════════════════╝")
        android.util.Log.d("DataBrowser", summaryLine)
        for ((tag, count) in eventCounts.toSortedMap()) {
            val name = getEventTypeName(tag)
            android.util.Log.d("DataBrowser", "  0x%02x (%3d): %-30s x%d".format(tag, tag, name, count))
        }
        android.util.Log.d("DataBrowser", "═══════════════════════════════════════════════════")

        // Parse and display each filtered event
        val nativeParser = RingEventParser()

        for ((index, event) in filteredEvents.withIndex()) {
            if (event.isEmpty()) continue

            val tag = event[0].toInt() and 0xFF
            val name = getEventTypeName(tag)
            val payload = if (event.size > 2) event.copyOfRange(2, event.size) else byteArrayOf()

            println("┌────────────────────────────────────────────────────┐")
            println("│ Event #${index + 1}: $name (0x%02x) - ${event.size} bytes".format(tag))
            println("└────────────────────────────────────────────────────┘")

            // Show full hex dump in logs
            val hexDump = event.joinToString(" ") { "%02x".format(it) }
            println("  Full hex: $hexDump")
            println("  Payload size: ${payload.size} bytes")

            output.append("────────────────────────────────────────────────────\n")
            output.append("Event #${index + 1}: $name (0x%02x)\n".format(tag))
            output.append("Size: ${event.size} bytes\n")

            // Show hex dump of first 50 bytes
            val hexDumpShort = event.take(50).joinToString(" ") { "%02x".format(it) }
            output.append("Hex: $hexDumpShort${if (event.size > 50) "..." else ""}\n")

            // ═══════════════════════════════════════════════════════════════
            // KOTLIN PARSER OUTPUT
            // ═══════════════════════════════════════════════════════════════
            output.append("\n[PARSED DATA]\n")

            if (payload.isNotEmpty()) {
                when (tag) {
                    0x46 -> {
                        // Temperature events - custom binary format
                        println("  Using custom binary parser for TEMP_EVENT...")
                        val fields = parseTempEventBinary(payload)
                        println("  Parsed ${fields.size} fields: ${fields.keys.joinToString(", ")}")

                        if (fields.isNotEmpty()) {
                            println("  ✓ Successfully parsed fields!")
                            for ((fieldNum, values) in fields.toSortedMap()) {
                                val fieldName = getFieldName(tag, fieldNum)
                                println("    Field $fieldNum ($fieldName): ${values.size} value(s)")
                                if (values.size == 1) {
                                    val formatted = formatValue(values[0], fieldNum, tag)
                                    println("      Value: $formatted")
                                    output.append("  Field %2d (%s): %s\n".format(fieldNum, fieldName, formatted))
                                } else {
                                    output.append("  Field %2d (%s): [array of ${values.size}]\n".format(fieldNum, fieldName))
                                    for ((i, value) in values.take(5).withIndex()) {
                                        val formatted = formatValue(value, fieldNum, tag)
                                        println("      [$i] = $formatted")
                                        output.append("    [%d] = %s\n".format(i, formatted))
                                    }
                                    if (values.size > 5) {
                                        output.append("    ... and ${values.size - 5} more\n")
                                    }
                                }
                            }
                        } else {
                            println("  ✗ No parseable fields found!")
                            output.append("  (No parseable fields - raw binary data)\n")
                        }
                    }
                    0x6A -> {
                        // API_SLEEP_PERIOD_INFO_2 - use verified parser
                        println("  Using verified SleepPeriodInfoParser for event 0x6A...")
                        try {
                            val info = SleepPeriodInfoParser.parse(event)
                            if (info != null) {
                                println("  ✓ Successfully parsed SleepPeriodInfo!")

                                // Calculate UTC timestamp using TIME_SYNC data
                                val utcMillis = calculateUtcFromRingTime(info.ringTimestamp)
                                val utcFormatted = if (utcMillis != null) {
                                    formatUtcTimestamp(utcMillis)
                                } else {
                                    "N/A (no TIME_SYNC)"
                                }

                                output.append("  UTC Timestamp: $utcFormatted\n")
                                output.append("  Ring Timestamp: ${info.ringTimestamp} decisec (%.1f sec since ring boot)\n".format(info.ringTimestamp / 10.0))
                                output.append("  Sleep State: ${info.sleepState} (${info.getSleepStateName()})\n")
                                output.append("  Motion Count: ${info.motionCount}\n")
                                output.append("  Average HR: ${"%.1f".format(info.averageHr)} bpm\n")
                                output.append("  HR Trend: ${"%.4f".format(info.hrTrend)}\n")
                                output.append("  MZCI (HRV): ${"%.4f".format(info.mzci)}\n")
                                output.append("  DZCI (HRV): ${"%.4f".format(info.dzci)}\n")
                                output.append("  Breath: ${"%.4f".format(info.breath)} breaths/min\n")
                                output.append("  Breath Variability: ${"%.4f".format(info.breathV)}\n")
                                output.append("  CV (PPG Quality): ${"%.4f".format(info.cv)}\n")

                                println("    UTC Timestamp: $utcFormatted")
                                println("    Ring Timestamp: ${info.ringTimestamp} sec (since boot)")
                                println("    Sleep State: ${info.sleepState} (${info.getSleepStateName()})")
                                println("    Motion Count: ${info.motionCount}")
                                println("    Average HR: %.1f bpm".format(info.averageHr))
                                println("    HR Trend: %.4f".format(info.hrTrend))
                                println("    MZCI: %.4f".format(info.mzci))
                                println("    DZCI: %.4f".format(info.dzci))
                                println("    Breath: %.4f breaths/min".format(info.breath))
                                println("    Breath Variability: %.4f".format(info.breathV))
                                println("    CV: %.4f".format(info.cv))
                            } else {
                                println("  ✗ SleepPeriodInfoParser returned null")
                                output.append("  (Parse failed - invalid format)\n")
                            }
                        } catch (e: Exception) {
                            println("  ✗ SleepPeriodInfoParser error: ${e.message}")
                            output.append("  (Parse error: ${e.message})\n")
                        }
                    }
                    else -> {
                        // Generic protobuf parsing
                        println("  Attempting to parse Protobuf fields...")
                        val fields = parseProtobufGeneric(payload, tag)
                        println("  Parsed ${fields.size} fields: ${fields.keys.joinToString(", ")}")

                        if (fields.isNotEmpty()) {
                            println("  ✓ Successfully parsed fields!")
                            for ((fieldNum, values) in fields.toSortedMap()) {
                                val fieldName = getFieldName(tag, fieldNum)
                                println("    Field $fieldNum ($fieldName): ${values.size} value(s)")
                                if (values.size == 1) {
                                    val formatted = formatValue(values[0], fieldNum, tag)
                                    println("      Value: $formatted")
                                    output.append("  Field %2d (%s): %s\n".format(fieldNum, fieldName, formatted))
                                } else {
                                    output.append("  Field %2d (%s): [array of ${values.size}]\n".format(fieldNum, fieldName))
                                    for ((i, value) in values.take(5).withIndex()) {
                                        val formatted = formatValue(value, fieldNum, tag)
                                        println("      [$i] = $formatted")
                                        output.append("    [%d] = %s\n".format(i, formatted))
                                    }
                                    if (values.size > 5) {
                                        output.append("    ... and ${values.size - 5} more\n")
                                    }
                                }
                            }
                        } else {
                            println("  ✗ No parseable fields found!")
                            output.append("  (No parseable fields - raw binary data)\n")
                        }
                    }
                }
            } else {
                output.append("  (Empty payload)\n")
            }
        }

        output.append("════════════════════════════════════════════════════\n")
        output.append("✅ Displayed ${filteredEvents.size} events\n")

        eventListText.text = output.toString()
    }

    private fun getEventTypeName(tag: Int): String {
        return when (tag) {
            65 -> "API_RING_START_IND"
            66 -> "API_TIME_SYNC_IND"
            67 -> "API_DEBUG_EVENT_IND"
            68 -> "API_IBI_EVENT"
            69 -> "API_STATE_CHANGE_IND"
            70 -> "API_TEMP_EVENT"
            71 -> "API_MOTION_EVENT"
            72 -> "API_SLEEP_PERIOD_INFO"
            73 -> "API_SLEEP_SUMMARY_1"
            74 -> "API_PPG_AMPLITUDE_IND"
            75 -> "API_SLEEP_PHASE_INFO"
            76 -> "API_SLEEP_SUMMARY_2"
            77 -> "API_RING_SLEEP_FEATURE_INFO"
            78 -> "API_SLEEP_PHASE_DETAILS"
            79 -> "API_SLEEP_SUMMARY_3"
            80 -> "API_ACTIVITY_INFO"
            81 -> "API_ACTIVITY_SUMMARY_1"
            82 -> "API_ACTIVITY_SUMMARY_2"
            83 -> "API_WEAR_EVENT"
            84 -> "API_RECOVERY_SUMMARY"
            85 -> "API_SLEEP_HR"
            86 -> "API_ALERT_EVENT"
            87 -> "API_RING_SLEEP_FEATURE_INFO_2"
            88 -> "API_SLEEP_SUMMARY_4"
            89 -> "API_EDA_EVENT"
            90 -> "API_SLEEP_PHASE_DATA"
            91 -> "API_BLE_CONNECTION_IND"
            92 -> "API_USER_INFO"
            93 -> "API_HRV_EVENT"
            94 -> "API_SELFTEST_EVENT"
            95 -> "API_RAW_ACM_EVENT"
            96 -> "API_IBI_AND_AMPLITUDE_EVENT"
            97 -> "API_DEBUG_DATA"
            98 -> "API_ON_DEMAND_MEAS"
            99 -> "API_PPG_PEAK_EVENT"
            100 -> "API_RAW_PPG_EVENT"
            101 -> "API_ON_DEMAND_SESSION"
            102 -> "API_ON_DEMAND_MOTION"
            103 -> "API_RAW_PPG_SUMMARY"
            104 -> "API_RAW_PPG_DATA"
            105 -> "API_TEMP_PERIOD"
            106 -> "API_SLEEP_PERIOD_INFO_2"
            107 -> "API_MOTION_PERIOD"
            108 -> "API_FEATURE_SESSION"
            109 -> "API_MEAS_QUALITY_EVENT"
            110 -> "API_SPO2_IBI_AND_AMPLITUDE_EVENT"
            111 -> "API_SPO2_EVENT"
            112 -> "API_SPO2_SMOOTHED_EVENT"
            113 -> "API_GREEN_IBI_AND_AMP_EVENT"
            114 -> "API_SLEEP_ACM_PERIOD"
            115 -> "API_EHR_TRACE_EVENT"
            116 -> "API_EHR_ACM_INTENSITY_EVENT"
            117 -> "API_SLEEP_TEMP_EVENT"
            118 -> "API_BEDTIME_PERIOD"
            119 -> "API_SPO2_DC_EVENT"
            121 -> "API_SELFTEST_DATA_EVENT"
            122 -> "API_TAG_EVENT"
            126 -> "API_REAL_STEP_EVENT_FEATURE_ONE"
            127 -> "API_REAL_STEP_EVENT_FEATURE_TWO"
            128 -> "API_GREEN_IBI_QUALITY_EVENT"
            129 -> "API_CVA_RAW_PPG_DATA"
            130 -> "API_SCAN_START"
            131 -> "API_SCAN_END"
            else -> "UNKNOWN_EVENT"
        }
    }

    private fun getFieldName(tag: Int, fieldNum: Int): String {
        // Tag 70 = API_TEMP_EVENT (Temperature sensors - custom binary format)
        if (tag == 70) {
            return when (fieldNum) {
                1 -> "timestamp_counter"
                2 -> "temp_sensor_1"
                3 -> "temp_reference"
                4 -> "temp_sensor_2"
                else -> "field$fieldNum"
            }
        }

        // Tag 97 = API_DEBUG_DATA (OnDemandSession)
        if (tag == 97) {
            return when (fieldNum) {
                1 -> "timestamp"
                2 -> "eventSubtype"
                3 -> "skinTempIntervalS"
                4 -> "motionPeriodIntervalS"
                5 -> "hrIntervalS"
                6 -> "hrvIntervalS"
                7 -> "breathingRateIntervalS"
                8 -> "rawPpgRateHz"
                9 -> "maxSessionDurationMin"
                else -> "field$fieldNum"
            }
        }
        return if (fieldNum == 1) "timestamp" else "field$fieldNum"
    }

    private fun formatValue(value: Long, fieldNum: Int, eventTag: Int = 0): String {
        // Tag 70 (API_TEMP_EVENT) fields 2-4 = temperature values (0.01°C units)
        if (eventTag == 70 && fieldNum in 2..4) {
            val celsius = value / 100.0
            val fahrenheit = celsius * 9.0 / 5.0 + 32.0
            return "$value (%.2f°C / %.2f°F)".format(celsius, fahrenheit)
        }

        // Field 1 is usually timestamp
        if (fieldNum == 1 && value > 1000000000 && value < 2000000000) {
            val date = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).apply {
                timeZone = java.util.TimeZone.getTimeZone("UTC")
            }.format(java.util.Date(value * 1000))
            return "$value (UTC: $date)"
        }

        // Tag 97 (API_DEBUG_DATA/OnDemandSession) field 2 = eventSubtype enum
        if (eventTag == 97 && fieldNum == 2) {
            val subtypeName = when (value.toInt()) {
                0 -> "SESSION_START"
                1 -> "SESSION_END_APP_REQUEST"
                2 -> "SESSION_END_TIMEOUT"
                3 -> "SESSION_END_LOW_BATTERY"
                4 -> "SESSION_END_UNEXPECTED_ERROR"
                255 -> "UNSPECIFIED"
                else -> "UNKNOWN"
            }
            return "$value ($subtypeName)"
        }

        return value.toString()
    }

    /**
     * Parse temperature event (0x46) custom binary format
     *
     * Format (11 bytes after tag):
     * Byte 0:     0x0a (format marker)
     * Bytes 1-2:  timestamp/counter (uint16 LE)
     * Bytes 3-4:  0x0000 (reserved)
     * Bytes 5-6:  temp sensor 1 (uint16 LE, 0.01°C)
     * Bytes 7-8:  reference temp (uint16 LE, ~32.00°C)
     * Bytes 9-10: temp sensor 2 (uint16 LE, 0.01°C)
     */
    private fun parseTempEventBinary(data: ByteArray): Map<Int, List<Long>> {
        val fields = mutableMapOf<Int, MutableList<Long>>()

        println("  → Binary format decoder:")
        println("    Payload size: ${data.size} bytes")

        // Validate minimum size (11 bytes)
        if (data.size < 11) {
            println("    ✗ Payload too small (expected 11 bytes)")
            return fields
        }

        // Check format marker
        val formatMarker = data[0].toInt() and 0xFF
        println("    Format marker: 0x%02x".format(formatMarker))
        if (formatMarker != 0x0a) {
            println("    ⚠ Warning: Unexpected format marker (expected 0x0a)")
        }

        // Read timestamp/counter (bytes 1-2, little-endian uint16)
        val timestamp = readUint16LE(data, 1)
        println("    Timestamp/counter: $timestamp")
        fields.getOrPut(1) { mutableListOf() }.add(timestamp)

        // Read reserved bytes (bytes 3-4)
        val reserved = readUint16LE(data, 3)
        println("    Reserved: 0x%04x".format(reserved))

        // Read temp sensor 1 (bytes 5-6, uint16 LE, 0.01°C units)
        val temp1Raw = readUint16LE(data, 5)
        println("    Temp sensor 1 raw: $temp1Raw (%.2f°C)".format(temp1Raw / 100.0))
        fields.getOrPut(2) { mutableListOf() }.add(temp1Raw)

        // Read reference temp (bytes 7-8, uint16 LE, 0.01°C units)
        val tempRefRaw = readUint16LE(data, 7)
        println("    Reference temp raw: $tempRefRaw (%.2f°C)".format(tempRefRaw / 100.0))
        fields.getOrPut(3) { mutableListOf() }.add(tempRefRaw)

        // Read temp sensor 2 (bytes 9-10, uint16 LE, 0.01°C units)
        val temp2Raw = readUint16LE(data, 9)
        println("    Temp sensor 2 raw: $temp2Raw (%.2f°C)".format(temp2Raw / 100.0))
        fields.getOrPut(4) { mutableListOf() }.add(temp2Raw)

        println("    ✓ Successfully decoded 3 temperature values")

        return fields
    }

    /**
     * Read a little-endian uint16 from byte array at given offset
     */
    private fun readUint16LE(data: ByteArray, offset: Int): Long {
        if (offset + 1 >= data.size) return 0
        val low = data[offset].toInt() and 0xFF
        val high = data[offset + 1].toInt() and 0xFF
        return ((high shl 8) or low).toLong()
    }

    private fun parseProtobufGeneric(data: ByteArray, tag: Int): Map<Int, List<Long>> {
        val fields = mutableMapOf<Int, MutableList<Long>>()
        var pos = 0

        while (pos < data.size) {
            val (header, headerSize) = readVarint(data, pos)
            if (headerSize == 0) break
            pos += headerSize

            val fieldNumber = (header shr 3).toInt()
            val wireType = (header and 0x7).toInt()

            when (wireType) {
                0 -> { // Varint
                    val (value, valueSize) = readVarint(data, pos)
                    if (valueSize > 0) {
                        fields.getOrPut(fieldNumber) { mutableListOf() }.add(value)
                        pos += valueSize
                    } else {
                        break
                    }
                }
                1 -> { // 64-bit
                    if (pos + 8 <= data.size) {
                        val value = data.copyOfRange(pos, pos + 8)
                            .reversed()
                            .fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xFF) }
                        fields.getOrPut(fieldNumber) { mutableListOf() }.add(value)
                        pos += 8
                    } else {
                        break
                    }
                }
                2 -> { // Length-delimited
                    val (length, lengthSize) = readVarint(data, pos)
                    if (lengthSize == 0 || pos + lengthSize + length.toInt() > data.size) break
                    pos += lengthSize

                    // Try to parse as packed repeated field
                    val chunk = data.copyOfRange(pos, pos + length.toInt())

                    // For temp events (tag 70):
                    // - Field 1 is packed timestamps (varints)
                    // - Fields 2-8 are packed temperature floats
                    if (tag == 70) {
                        if (fieldNumber == 1) {
                            // Parse packed timestamps as varints
                            val packed = tryParsePackedRepeated(chunk)
                            if (packed.isNotEmpty()) {
                                fields.getOrPut(fieldNumber) { mutableListOf() }.addAll(packed)
                                pos += length.toInt()
                                continue
                            }
                        } else if (fieldNumber in 2..8) {
                            // Parse temperature fields as packed floats
                            val packedFloats = tryParsePackedFloats(chunk)
                            if (packedFloats.isNotEmpty()) {
                                fields.getOrPut(fieldNumber) { mutableListOf() }.addAll(packedFloats)
                                pos += length.toInt()
                                continue
                            }
                        }
                    }

                    // Generic: try packed varints
                    val packed = tryParsePackedRepeated(chunk)
                    if (packed.isNotEmpty()) {
                        fields.getOrPut(fieldNumber) { mutableListOf() }.addAll(packed)
                    } else {
                        // Store length as value if not parseable
                        fields.getOrPut(fieldNumber) { mutableListOf() }.add(length)
                    }
                    pos += length.toInt()
                }
                5 -> { // 32-bit
                    if (pos + 4 <= data.size) {
                        val value = data.copyOfRange(pos, pos + 4)
                            .reversed()
                            .fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xFF) }
                        fields.getOrPut(fieldNumber) { mutableListOf() }.add(value)
                        pos += 4
                    } else {
                        break
                    }
                }
                else -> {
                    // Unknown wire type, skip
                    break
                }
            }
        }

        return fields
    }

    private fun tryParsePackedRepeated(data: ByteArray): List<Long> {
        val values = mutableListOf<Long>()
        var pos = 0

        while (pos < data.size) {
            val (value, size) = readVarint(data, pos)
            if (size == 0) break
            values.add(value)
            pos += size
        }

        return values
    }

    private fun tryParsePackedFloats(data: ByteArray): List<Long> {
        val values = mutableListOf<Long>()
        var pos = 0

        // Each float is 4 bytes (IEEE 754 little-endian)
        while (pos + 4 <= data.size) {
            val bytes = data.copyOfRange(pos, pos + 4)
            // Convert 4-byte little-endian to float
            val intBits = (bytes[0].toInt() and 0xFF) or
                         ((bytes[1].toInt() and 0xFF) shl 8) or
                         ((bytes[2].toInt() and 0xFF) shl 16) or
                         ((bytes[3].toInt() and 0xFF) shl 24)
            val floatValue = Float.fromBits(intBits)

            // Convert to 0.01°C units for storage (multiply by 100)
            val tempValue = (floatValue * 100).toLong()
            values.add(tempValue)
            pos += 4
        }

        return if (pos == data.size) values else emptyList()
    }

    private fun readVarint(data: ByteArray, offset: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var pos = offset

        while (pos < data.size) {
            val b = data[pos].toLong() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            pos++

            if ((b and 0x80) == 0L) {
                return Pair(result, pos - offset)
            }

            shift += 7
            if (shift >= 64) break
        }

        return Pair(0, 0)
    }

    /**
     * Calculate UTC timestamp from ring timestamp using stored TIME_SYNC point
     * Formula: eventUTC_ms = syncUTC_ms - ((syncRingTime_decisec - eventRingTime_decisec) * 100)
     *
     * @param eventRingTimestamp Ring timestamp in DECISECONDS (raw value from event bytes 2-5)
     * @return UTC timestamp in milliseconds, or null if no TIME_SYNC point stored
     */
    private fun calculateUtcFromRingTime(eventRingTimestamp: Long): Long? {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val syncRingTimeDeciseconds = prefs.getLong(PREF_SYNC_RING_TIME, -1)
        val syncUtcTimeMillis = prefs.getLong(PREF_SYNC_UTC_TIME, -1)

        if (syncRingTimeDeciseconds == -1L || syncUtcTimeMillis == -1L) {
            return null  // No TIME_SYNC point stored yet
        }

        // Both timestamps are in deciseconds - no conversion needed
        val eventRingTimeDeciseconds = eventRingTimestamp

        // Calculate UTC: syncUTC - (syncRingTime - eventRingTime) * 100ms
        val timeDiffDeciseconds = syncRingTimeDeciseconds - eventRingTimeDeciseconds
        val eventUtcMillis = syncUtcTimeMillis - (timeDiffDeciseconds * 100)

        return eventUtcMillis
    }

    /**
     * Format UTC timestamp as "d.M.yyyy HH:mm" (e.g., "5.1.2025 14:30")
     */
    private fun formatUtcTimestamp(utcMillis: Long): String {
        val date = java.util.Date(utcMillis)
        val formatter = java.text.SimpleDateFormat("d.M.yyyy HH:mm", java.util.Locale.getDefault())
        formatter.timeZone = java.util.TimeZone.getTimeZone("UTC")
        return formatter.format(date)
    }
}
