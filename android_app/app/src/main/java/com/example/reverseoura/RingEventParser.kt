package com.example.reverseoura

import android.util.Log

/**
 * Wrapper for Oura's native libringeventparser.so library
 *
 * This loads the original Oura library to parse ring events.
 */
class RingEventParser {

    companion object {
        private const val TAG = "RingEventParser"

        init {
            try {
                // Load our C++ JNI bridge (which internally uses dlopen to access libringeventparser.so)
                System.loadLibrary("ringeventparser_jni")
                Log.d(TAG, "✓ Native JNI bridge loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "✗ Failed to load JNI bridge: ${e.message}")
            }
        }
    }

    /**
     * Parse ring events using Oura's native parser
     *
     * Based on decompiled RingEventParserObj.java:
     * native RingData nativeParseEvents(byte[] ringEvents, int ringTime, long utcTime, boolean jzLogMode)
     *
     * @param ringEvents Concatenated event bytes (all events together)
     * @param ringTime Ring's internal timestamp (from TIME_INFO event)
     * @param utcTime Current UTC time in milliseconds
     * @param debugMode Enable debug logging (use false for production)
     * @return Parsed data structure (will be complex C++ object)
     */
    private external fun nativeParseEvents(
        ringEvents: ByteArray,
        ringTime: Int,
        utcTime: Long,
        debugMode: Boolean
    ): Any?

    /**
     * Parse a batch of ring events
     *
     * @param events List of individual event byte arrays
     * @param ringTime Ring timestamp (seconds since ring boot)
     * @param utcTime Current UTC timestamp (milliseconds)
     * @return Parsed result or null if parsing fails
     */
    fun parseEvents(events: List<ByteArray>, ringTime: Int = 0, utcTime: Long = System.currentTimeMillis()): Any? {
        if (events.isEmpty()) {
            Log.w(TAG, "No events to parse")
            return null
        }

        // Concatenate all events into single byte array (as Oura does)
        val totalSize = events.sumOf { it.size }
        val concatenated = ByteArray(totalSize)
        var offset = 0

        Log.d(TAG, "╔═══════════════════════════════════════════════════════════╗")
        Log.d(TAG, "║ RING EVENT PARSER - parseEvents()                        ║")
        Log.d(TAG, "╚═══════════════════════════════════════════════════════════╝")
        Log.d(TAG, "Number of events: ${events.size}")
        Log.d(TAG, "Total concatenated size: $totalSize bytes")
        Log.d(TAG, "Ring time: $ringTime")
        Log.d(TAG, "UTC time: $utcTime")

        for ((i, event) in events.withIndex()) {
            Log.d(TAG, "  Event $i: ${event.size}b - ${event.take(16).joinToString(" ") { "%02x".format(it) }}${if (event.size > 16) "..." else ""}")
            System.arraycopy(event, 0, concatenated, offset, event.size)
            offset += event.size
        }

        Log.d(TAG, "Concatenated hex (first 64b): ${concatenated.take(64).joinToString(" ") { "%02x".format(it) }}${if (concatenated.size > 64) "..." else ""}")
        Log.d(TAG, "─".repeat(60))
        Log.d(TAG, "Calling nativeParseEvents()...")

        return try {
            val result = nativeParseEvents(concatenated, ringTime, utcTime, false)
            Log.d(TAG, "─".repeat(60))
            Log.d(TAG, "✓ nativeParseEvents() completed")
            Log.d(TAG, "Result: ${result?.javaClass?.name ?: "null"}")
            if (result != null) {
                Log.d(TAG, "Result toString: $result")
            }
            Log.d(TAG, "╚═══════════════════════════════════════════════════════════╝")
            result
        } catch (e: Exception) {
            Log.e(TAG, "─".repeat(60))
            Log.e(TAG, "✗ Native parsing failed: ${e.message}")
            Log.e(TAG, "Exception: ${e.javaClass.name}")
            e.printStackTrace()
            Log.e(TAG, "╚═══════════════════════════════════════════════════════════╝")
            null
        }
    }

    /**
     * Parse a single event
     */
    fun parseEvent(event: ByteArray, ringTime: Int = 0): Any? {
        Log.d(TAG, "→ parseEvent() wrapper - calling parseEvents() with single event")
        Log.d(TAG, "  Event size: ${event.size} bytes")
        Log.d(TAG, "  Event hex: ${event.joinToString(" ") { "%02x".format(it) }}")
        return parseEvents(listOf(event), ringTime)
    }

    /**
     * Call C++ EventParser::parse_api_sleep_period_info directly
     *
     * @param eventBytes Raw event bytes (16 bytes for event 0x6a)
     * @return FloatArray with 9 parsed values, or null if parsing fails
     */
    private external fun nativeParseSleepPeriodInfo(eventBytes: ByteArray): FloatArray?

    /**
     * Parse event 0x6A (SLEEP_PERIOD_INFO) using native C++ function
     */
    fun parseSleepPeriodInfoNative(eventBytes: ByteArray): FloatArray? {
        Log.d(TAG, "Calling native parse_api_sleep_period_info")
        Log.d(TAG, "  Event hex: ${eventBytes.joinToString(" ") { "%02x".format(it) }}")
        return try {
            nativeParseSleepPeriodInfo(eventBytes)
        } catch (e: Exception) {
            Log.e(TAG, "Native parsing failed: ${e.message}")
            null
        }
    }
}
