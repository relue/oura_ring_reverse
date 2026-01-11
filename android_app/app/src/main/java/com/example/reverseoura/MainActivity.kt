package com.example.reverseoura

import android.Manifest
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {

    companion object {
        private const val REQUEST_PERMISSIONS = 1001
        private const val TAG = "ReverseOura"
        const val ACTION_COMMAND = "com.example.reverseoura.COMMAND"
    }

    // ADB Broadcast Receiver for remote control
    private val commandReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val cmd = intent?.getStringExtra("cmd") ?: return
            Log.d(TAG, "ADB Command received: $cmd")
            log("📡 ADB Command: $cmd")

            when (cmd.lowercase()) {
                "scan", "connect" -> {
                    Log.d(TAG, "Executing: connectToRing()")
                    connectToRing()
                }
                "auth" -> {
                    Log.d(TAG, "Executing: performAuthentication()")
                    if (isConnected) performAuthentication()
                    else log("❌ Not connected")
                }
                "heartbeat", "start_hb" -> {
                    Log.d(TAG, "Executing: startHeartbeatCapture()")
                    if (isConnected && isAuthenticated) startHeartbeatCapture()
                    else log("❌ Not connected/authenticated")
                }
                "stop", "stop_hb" -> {
                    Log.d(TAG, "Executing: stopMonitoring()")
                    stopMonitoring()
                }
                "data", "get_data" -> {
                    Log.d(TAG, "Executing: getDataFromRing()")
                    if (isConnected && isAuthenticated) getDataFromRing()
                    else log("❌ Not connected/authenticated")
                }
                "sleep", "get_sleep" -> {
                    Log.d(TAG, "Executing: getSleepDataFromRing()")
                    if (isConnected && isAuthenticated) getSleepDataFromRing()
                    else log("❌ Not connected/authenticated")
                }
                "status" -> {
                    val status = "Connected: $isConnected, Authenticated: $isAuthenticated, HB Count: $heartbeatCount"
                    Log.d(TAG, "Status: $status")
                    log("📊 $status")
                }
                "disconnect" -> {
                    Log.d(TAG, "Executing: disconnect")
                    bluetoothGatt?.disconnect()
                    bluetoothGatt?.close()
                    isConnected = false
                    isAuthenticated = false
                    log("🔌 Disconnected")
                }
                "setauth", "set_auth_key" -> {
                    Log.d(TAG, "Executing: testSetAuthKey()")
                    testSetAuthKey()
                }
                "synctime", "sync_time" -> {
                    Log.d(TAG, "Executing: sendTimeSyncRequest()")
                    if (isConnected && isAuthenticated) sendTimeSyncRequest()
                    else log("❌ Not connected/authenticated")
                }
                "factoryreset", "factory_reset" -> {
                    Log.d(TAG, "Executing: sendFactoryReset()")
                    sendFactoryReset()
                }
                else -> {
                    // Check for set_key:HEXKEY command to set auth key without writing to ring
                    if (cmd.startsWith("set_key:")) {
                        val hexKey = cmd.substringAfter("set_key:").replace(" ", "")
                        try {
                            val keyBytes = hexKey.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                            if (keyBytes.size == 16) {
                                currentAuthKey = keyBytes
                                saveAuthKey()
                                updateAuthKeyUI()
                                log("✅ Auth key set: ${keyBytes.joinToString(" ") { "%02x".format(it) }}")
                            } else {
                                log("❌ Key must be 16 bytes (32 hex chars)")
                            }
                        } catch (e: Exception) {
                            log("❌ Invalid hex key: $hexKey")
                        }
                    } else if (cmd.startsWith("send_hex:")) {
                        val hexStr = cmd.substringAfter("send_hex:")
                        try {
                            val bytes = hexStr.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                            Log.d(TAG, "Sending hex command: $hexStr")
                            sendCommand(bytes)
                        } catch (e: Exception) {
                            log("❌ Invalid hex: $hexStr")
                        }
                    } else {
                        log("❓ Unknown command: $cmd")
                    }
                }
            }
        }
    }

    // BLE UUIDs (from reverse engineering)
    private val SERVICE_UUID = UUID.fromString("98ed0001-a541-11e4-b6a0-0002a5d5c51b")
    private val WRITE_CHAR_UUID = UUID.fromString("98ed0002-a541-11e4-b6a0-0002a5d5c51b")
    private val NOTIFY_CHAR_UUID = UUID.fromString("98ed0003-a541-11e4-b6a0-0002a5d5c51b")

    // Oura Ring address (from your device)
    private val OURA_ADDRESS = "5F:1F:30:5E:19:EC"

    // Current auth key (loaded from storage or set via SetAuthKey)
    // No default - must be set via SetAuthKey or loaded from storage
    private var currentAuthKey: ByteArray? = null

    // SharedPreferences keys for persistent storage
    private val PREFS_NAME = "OuraRingPrefs"
    private val PREF_AUTH_KEY = "auth_key"
    private val PREF_SYNC_RING_TIME = "sync_ring_time_deciseconds"
    private val PREF_SYNC_UTC_TIME = "sync_utc_time_millis"

    // Authentication commands
    private val CMD_GET_AUTH_NONCE = byteArrayOf(0x2f, 0x01, 0x2b)

    // SetAuthKey command (for writing new auth key to ring)
    private val CMD_SET_AUTH_KEY_TAG = 0x24.toByte()
    private val CMD_SET_AUTH_KEY_SUBCMD = 0x10.toByte()

    // Factory Reset command (clears ring memory including auth key)
    private val CMD_FACTORY_RESET = byteArrayOf(0x1a, 0x00)

    // Init commands (sent after authentication)
    private val CMD_INIT_1 = byteArrayOf(0x2f, 0x02, 0x20, 0x02)
    private val CMD_INIT_2 = byteArrayOf(0x2f, 0x03, 0x22, 0x02, 0x03)
    private val CMD_START_STREAM = byteArrayOf(0x2f, 0x03, 0x26, 0x02, 0x02)
    private val CMD_STOP = byteArrayOf(0x2f, 0x03, 0x22, 0x02, 0x01)

    private lateinit var bluetoothAdapter: BluetoothAdapter
    private var bluetoothGatt: BluetoothGatt? = null
    private var writeCharacteristic: BluetoothGattCharacteristic? = null
    private var notifyCharacteristic: BluetoothGattCharacteristic? = null

    private lateinit var authKeyText: TextView
    private lateinit var ringMacText: TextView
    private lateinit var statusText: TextView
    private lateinit var bpmText: TextView
    private lateinit var ibiText: TextView
    private lateinit var countText: TextView
    private lateinit var debugLog: TextView
    private lateinit var connectButton: Button
    private lateinit var authRefreshButton: Button
    private lateinit var getDataButton: Button
    private lateinit var getSleepDataButton: Button
    private lateinit var showDataButton: Button
    private lateinit var startHbCaptureButton: Button
    private lateinit var stopHbCaptureButton: Button
    private lateinit var clearLogButton: Button
    private lateinit var testSetAuthKeyButton: Button
    private lateinit var syncTimeButton: Button
    private lateinit var factoryResetButton: Button

    private var heartbeatCount = 0
    private var scanCallback: ScanCallback? = null
    private var isScanning = false
    private val scanHandler = android.os.Handler(android.os.Looper.getMainLooper())

    // Authentication state
    private var isAuthenticated = false
    private var authNonce: ByteArray? = null

    // Track pending SetAuthKey operation
    private var pendingNewAuthKey: ByteArray? = null

    // Init sequence state tracking (for ACK-based flow)
    private enum class InitState {
        IDLE,
        WAITING_FOR_INIT1_ACK,
        WAITING_FOR_INIT2_ACK,
        WAITING_FOR_START_STREAM_ACK,
        MONITORING_ACTIVE
    }
    private var initState = InitState.IDLE

    // Connection state tracking
    private var isConnected = false
    private var pendingOperation: (() -> Unit)? = null

    // Event data retrieval tracking
    private var eventCount = 0
    private var totalEventsReceived = 0
    private val eventData = mutableListOf<ByteArray>()

    // Event blacklist (empty = store all event types)
    private val eventBlacklist = setOf(0x43, 0x61)  // Event types to EXCLUDE

    // Sleep event whitelist (for FETCHING_SLEEP mode only)
    private val sleepEventWhitelist = setOf(
        0x48,  // SLEEP_PERIOD_INFO
        0x49,  // SLEEP_SUMMARY_1
        0x4B,  // SLEEP_PHASE_INFO
        0x4C,  // SLEEP_SUMMARY_2
        0x4D,  // RING_SLEEP_FEATURE_INFO
        0x4E,  // SLEEP_PHASE_DETAILS
        0x4F,  // SLEEP_SUMMARY_3
        0x55,  // SLEEP_HR
        0x57,  // RING_SLEEP_FEATURE_INFO_2
        0x58,  // SLEEP_SUMMARY_4
        0x5A,  // SLEEP_PHASE_DATA
        0x6a,  // SLEEP_PERIOD_INFO_2
        0x72,  // SLEEP_ACM_PERIOD
        0x75,  // SLEEP_TEMP_EVENT
        0x76   // BEDTIME_PERIOD
    )

    // Target events to fetch (will go back target_events * 70 sequence numbers)
    private val targetEvents = 3000
    private val maxEventsToKeep = targetEvents * 70  // Approx 70 seq nums per event (after blacklist)

    // Continuous fetch tracking
    private var currentSeqNum: Long = 0  // Current event sequence number
    private var bytesLeft: Long = -1  // -1 = not started, 0 = sync complete, >0 = continue
    private var batchSize = 0  // 0 = fetch ALL remaining events after sequence number

    // Binary search probing state
    private enum class FetchMode {
        PROBING,         // Binary search to find last event
        FETCHING,        // Fetch actual data (all event types)
        FETCHING_SLEEP   // Fetch and filter only sleep-related events
    }
    private var fetchMode = FetchMode.PROBING
    private var probeLow: Long = 0
    private var probeHigh: Long = 100000  // Initial high guess
    private var lastValidSeq: Long = -1  // Last sequence number that returned events

    // Sleep statistics
    private data class SleepStats(
        var totalSleepEvents: Int = 0,
        var sleepPhaseDataEvents: Int = 0,
        var sleepHrEvents: Int = 0,
        var sleepTempEvents: Int = 0,
        var sleepSummaryEvents: Int = 0,
        var otherEvents: Int = 0
    )

    // SLEEP_PERIOD_INFO_2 (0x6a) decoder tracking
    private var hasDecodedFirstSleepPeriodInfo = false

    // Stop control for event fetching
    private var shouldStopFetching = false
    private var stopAfterEventType: Int? = null  // Event type to stop after (e.g., 0x6a)
    private var stopAfterEventCount: Int = 1  // Number of target events to collect before stopping
    private var targetEventCounter: Int = 0  // Counter for target event type

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize UI
        authKeyText = findViewById(R.id.authKeyText)
        ringMacText = findViewById(R.id.ringMacText)
        statusText = findViewById(R.id.statusText)
        bpmText = findViewById(R.id.bpmText)
        ibiText = findViewById(R.id.ibiText)
        countText = findViewById(R.id.countText)
        debugLog = findViewById(R.id.debugLog)
        connectButton = findViewById(R.id.connectButton)
        authRefreshButton = findViewById(R.id.authRefreshButton)
        getDataButton = findViewById(R.id.getDataButton)
        getSleepDataButton = findViewById(R.id.getSleepDataButton)
        showDataButton = findViewById(R.id.showDataButton)
        startHbCaptureButton = findViewById(R.id.startHbCaptureButton)
        stopHbCaptureButton = findViewById(R.id.stopHbCaptureButton)
        clearLogButton = findViewById(R.id.clearLogButton)
        testSetAuthKeyButton = findViewById(R.id.testSetAuthKeyButton)
        syncTimeButton = findViewById(R.id.syncTimeButton)
        factoryResetButton = findViewById(R.id.factoryResetButton)

        // Load saved auth key from storage
        loadAuthKey()

        // Display initial auth key
        updateAuthKeyUI()

        // Display ring MAC address (last 3 octets)
        updateRingMacUI()

        // Bluetooth setup
        val bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        log("MainActivity created")
        log("Bluetooth adapter: ${if (::bluetoothAdapter.isInitialized) "OK" else "NOT FOUND"}")

        // Register ADB command receiver
        val filter = IntentFilter(ACTION_COMMAND)
        registerReceiver(commandReceiver, filter, Context.RECEIVER_EXPORTED)
        Log.d(TAG, "ADB command receiver registered")
        log("📡 ADB receiver ready - use: adb shell am broadcast -a $ACTION_COMMAND --es cmd \"<command>\"")

        // Check permissions
        checkPermissions()

        connectButton.setOnClickListener {
            log("=== CONNECT BUTTON CLICKED ===")
            connectToRing()
        }

        authRefreshButton.setOnClickListener {
            log("=== AUTH REFRESH BUTTON CLICKED ===")
            if (isConnected) {
                performAuthentication()
            } else {
                log("❌ Not connected! Click Connect first.")
            }
        }

        getDataButton.setOnClickListener {
            log("=== GET DATA BUTTON CLICKED ===")
            if (isConnected && isAuthenticated) {
                getDataFromRing()
            } else {
                log("❌ Not connected or not authenticated!")
                log("   Connected: $isConnected, Authenticated: $isAuthenticated")
            }
        }

        getSleepDataButton.setOnClickListener {
            log("=== GET SLEEP DATA BUTTON CLICKED ===")
            if (isConnected && isAuthenticated) {
                getSleepDataFromRing()
            } else {
                log("❌ Not connected or not authenticated!")
                log("   Connected: $isConnected, Authenticated: $isAuthenticated")
            }
        }

        showDataButton.setOnClickListener {
            log("=== SHOW DATA BUTTON CLICKED ===")
            if (eventData.isEmpty()) {
                log("⚠️ No event data available. Click 'Get Data' first!")
                runOnUiThread {
                    statusText.text = "No data yet"
                    bpmText.text = "GET DATA\nFIRST"
                }
            } else {
                // Pass data to DataBrowserActivity and launch it
                DataBrowserActivity.eventData = eventData
                val intent = Intent(this, DataBrowserActivity::class.java)
                startActivity(intent)
                log("📱 Launched Data Browser with ${eventData.size} events")
            }
        }

        startHbCaptureButton.setOnClickListener {
            log("=== START HB CAPTURE BUTTON CLICKED ===")
            if (isConnected && isAuthenticated) {
                startHeartbeatCapture()
            } else {
                log("❌ Not connected or not authenticated!")
                log("   Connected: $isConnected, Authenticated: $isAuthenticated")
            }
        }

        stopHbCaptureButton.setOnClickListener {
            log("=== STOP HB CAPTURE BUTTON CLICKED ===")
            stopMonitoring()
        }

        clearLogButton.setOnClickListener {
            debugLog.text = ""
            log("Log cleared")
        }

        testSetAuthKeyButton.setOnClickListener {
            log("⚠️  Test SetAuthKey button clicked!")
            testSetAuthKey()
        }

        syncTimeButton.setOnClickListener {
            log("=== SYNC TIME BUTTON CLICKED ===")
            if (isConnected && isAuthenticated) {
                sendTimeSyncRequest()
            } else {
                log("❌ Not connected or not authenticated!")
                log("   Connected: $isConnected, Authenticated: $isAuthenticated")
            }
        }

        factoryResetButton.setOnClickListener {
            log("⚠️  Factory Reset button clicked!")
            log("⚠️  This will WIPE the ring's memory including auth key!")
            sendFactoryReset()
        }
    }

    private fun log(message: String) {
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US).format(java.util.Date())

        // Log to Android system log (visible in logcat)
        android.util.Log.d("OuraRing", message)

        // Also show in UI
        runOnUiThread {
            debugLog.append("[$timestamp] $message\n")
            // Auto-scroll to bottom
            (debugLog.parent as? android.widget.ScrollView)?.fullScroll(android.view.View.FOCUS_DOWN)
        }
    }

    private fun updateAuthKeyUI() {
        val keyHex = currentAuthKey?.joinToString(" ") { "%02x".format(it) } ?: "NOT SET - Use SetAuthKey button"
        runOnUiThread {
            authKeyText.text = keyHex
        }
        if (currentAuthKey != null) {
            log("Current auth key: $keyHex")
        } else {
            log("⚠️  No auth key set! Use SetAuthKey to write a key to the ring")
        }
    }

    private fun updateRingMacUI() {
        // Extract last 3 octets from MAC address for "short mac"
        val macParts = OURA_ADDRESS.split(":")
        val shortMac = macParts.takeLast(3).joinToString(":")
        runOnUiThread {
            ringMacText.text = shortMac
        }
        log("Ring MAC (short): $shortMac | Full: $OURA_ADDRESS")
    }

    private fun loadAuthKey() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val savedKeyHex = prefs.getString(PREF_AUTH_KEY, null)

        if (savedKeyHex != null) {
            try {
                val keyBytes = savedKeyHex.split(" ").map { it.toInt(16).toByte() }.toByteArray()
                if (keyBytes.size == 16) {
                    currentAuthKey = keyBytes
                    log("✅ Loaded auth key from storage")
                } else {
                    log("⚠️  Saved auth key has wrong length")
                }
            } catch (e: Exception) {
                log("⚠️  Failed to parse saved auth key: ${e.message}")
            }
        } else {
            log("ℹ️  No saved auth key found")
        }
    }

    private fun saveAuthKey() {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        if (currentAuthKey != null) {
            val keyHex = currentAuthKey!!.joinToString(" ") { "%02x".format(it) }
            prefs.edit().putString(PREF_AUTH_KEY, keyHex).apply()
            log("💾 Saved auth key to storage")
        } else {
            prefs.edit().remove(PREF_AUTH_KEY).apply()
            log("💾 Cleared saved auth key from storage")
        }
    }

    /**
     * Save TIME_SYNC synchronization point (ring time in deciseconds, UTC time in milliseconds)
     */
    private fun saveTimeSyncPoint(ringTimeDeciseconds: Long, utcTimeMillis: Long) {
        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        prefs.edit()
            .putLong(PREF_SYNC_RING_TIME, ringTimeDeciseconds)
            .putLong(PREF_SYNC_UTC_TIME, utcTimeMillis)
            .apply()
        log("💾 Saved TIME_SYNC point: ring=$ringTimeDeciseconds decisec, utc=$utcTimeMillis ms")
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
        val date = Date(utcMillis)
        val formatter = java.text.SimpleDateFormat("d.M.yyyy HH:mm", Locale.getDefault())
        formatter.timeZone = TimeZone.getTimeZone("UTC")
        return formatter.format(date)
    }

    private fun checkPermissions() {
        log("Checking permissions...")
        val permissions = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            // Android 12+ (API 31+)
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        } else {
            // Android 11 and below - only need location
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        }

        val missing = permissions.filter {
            ActivityCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missing.isNotEmpty()) {
            log("Missing permissions: ${missing.joinToString()}")
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), 1)
        } else {
            log("All permissions granted")
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        if (requestCode == REQUEST_PERMISSIONS) {
            val granted = grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            log("Permission result: ${if (granted) "GRANTED" else "DENIED"}")

            if (granted) {
                log("All permissions granted")
                // Don't auto-connect - let user click Connect button
            } else {
                statusText.text = "Permissions denied"
                log("ERROR: User denied permissions")
            }
        }
    }

    private fun connectToRing() {
        log("=== CONNECT TO RING ===")

        // Check and request permissions based on Android version
        val neededPermissions = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            // Android 12+ (API 31+)
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        } else {
            // Android 11 and below
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        }

        val missing = neededPermissions.filter {
            ActivityCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missing.isNotEmpty()) {
            log("Requesting permissions: ${missing.joinToString()}")
            log("Android version: ${android.os.Build.VERSION.SDK_INT}")
            statusText.text = "Requesting permissions..."
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), REQUEST_PERMISSIONS)
            return
        }

        statusText.text = "Scanning for Oura Ring..."
        heartbeatCount = 0
        updateUI(0.0, 0)

        // Check permission for scanning (version-specific)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
                log("ERROR: Missing BLUETOOTH_SCAN permission")
                statusText.text = "Missing Bluetooth permissions"
                return
            }
        }

        if (isScanning) {
            log("Already scanning - ignoring start request")
            return
        }

        log("Starting BLE scan for Oura Ring (name contains 'Oura' or MAC: $OURA_ADDRESS)")
        val scanner = bluetoothAdapter.bluetoothLeScanner

        if (scanner == null) {
            log("ERROR: BLE scanner is null - Bluetooth might be off")
            statusText.text = "Bluetooth not available"
            return
        }

        isScanning = true
        val foundDevices = mutableSetOf<String>()

        scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val device = result.device
                val rssi = result.rssi

                // Only log each unique device once
                if (!foundDevices.contains(device.address)) {
                    foundDevices.add(device.address)
                    log("Found device: ${device.address} (${device.name ?: "unnamed"}) RSSI: $rssi")
                }

                // Check for Oura Ring by MAC or name
                if (device.address == OURA_ADDRESS || device.name?.contains("Oura", ignoreCase = true) == true) {
                    log(">>> OURA RING FOUND! <<<")
                    log("    Address: ${device.address}")
                    log("    Name: ${device.name ?: "unnamed"}")
                    stopScan(scanner)
                    connectToDevice(device)
                }
            }

            override fun onScanFailed(errorCode: Int) {
                log("ERROR: Scan failed with code: $errorCode")
                runOnUiThread { statusText.text = "Scan failed" }
                isScanning = false
            }
        }

        scanner.startScan(scanCallback)
        log("BLE scan started - will timeout in 10 seconds")

        // Timeout after 10 seconds
        scanHandler.postDelayed({
            if (isScanning) {
                log("Scan timeout - Oura Ring not found")
                stopScan(scanner)
                runOnUiThread {
                    statusText.text = "Oura Ring not found"
                }
            }
        }, 10000)

        // Also check bonded devices
        try {
            val bondedDevices = bluetoothAdapter.bondedDevices
            log("Checking ${bondedDevices.size} bonded devices...")
            bondedDevices.forEach { device ->
                log("  Bonded: ${device.address} - ${device.name ?: "unnamed"}")
                if (device.address == OURA_ADDRESS || device.name?.contains("Oura", ignoreCase = true) == true) {
                    log(">>> FOUND BONDED OURA RING: ${device.address} <<<")
                    stopScan(scanner)
                    connectToDevice(device)
                }
            }
        } catch (e: Exception) {
            log("Error checking bonded devices: ${e.message}")
        }
    }

    private fun stopScan(scanner: android.bluetooth.le.BluetoothLeScanner) {
        if (isScanning && scanCallback != null) {
            try {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                    if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED) {
                        scanner.stopScan(scanCallback)
                    }
                } else {
                    scanner.stopScan(scanCallback)
                }
                log("Scan stopped")
            } catch (e: Exception) {
                log("Error stopping scan: ${e.message}")
            }
            isScanning = false
            scanHandler.removeCallbacksAndMessages(null)
        }
    }

    private fun connectToDevice(device: BluetoothDevice) {
        log("Connecting to device: ${device.address}")
        statusText.text = "Connecting to ${device.address}..."

        // Check BLUETOOTH_CONNECT only on Android 12+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                statusText.text = "Missing Bluetooth permissions"
                log("ERROR: Missing BLUETOOTH_CONNECT permission")
                return
            }
        }

        // Check bond state and initiate pairing if needed
        val bondState = device.bondState
        log("Device bond state: $bondState (${getBondStateString(bondState)})")

        when (bondState) {
            BluetoothDevice.BOND_NONE -> {
                log("⚠️  Device not bonded - initiating pairing...")
                log("⚠️  Android OS will show pairing dialog")
                statusText.text = "Starting pairing process..."

                // This will trigger OS pairing dialog
                val bondResult = device.createBond()
                log("createBond() result: $bondResult")

                if (bondResult) {
                    log("✅ Pairing initiated - waiting for user to accept...")
                    statusText.text = "Accept pairing dialog..."

                    // Wait for bonding to complete before connecting
                    android.os.Handler(mainLooper).postDelayed({
                        log("Checking bond state after pairing...")
                        if (device.bondState == BluetoothDevice.BOND_BONDED) {
                            log("✅ Device successfully bonded!")
                            proceedWithConnection(device)
                        } else {
                            log("⚡ Pairing not complete yet - retrying check...")
                            // Give more time and retry
                            android.os.Handler(mainLooper).postDelayed({
                                log("Final bond state check...")
                                if (device.bondState == BluetoothDevice.BOND_BONDED) {
                                    log("✅ Device successfully bonded!")
                                    proceedWithConnection(device)
                                } else {
                                    log("❌ Pairing failed or not completed")
                                    statusText.text = "Pairing failed"
                                }
                            }, 10000) // Wait another 10 seconds
                        }
                    }, 5000) // Initial 5 second wait
                    return
                } else {
                    log("❌ Failed to initiate bonding")
                    statusText.text = "Bonding failed"
                    return
                }
            }
            BluetoothDevice.BOND_BONDING -> {
                log("⚡ Device is currently bonding - waiting...")
                statusText.text = "Bonding in progress..."
                android.os.Handler(mainLooper).postDelayed({
                    connectToDevice(device) // Retry
                }, 2000)
                return
            }
            BluetoothDevice.BOND_BONDED -> {
                log("✅ Device already bonded - proceeding with connection")
            }
        }

        proceedWithConnection(device)
    }

    private fun getBondStateString(state: Int): String {
        return when (state) {
            BluetoothDevice.BOND_NONE -> "BOND_NONE"
            BluetoothDevice.BOND_BONDING -> "BOND_BONDING"
            BluetoothDevice.BOND_BONDED -> "BOND_BONDED"
            else -> "UNKNOWN"
        }
    }

    private fun proceedWithConnection(device: BluetoothDevice) {
        log("Proceeding with GATT connection...")
        statusText.text = "Connecting..."

        // Check BLUETOOTH_CONNECT only on Android 12+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                statusText.text = "Missing Bluetooth permissions"
                log("ERROR: Missing BLUETOOTH_CONNECT permission")
                return
            }
        }

        bluetoothGatt = device.connectGatt(this, false, object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                log("Connection state changed: status=$status, newState=$newState")

                when (newState) {
                    BluetoothProfile.STATE_CONNECTED -> {
                        log(">>> CONNECTED <<<")
                        runOnUiThread { statusText.text = "Connected! Discovering services..." }
                        log("Starting service discovery...")
                        gatt.discoverServices()
                    }
                    BluetoothProfile.STATE_DISCONNECTED -> {
                        log(">>> DISCONNECTED <<<")
                        isConnected = false
                        runOnUiThread { statusText.text = "Disconnected" }
                    }
                    BluetoothProfile.STATE_CONNECTING -> {
                        log("Connecting...")
                    }
                    BluetoothProfile.STATE_DISCONNECTING -> {
                        log("Disconnecting...")
                    }
                }
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                log("Services discovered: status=$status (${if (status == BluetoothGatt.GATT_SUCCESS) "SUCCESS" else "FAILED"})")

                if (status == BluetoothGatt.GATT_SUCCESS) {
                    log("Found ${gatt.services.size} services")
                    gatt.services.forEach { service ->
                        log("  Service: ${service.uuid}")
                    }

                    val service = gatt.getService(SERVICE_UUID)
                    if (service == null) {
                        log("ERROR: Oura service not found!")
                        return
                    }
                    log(">>> Oura service found: $SERVICE_UUID")

                    writeCharacteristic = service.getCharacteristic(WRITE_CHAR_UUID)
                    notifyCharacteristic = service.getCharacteristic(NOTIFY_CHAR_UUID)

                    log("Write characteristic: ${if (writeCharacteristic != null) "FOUND" else "NOT FOUND"}")
                    log("Notify characteristic: ${if (notifyCharacteristic != null) "FOUND" else "NOT FOUND"}")

                    if (notifyCharacteristic == null) {
                        log("ERROR: Notify characteristic not found!")
                        return
                    }

                    // Enable notifications
                    log("Enabling notifications on ${notifyCharacteristic?.uuid}")
                    val notifEnabled = gatt.setCharacteristicNotification(notifyCharacteristic, true)
                    log("setCharacteristicNotification: ${if (notifEnabled) "SUCCESS" else "FAILED"}")

                    val descriptor = notifyCharacteristic?.getDescriptor(
                        UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
                    )
                    if (descriptor == null) {
                        log("ERROR: CCCD descriptor not found!")
                        return
                    }

                    log("Writing CCCD descriptor to enable notifications...")
                    descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    val writeSuccess = gatt.writeDescriptor(descriptor)
                    log("writeDescriptor: ${if (writeSuccess) "QUEUED" else "FAILED"}")
                } else {
                    log("ERROR: Service discovery failed")
                }
            }

            override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
                log("Descriptor write: status=$status (${if (status == BluetoothGatt.GATT_SUCCESS) "SUCCESS" else "FAILED"})")
                log(">>> Notifications enabled! <<<")

                // Mark as connected
                isConnected = true

                // Execute pending operation if any (SetAuthKey or Factory Reset)
                if (pendingOperation != null) {
                    log("Executing pending operation...")
                    val operation = pendingOperation
                    pendingOperation = null
                    operation?.invoke()
                } else {
                    // Connection successful - wait for user to click Auth Refresh or Start HB Capture
                    runOnUiThread { statusText.text = "Connected - Ready for commands" }
                    log(">>> CONNECTION COMPLETE <<<")
                    log("Use Auth Refresh button to authenticate, then Start HB Capture to begin monitoring")
                }
            }

            override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
                log("Characteristic write: status=$status (${if (status == BluetoothGatt.GATT_SUCCESS) "SUCCESS" else "FAILED"})")
            }

            // OLD API (Android < 13) - characteristic.value
            @Deprecated("Deprecated in API 33")
            override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
                log("onCharacteristicChanged (OLD API) called")
                val data = characteristic.value
                handleNotification(characteristic, data)
            }

            // NEW API (Android 13+) - value as parameter
            override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
                log("onCharacteristicChanged (NEW API) called")
                handleNotification(characteristic, value)
            }

            private fun handleNotification(characteristic: BluetoothGattCharacteristic, data: ByteArray?) {
                // STOP GUARD: Silently drop ALL notifications if stop condition met
                if (shouldStopFetching && data != null && data.isNotEmpty()) {
                    // Check if this is a GetEvent notification (0x11 or >= 0x41)
                    if (data[0] == 0x11.toByte() || (data[0].toInt() and 0xFF) >= 0x41) {
                        // Silently ignore - no logging to avoid spam
                        return
                    }
                }

                if (data == null) {
                    log("RX: <NULL DATA>")
                    return
                }

                val hexString = data.joinToString(" ") { "%02x".format(it) }
                log("========================================")
                log("RX NOTIFICATION: ${data.size} bytes")
                log("RAW HEX: $hexString")
                log("Characteristic: ${characteristic.uuid}")

                // Print indexed hex dump for clarity
                val indexed = data.mapIndexed { index, byte ->
                    "[$index]=0x%02x".format(byte)
                }.joinToString(" ")
                log("INDEXED: $indexed")
                log("========================================")

                // Check for SetAuthKey response first (tag 0x25)
                if (data.size >= 3 && data[0] == 0x25.toByte() && data[1] == 0x01.toByte()) {
                    log("╔═══════════════════════════════════════════════════╗")
                    log("║  SET AUTH KEY RESPONSE FROM RING                  ║")
                    log("╚═══════════════════════════════════════════════════╝")

                    val status = data[2].toInt() and 0xFF
                    log("  📥 RESPONSE (${data.size} bytes): $hexString")
                    log("  🔍 BREAKDOWN:")
                    log("     Byte 0 (Tag):    0x%02x (expected 0x25)".format(data[0]))
                    log("     Byte 1 (Subcmd): 0x%02x (expected 0x01)".format(data[1]))
                    log("     Byte 2 (Status): 0x%02x".format(data[2]))

                    if (status == 0) {
                        log("  ✅ SetAuthKey SUCCESS!")
                        log("  → New auth key accepted and stored in ring")

                        // Update currentAuthKey with the new key that was accepted
                        if (pendingNewAuthKey != null) {
                            currentAuthKey = pendingNewAuthKey!!.copyOf()
                            pendingNewAuthKey = null

                            log("  🔄 Updated current auth key for future authentication")
                            saveAuthKey()  // Persist to storage
                            updateAuthKeyUI()
                        }

                        runOnUiThread {
                            statusText.text = "SetAuthKey successful!"
                        }
                    } else {
                        log("  ❌ SetAuthKey FAILED! Status: 0x%02x".format(status))
                        pendingNewAuthKey = null  // Clear pending key on failure
                        runOnUiThread {
                            statusText.text = "SetAuthKey failed: status=$status"
                        }
                    }
                    log("═══════════════════════════════════════════════════")
                    return
                }

                // Check for Factory Reset response (tag 0x1b)
                if (data.size >= 3 && data[0] == 0x1b.toByte()) {
                    log("╔═══════════════════════════════════════════════════╗")
                    log("║  FACTORY RESET RESPONSE FROM RING                 ║")
                    log("╚═══════════════════════════════════════════════════╝")

                    val status = data[2].toInt() and 0xFF
                    log("  📥 RESPONSE (${data.size} bytes): $hexString")
                    log("  🔍 BREAKDOWN:")
                    log("     Byte 0 (Tag):    0x%02x (expected 0x1b)".format(data[0]))
                    log("     Byte 1 (Subcmd): 0x%02x (expected 0x01)".format(data[1]))
                    log("     Byte 2 (Status): 0x%02x".format(data[2]))

                    if (status == 0) {
                        log("  ✅ Factory reset SUCCESS - Ring memory wiped!")
                        log("  → Ring has been reset to factory defaults")
                        log("  → Auth key has been erased from ring")

                        // Clear local auth key storage
                        currentAuthKey = null
                        saveAuthKey()
                        updateAuthKeyUI()

                        log("  💾 Cleared local auth key storage")

                        runOnUiThread {
                            statusText.text = "Factory reset successful!"
                        }
                    } else {
                        log("  ❌ Factory reset FAILED! Status: 0x%02x".format(status))
                        runOnUiThread {
                            statusText.text = "Factory reset failed: status=$status"
                        }
                    }
                    log("═══════════════════════════════════════════════════")
                    return
                }

                // Check for TIME_SYNC response (tag 0x13)
                if (data.size >= 7 && data[0] == 0x13.toByte() && data[1] == 0x05.toByte()) {
                    log("╔═══════════════════════════════════════════════════╗")
                    log("║  ✅ TIME_SYNC SUCCESS - Response from Ring        ║")
                    log("╚═══════════════════════════════════════════════════╝")

                    // Parse ring time from bytes 2-5 (little-endian uint32)
                    // Ring time is in DECISECONDS (0.1 second units)
                    val ringTimeDeciseconds = ((data[2].toInt() and 0xFF) or
                                               ((data[3].toInt() and 0xFF) shl 8) or
                                               ((data[4].toInt() and 0xFF) shl 16) or
                                               ((data[5].toInt() and 0xFF) shl 24)).toLong() and 0xFFFFFFFFL

                    val ringTimeSeconds = ringTimeDeciseconds / 10.0
                    val uptimeHours = ringTimeSeconds / 3600.0
                    val uptimeDays = uptimeHours / 24.0

                    // Get current UTC time when we received this response
                    val currentUtcMillis = System.currentTimeMillis()

                    // Save the synchronization point
                    saveTimeSyncPoint(ringTimeDeciseconds, currentUtcMillis)

                    log("  📥 RESPONSE (${data.size} bytes): $hexString")
                    log("  🔍 RING TIME SYNC:")
                    log("     Ring Time:  $ringTimeDeciseconds deciseconds (%.1f seconds)".format(ringTimeSeconds))
                    log("     Uptime:     %.2f hours (%.2f days)".format(uptimeHours, uptimeDays))
                    log("  ✅ Synchronization point established and saved!")
                    log("═══════════════════════════════════════════════════")

                    runOnUiThread {
                        statusText.text = "Time synced! Ring: %.1fs".format(ringTimeSeconds)
                    }
                    return
                }

                // Check for GetEvent responses (tag 0x11 or event tags >= 0x41)
                if (data.isNotEmpty() && (data[0] == 0x11.toByte() || (data[0].toInt() and 0xFF) >= 0x41)) {
                    // STOP GUARD: Immediately reject all GetEvent notifications if stop condition met
                    if (shouldStopFetching) {
                        val eventType = if (data[0] == 0x11.toByte()) "SUMMARY 0x11" else "EVENT 0x%02x".format(data[0].toInt() and 0xFF)
                        log("[STOP RETRIEVE] Ignoring notification after stop: $eventType (${data.size}b)")
                        return
                    }

                    if (data[0] == 0x11.toByte() && data.size >= 3) {
                        // GetEvent summary response
                        // Format: [0x11, length, eventsReceived, sleepAnalysisProgress, bytesLeft(4 bytes LE)]
                        val eventsReceived = data[2].toInt() and 0xFF  // Events in THIS batch
                        val sleepAnalysisProgress = if (data.size >= 4) data[3].toInt() and 0xFF else -1

                        // Parse bytesLeft (4 bytes, little-endian)
                        bytesLeft = if (data.size >= 8) {
                            val b0 = (data[4].toLong() and 0xFF)
                            val b1 = (data[5].toLong() and 0xFF) shl 8
                            val b2 = (data[6].toLong() and 0xFF) shl 16
                            val b3 = (data[7].toLong() and 0xFF) shl 24
                            b0 or b1 or b2 or b3
                        } else {
                            0L
                        }

                        if (fetchMode == FetchMode.PROBING) {
                            // BINARY SEARCH MODE
                            log("╔═══════════════════════════════════════════════════╗")
                            log("║  BINARY SEARCH PROBE RESPONSE                     ║")
                            log("╚═══════════════════════════════════════════════════╝")
                            log("  Probed sequence: $currentSeqNum")
                            log("  Events received: $eventsReceived")
                            log("  Bytes left: $bytesLeft")
                            log("  Current range: [$probeLow, $probeHigh]")

                            if (eventsReceived > 0) {
                                // Found events at this sequence - try higher
                                lastValidSeq = currentSeqNum
                                probeLow = currentSeqNum
                                log("  ✓ Valid sequence! Last known valid: $lastValidSeq")
                            } else {
                                // No events at this sequence - try lower
                                probeHigh = currentSeqNum
                                log("  ✗ Beyond end, searching lower...")
                            }

                            // Check if search converged
                            if (probeHigh - probeLow <= 1) {
                                // Found the last event!
                                if (lastValidSeq < 0) {
                                    // No events on ring at all
                                    log("╔═══════════════════════════════════════════════════╗")
                                    log("║  BINARY SEARCH RESULT FINAL                       ║")
                                    log("╚═══════════════════════════════════════════════════╝")
                                    log("  Ring is EMPTY (no events found)")
                                    runOnUiThread {
                                        statusText.text = "No events on ring"
                                        bpmText.text = "NO DATA"
                                    }
                                    log("═══════════════════════════════════════════════════")
                                    return
                                }

                                log("╔═══════════════════════════════════════════════════╗")
                                log("║  BINARY SEARCH RESULT FINAL                       ║")
                                log("╚═══════════════════════════════════════════════════╝")
                                log("[SEARCH] Last position found: $lastValidSeq")
                                log("[SEARCH] Total events on ring: ~${lastValidSeq + 1}")
                                log("═══════════════════════════════════════════════════")

                                // Switch to fetch mode - get newest events
                                fetchMode = FetchMode.FETCHING
                                val offset = maxEventsToKeep - 1
                                val startSeq = maxOf(0, lastValidSeq - offset)
                                currentSeqNum = startSeq
                                bytesLeft = -1
                                totalEventsReceived = 0
                                eventCount = 0
                                eventData.clear()

                                log("[OFFSET] Target events: $targetEvents")
                                log("[OFFSET] Offset calculation: $lastValidSeq - $offset = $startSeq")
                                log("[OFFSET] Will fetch from seq $startSeq to end")
                                log("→ Switching to FETCHING mode")
                                runOnUiThread { statusText.text = "Fetching newest events..." }
                                sendGetEventCommand()
                            } else {
                                // Continue binary search
                                currentSeqNum = (probeLow + probeHigh) / 2
                                log("→ Next probe: $currentSeqNum (range: [$probeLow, $probeHigh])")
                                runOnUiThread { statusText.text = "Searching... testing seq $currentSeqNum" }
                                sendGetEventCommand()
                            }
                            log("═══════════════════════════════════════════════════")
                            return
                        } else {
                            // FETCHING or FETCHING_SLEEP MODE - normal data collection
                            val modeText = if (fetchMode == FetchMode.FETCHING_SLEEP) "SLEEP DATA" else "ALL DATA"
                            log("╔═══════════════════════════════════════════════════╗")
                            log("║  FETCH BATCH RESPONSE ($modeText)".padEnd(51) + "║")
                            log("╚═══════════════════════════════════════════════════╝")
                            log("[BATCH] Events in this batch: $eventsReceived")
                            log("[BATCH] Total events fetched so far: $totalEventsReceived")
                            log("[BATCH] Events stored (after filtering): $eventCount")
                            log("[POSITION] Current sequence: $currentSeqNum")
                            log("[POSITION] Bytes left on ring: $bytesLeft")

                            // Update sequence number for next batch
                            val nextSeq = currentSeqNum + eventsReceived.toLong()
                            currentSeqNum = nextSeq

                            // Continue fetching until bytesLeft == 0 OR stop condition met
                            if (bytesLeft > 0 && !shouldStopFetching) {
                                log("[LOOP] Continuing fetch - next seq: $nextSeq")
                                sendGetEventCommand()
                                log("═══════════════════════════════════════════════════")
                                return
                            } else {
                                // Determine why fetching stopped
                                if (shouldStopFetching) {
                                    log("[STOP RETRIEVE] ═══════════════════════════════════")
                                    log("[STOP RETRIEVE] FETCH STOPPED BY STOP CONDITION")
                                    log("[STOP RETRIEVE] Target event: 0x%02x".format(stopAfterEventType))
                                    log("[STOP RETRIEVE] Total events fetched: $totalEventsReceived")
                                    log("[STOP RETRIEVE] Events stored: $eventCount")
                                    log("[STOP RETRIEVE] Future notifications will be rejected")
                                    log("[STOP RETRIEVE] ═══════════════════════════════════")
                                } else {
                                    // bytesLeft == 0, reached end of ring
                                    log("[COMPLETE] Reached end of ring data")
                                    log("[COMPLETE] Total events fetched: $totalEventsReceived")
                                    log("[COMPLETE] Events stored: $eventCount")
                                }
                            }

                            // Fetch complete - display results
                            log("  Total events retrieved: $totalEventsReceived")
                            log("  Events after filtering: $eventCount")

                            if (eventCount == 0) {
                                log("  ℹ️  No events stored")
                                runOnUiThread {
                                    statusText.text = "No events on ring"
                                    bpmText.text = "NO DATA"
                                }
                            } else {
                                log("  ✅ Displaying $eventCount events")
                                displaySleepFacts()
                            }
                            log("═══════════════════════════════════════════════════")
                            return
                        }
                    } else if ((data[0].toInt() and 0xFF) >= 0x41) {
                        // Event payload
                        val eventTag = data[0].toInt() and 0xFF

                        // Only process events in FETCHING or FETCHING_SLEEP mode, skip in PROBING mode
                        if (fetchMode == FetchMode.FETCHING || fetchMode == FetchMode.FETCHING_SLEEP) {
                            totalEventsReceived++

                            // Determine if we should store this event based on fetch mode
                            val shouldStore = when (fetchMode) {
                                FetchMode.FETCHING -> {
                                    // Apply blacklist - if empty, store all events; otherwise exclude blacklisted types
                                    eventBlacklist.isEmpty() || !eventBlacklist.contains(eventTag)
                                }
                                FetchMode.FETCHING_SLEEP -> {
                                    // Only store sleep events from whitelist
                                    sleepEventWhitelist.contains(eventTag)
                                }
                                else -> false  // PROBING mode - shouldn't reach here
                            }

                            if (shouldStore) {
                                eventCount++
                                eventData.add(data.copyOf())

                                // Check if we should stop after collecting N events of this type
                                if (stopAfterEventType != null && eventTag == stopAfterEventType) {
                                    targetEventCounter++
                                    log("  📊 [EVENT COUNTER] Collected ${targetEventCounter} of ${stopAfterEventCount} target events (0x%02x)".format(eventTag))

                                    if (targetEventCounter >= stopAfterEventCount) {
                                        log("  🛑 [STOP RETRIEVE] STOP CONDITION MET!")
                                        log("  🛑 [STOP RETRIEVE] Collected ${targetEventCounter} events of type 0x%02x".format(eventTag))
                                        log("  🛑 [STOP RETRIEVE] Setting stop flag - will reject future notifications")
                                        shouldStopFetching = true
                                    }
                                }

                                // DECODER DISABLED: Use Data Browser + Python script for offline decoding
                                // The in-app decoder causes binder overflow even with minimal logging
                                // if (eventTag == 0x6a && !hasDecodedFirstSleepPeriodInfo) {
                                //     hasDecodedFirstSleepPeriodInfo = true
                                //     decodeSleepPeriodInfo2Minimal(data)
                                // }
                            }

                            // Only log every 100th event to avoid binder overflow
                            if (totalEventsReceived % 100 == 1 || totalEventsReceived <= 10) {
                                val filterStatus = if (shouldStore) "✓" else "⊗"
                                val eventType = when (eventTag) {
                                    0x48 -> "SLEEP_PERIOD_INFO"
                                    0x49 -> "SLEEP_SUMMARY_1"
                                    0x4B -> "SLEEP_PHASE_INFO"
                                    0x4C -> "SLEEP_SUMMARY_2"
                                    0x4E -> "SLEEP_PHASE_DETAILS"
                                    0x55 -> "SLEEP_HR"
                                    0x58 -> "SLEEP_SUMMARY_4"
                                    0x5A -> "SLEEP_PHASE_DATA"
                                    0x6a -> "SLEEP_PERIOD_INFO_2"
                                    0x75 -> "SLEEP_TEMP_EVENT"
                                    in 0x41..0x83 -> "0x%02x".format(eventTag)
                                    else -> "??"
                                }
                                log("  Event #$totalEventsReceived: $eventType (${data.size}b) $filterStatus")
                            }
                        } else {
                            // In PROBING mode - silent
                        }
                        return
                    }
                }

                // Check for authentication responses first
                if (!isAuthenticated && data.size >= 3 && data[0] == 0x2f.toByte()) {
                    // GetAuthNonce response: 2f <subcmd> 2c <15-byte-nonce>
                    // Note: Official app ignores byte 1 (subcmd) and only checks byte 2
                    if (data[2] == 0x2c.toByte() && data.size >= 18) {
                        log("╔═══════════════════════════════════════════════════╗")
                        log("║  AUTHENTICATION: GetAuthNonce RESPONSE           ║")
                        log("╚═══════════════════════════════════════════════════╝")

                        // Extract 15-byte nonce (bytes 3-17) - official app extracts bytes 3-18 from 18-byte response
                        val nonce = data.copyOfRange(3, 18)
                        authNonce = nonce

                        val nonceHex = nonce.joinToString(" ") { "%02x".format(it) }
                        log("  📥 NONCE FROM RING (${nonce.size} bytes):")
                        log("     $nonceHex")
                        log("  → Encrypting nonce with auth key...")

                        // Encrypt nonce and send authenticate command
                        val encryptedNonce = encryptNonce(nonce)
                        sendAuthenticateCommand(encryptedNonce)
                        return
                    }

                    // Authenticate response: 2f <subcmd> 2e <status>
                    if (data.size >= 4 && data[2] == 0x2e.toByte()) {
                        log("╔═══════════════════════════════════════════════════╗")
                        log("║  AUTHENTICATION: Authenticate RESPONSE            ║")
                        log("╚═══════════════════════════════════════════════════╝")

                        val status = data[3].toInt() and 0xFF
                        log("  📥 STATUS FROM RING: 0x%02x".format(data[3]))

                        if (status == 0) {
                            log("  ✅ AUTHENTICATION SUCCESS!")
                            isAuthenticated = true
                            initState = InitState.IDLE

                            runOnUiThread { statusText.text = "Authenticated - Ready for HB capture" }
                            log("  → Authentication complete!")
                            log("  → Click 'Start HB' to begin heartbeat monitoring")
                        } else {
                            log("  ❌ AUTHENTICATION FAILED! Status: $status")
                            runOnUiThread { statusText.text = "Authentication failed!" }
                        }
                        log("═══════════════════════════════════════════════════")
                        return
                    }
                }

                // Check if this is a heartbeat packet (2f 0f 28)
                if (data.size >= 10 &&
                    data[0] == 0x2f.toByte() &&
                    data[1] == 0x0f.toByte() &&
                    data[2] == 0x28.toByte()) {
                    log("    >>> THIS IS A HEARTBEAT PACKET! <<<")
                    parseHeartbeat(data)
                } else {
                    // ACK/Response handling with state-based sequencing
                    log("    Type: ACK/Response (not heartbeat)")

                    if (data.size >= 3 && data[0] == 0x2f.toByte()) {
                        val ackByte = data[2]

                        when (ackByte) {
                            0x21.toByte() -> {
                                log("    ✅ ACK for: INIT_1")
                                if (initState == InitState.WAITING_FOR_INIT1_ACK) {
                                    log("    → Sending INIT_2...")
                                    sendCommand(CMD_INIT_2)
                                }
                            }
                            0x23.toByte() -> {
                                log("    ✅ ACK for: INIT_2")
                                if (initState == InitState.WAITING_FOR_INIT2_ACK) {
                                    log("    → Sending START_STREAM...")
                                    sendCommand(CMD_START_STREAM)
                                }
                            }
                            0x27.toByte() -> {
                                log("    ✅ ACK for: START_STREAM")
                                if (initState == InitState.WAITING_FOR_START_STREAM_ACK) {
                                    initState = InitState.MONITORING_ACTIVE
                                    runOnUiThread { statusText.text = "Monitoring heartbeat..." }
                                    log(">>> HEARTBEAT MONITORING ACTIVE <<<")
                                }
                            }
                            else -> {
                                log("    ACK for: Unknown command (byte 2 = 0x%02x)".format(ackByte))
                            }
                        }
                    }
                }
            }
        })
    }

    private fun sendCommand(command: ByteArray) {
        // Check BLUETOOTH_CONNECT only on Android 12+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                log("ERROR: Missing BLUETOOTH_CONNECT permission for sendCommand")
                return
            }
        }

        val hexString = command.joinToString(" ") { "%02x".format(it) }
        val commandName = when {
            command.contentEquals(CMD_INIT_1) -> "INIT_1"
            command.contentEquals(CMD_INIT_2) -> "INIT_2"
            command.contentEquals(CMD_START_STREAM) -> "START_STREAM"
            command.contentEquals(CMD_STOP) -> "STOP"
            else -> "UNKNOWN"
        }
        log("TX: $hexString ($commandName)")

        // Update state to track what ACK we're expecting
        when {
            command.contentEquals(CMD_INIT_1) -> {
                initState = InitState.WAITING_FOR_INIT1_ACK
                log("  → Waiting for INIT_1 ACK (0x21)...")
            }
            command.contentEquals(CMD_INIT_2) -> {
                initState = InitState.WAITING_FOR_INIT2_ACK
                log("  → Waiting for INIT_2 ACK (0x23)...")
            }
            command.contentEquals(CMD_START_STREAM) -> {
                initState = InitState.WAITING_FOR_START_STREAM_ACK
                log("  → Waiting for START_STREAM ACK (0x27)...")
            }
        }

        writeCharacteristic?.value = command
        val writeSuccess = bluetoothGatt?.writeCharacteristic(writeCharacteristic)
        log("  writeCharacteristic: ${if (writeSuccess == true) "QUEUED" else "FAILED"}")
    }

    private fun parseHeartbeat(data: ByteArray) {
        // Check if this is a heartbeat packet
        if (data[0] == 0x2f.toByte() && data[1] == 0x0f.toByte() && data[2] == 0x28.toByte()) {
            // Extract IBI (12-bit little-endian in bytes 8-9)
            val ibiLow = data[8].toInt() and 0xFF
            val ibiHigh = data[9].toInt() and 0x0F
            val ibiMs = (ibiHigh shl 8) or ibiLow

            // Calculate BPM
            val bpm = 60000.0 / ibiMs

            heartbeatCount++

            log("  >>> HEARTBEAT #$heartbeatCount: ${String.format("%.1f", bpm)} BPM (IBI: ${ibiMs}ms)")
            log("      Raw IBI bytes: [8]=0x%02x [9]=0x%02x -> %d ms".format(data[8], data[9], ibiMs))

            runOnUiThread {
                updateUI(bpm, ibiMs)
            }
        } else {
            log("  Not a heartbeat packet: [0]=0x%02x [1]=0x%02x [2]=0x%02x".format(data[0], data[1], data[2]))
        }
    }

    private fun updateUI(bpm: Double, ibiMs: Int) {
        bpmText.text = String.format("%.1f BPM", bpm)
        ibiText.text = "$ibiMs ms"
        countText.text = "Heartbeats: $heartbeatCount"
    }

    // ========== AUTHENTICATION METHODS ==========

    private fun performAuthentication() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  AUTHENTICATION STEP 1: GetAuthNonce             ║")
        log("╚═══════════════════════════════════════════════════╝")
        log("  📤 SENDING GetAuthNonce REQUEST: 2f 01 2b")
        log("  → Asking ring for random 16-byte nonce...")

        // Reset authentication state
        isAuthenticated = false
        authNonce = null

        // Send GetAuthNonce command
        sendAuthCommand(CMD_GET_AUTH_NONCE)
    }

    private fun encryptNonce(nonce: ByteArray): ByteArray {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  AUTHENTICATION STEP 2: Encrypt Nonce            ║")
        log("╚═══════════════════════════════════════════════════╝")

        if (currentAuthKey == null) {
            log("  ❌ ERROR: No auth key set! Cannot encrypt nonce.")
            throw IllegalStateException("No auth key available for encryption")
        }

        val authKeyHex = currentAuthKey!!.joinToString(" ") { "%02x".format(it) }
        val nonceHex = nonce.joinToString(" ") { "%02x".format(it) }

        log("  🔑 CURRENT AUTH KEY (16 bytes):")
        log("     $authKeyHex")
        log("  📝 NONCE TO ENCRYPT (${nonce.size} bytes):")
        log("     $nonceHex")
        log("  🔒 ALGORITHM: AES/ECB/PKCS5Padding")

        try {
            // Create AES cipher with ECB mode and PKCS5 padding
            // This matches what the official Oura app uses (discovered via reverse engineering)
            val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
            val keySpec = SecretKeySpec(currentAuthKey!!, "AES")

            // Initialize cipher in ENCRYPT mode
            cipher.init(Cipher.ENCRYPT_MODE, keySpec)

            // Encrypt the nonce
            val encryptedNonce = cipher.doFinal(nonce)

            val encryptedHex = encryptedNonce.joinToString(" ") { "%02x".format(it) }
            log("  ✅ ENCRYPTED NONCE (${encryptedNonce.size} bytes):")
            log("     $encryptedHex")
            log("═══════════════════════════════════════════════════")

            return encryptedNonce
        } catch (e: Exception) {
            log("  ❌ ERROR encrypting nonce: ${e.message}")
            throw e
        }
    }

    private fun sendAuthenticateCommand(encryptedNonce: ByteArray) {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  AUTHENTICATION STEP 3: Send Authenticate        ║")
        log("╚═══════════════════════════════════════════════════╝")

        // Build authenticate command: 2f 11 2d <16-byte-encrypted-nonce>
        // Total: 19 bytes
        val command = ByteArray(19)
        command[0] = 0x2f.toByte()  // Tag
        command[1] = 0x11.toByte()  // Subcmd
        command[2] = 0x2d.toByte()  // Extended tag

        // Copy encrypted nonce (should be 16 bytes after PKCS5 padding removal by cipher)
        // Note: AES/ECB/PKCS5Padding might produce a padded output, but we only send first 16 bytes
        System.arraycopy(encryptedNonce, 0, command, 3, 16)

        val cmdHex = command.joinToString(" ") { "%02x".format(it) }
        log("  📤 SENDING Authenticate COMMAND (19 bytes):")
        log("     $cmdHex")
        log("  → Waiting for ring to verify...")

        sendAuthCommand(command)
    }

    private fun sendAuthCommand(command: ByteArray) {
        // Check BLUETOOTH_CONNECT only on Android 12+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                log("ERROR: Missing BLUETOOTH_CONNECT permission for sendAuthCommand")
                return
            }
        }

        val hexString = command.joinToString(" ") { "%02x".format(it) }
        log("TX: $hexString")

        writeCharacteristic?.value = command
        val writeSuccess = bluetoothGatt?.writeCharacteristic(writeCharacteristic)
        log("  writeCharacteristic: ${if (writeSuccess == true) "QUEUED" else "FAILED"}")
    }

    // ========== SET AUTH KEY METHODS ==========

    fun sendSetAuthKey(newAuthKey: ByteArray) {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  SET AUTH KEY: Writing new key to ring          ║")
        log("╚═══════════════════════════════════════════════════╝")

        if (newAuthKey.size != 16) {
            log("  ❌ ERROR: Auth key must be 16 bytes, got ${newAuthKey.size}")
            return
        }

        val keyHex = newAuthKey.joinToString(" ") { "%02x".format(it) }
        log("  🔑 NEW AUTH KEY (16 bytes):")
        log("     $keyHex")

        // Store the pending key so we can update currentAuthKey when ring confirms
        pendingNewAuthKey = newAuthKey.copyOf()

        // Build command: 24 10 <16-byte-key>
        val command = ByteArray(18)
        command[0] = CMD_SET_AUTH_KEY_TAG      // 0x24
        command[1] = CMD_SET_AUTH_KEY_SUBCMD   // 0x10
        System.arraycopy(newAuthKey, 0, command, 2, 16)

        val cmdHex = command.joinToString(" ") { "%02x".format(it) }
        log("  📤 SENDING SetAuthKey COMMAND (18 bytes):")
        log("     $cmdHex")
        log("  → Waiting for ring to confirm...")

        sendAuthCommand(command)
    }

    fun testSetAuthKey() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  TEST: SetAuthKey with random key                ║")
        log("╚═══════════════════════════════════════════════════╝")

        // Generate a test auth key
        val testKey = byteArrayOf(
            0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(),
            0xEE.toByte(), 0xFF.toByte(), 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66,
            0x77, 0x88.toByte(), 0x99.toByte(), 0x00
        )

        log("  ⚠️  WARNING: This will write a TEST key to the ring!")
        log("  ⚠️  You may need to re-pair with official app after this")
        log("  🔑 Test key: ${testKey.joinToString(" ") { "%02x".format(it) }}")
        log("")

        // Ensure connection before sending
        ensureConnected {
            sendSetAuthKey(testKey)
        }
    }

    // ========== FACTORY RESET METHOD ==========

    fun sendFactoryReset() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  FACTORY RESET: Sending command to ring          ║")
        log("╚═══════════════════════════════════════════════════╝")
        log("  📤 COMMAND: 1a 00")
        log("  ⚠️  This will ERASE all ring data including auth key!")
        log("  ⚠️  The ring will need to be re-paired after this!")
        log("")

        // Ensure connection before sending
        ensureConnected {
            val cmdHex = CMD_FACTORY_RESET.joinToString(" ") { "%02x".format(it) }
            log("  Sending factory reset command: $cmdHex")
            sendAuthCommand(CMD_FACTORY_RESET)
        }
    }

    // Helper function to ensure connection before executing operation
    private fun ensureConnected(operation: () -> Unit) {
        if (isConnected) {
            // Already connected, execute immediately
            operation()
        } else {
            // Not connected, queue operation and start connection
            log("Not connected - initiating connection first...")
            pendingOperation = operation
            connectToRing()
        }
    }

    private fun startHeartbeatCapture() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  START HEARTBEAT CAPTURE                         ║")
        log("╚═══════════════════════════════════════════════════╝")

        if (!isConnected) {
            log("❌ Not connected! Click Connect first.")
            statusText.text = "Not connected"
            return
        }

        if (!isAuthenticated) {
            log("❌ Not authenticated! Click Auth first.")
            statusText.text = "Not authenticated"
            return
        }

        log("  → Starting heartbeat initialization sequence...")
        log("  → Step 1: Sending INIT_1 command")
        runOnUiThread { statusText.text = "Initializing heartbeat..." }

        // Reset init state and start the sequence
        initState = InitState.IDLE
        sendCommand(CMD_INIT_1)
    }

    private fun getDataFromRing() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  GET DATA FROM RING (ALL EVENTS)                 ║")
        log("╚═══════════════════════════════════════════════════╝")

        // Clear previous events and reset state
        eventCount = 0
        totalEventsReceived = 0
        eventData.clear()

        // Initialize binary search probing
        fetchMode = FetchMode.PROBING
        probeLow = 0
        probeHigh = 50000000  // Initial high guess: 50 million
        lastValidSeq = -1
        currentSeqNum = probeHigh / 2  // Start at midpoint (25 million)
        bytesLeft = -1

        log("→ Starting BINARY SEARCH to find last event number")
        log("  Initial probe range: [$probeLow, $probeHigh]")
        log("  Testing sequence: $currentSeqNum")
        sendGetEventCommand()
    }

    private fun getSleepDataFromRing() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  GET SLEEP DATA FROM RING (SLEEP EVENTS ONLY)    ║")
        log("╚═══════════════════════════════════════════════════╝")
        log("  Sleep event types in whitelist:")
        log("    0x48 SLEEP_PERIOD_INFO")
        log("    0x49 SLEEP_SUMMARY_1")
        log("    0x4B SLEEP_PHASE_INFO")
        log("    0x4C SLEEP_SUMMARY_2")
        log("    0x4D RING_SLEEP_FEATURE_INFO")
        log("    0x4E SLEEP_PHASE_DETAILS")
        log("    0x4F SLEEP_SUMMARY_3")
        log("    0x55 SLEEP_HR")
        log("    0x57 RING_SLEEP_FEATURE_INFO_2")
        log("    0x58 SLEEP_SUMMARY_4")
        log("    0x5A SLEEP_PHASE_DATA")
        log("    0x6a SLEEP_PERIOD_INFO_2")
        log("    0x72 SLEEP_ACM_PERIOD")
        log("    0x75 SLEEP_TEMP_EVENT")
        log("    0x76 BEDTIME_PERIOD")
        log("  → Will fetch ALL events from ring sequence 0")
        log("  → Client-side filtering: Only sleep events will be stored")

        // Clear previous events and reset state
        eventCount = 0
        totalEventsReceived = 0
        eventData.clear()

        // Start fetching from sequence 0 (beginning of ring storage)
        // No binary search - fetch everything and filter client-side
        fetchMode = FetchMode.FETCHING_SLEEP
        currentSeqNum = 0
        bytesLeft = -1  // -1 = not started yet
        batchSize = 0  // 0 = fetch ALL remaining events

        // Initialize stop control for testing
        shouldStopFetching = false
        stopAfterEventType = 0x6a  // Stop after receiving SLEEP_PERIOD_INFO_2
        stopAfterEventCount = 20  // Collect 20 events before stopping
        targetEventCounter = 0     // Reset counter

        log("→ Starting SLEEP DATA FETCH from sequence 0")
        log("  Mode: FETCHING_SLEEP (client-side filtering)")
        log("  STOP AFTER: 20 events of type 0x6a (SLEEP_PERIOD_INFO_2)")
        sendGetEventCommand()
    }

    private fun sendGetEventCommand() {
        // Build GetEvent command (0x10)
        // Format: 10 09 <event_seq_num:4-bytes LE> <max_events:1-byte> <flags:4-bytes LE>
        // NOTE: The first parameter is an EVENT SEQUENCE NUMBER, not a Unix timestamp!
        // Each event has a sequential number starting from 0, incrementing by 1 per event.
        val getEventCmd = ByteArray(11)
        getEventCmd[0] = 0x10  // REQUEST_TAG
        getEventCmd[1] = 0x09  // length

        // event sequence number (4 bytes, little endian)
        getEventCmd[2] = (currentSeqNum and 0xFF).toByte()
        getEventCmd[3] = ((currentSeqNum shr 8) and 0xFF).toByte()
        getEventCmd[4] = ((currentSeqNum shr 16) and 0xFF).toByte()
        getEventCmd[5] = ((currentSeqNum shr 24) and 0xFF).toByte()

        // Max events: 1 for probing, batchSize for fetching
        val maxEvents = if (fetchMode == FetchMode.PROBING) 1 else batchSize
        getEventCmd[6] = maxEvents.toByte()

        // flags (4 bytes, little endian): 0x00000000
        getEventCmd[7] = 0x00
        getEventCmd[8] = 0x00
        getEventCmd[9] = 0x00
        getEventCmd[10] = 0x00

        log("→ Sending GetEvent command")
        log("  Mode: $fetchMode")
        log("  Sequence number: $currentSeqNum, Max events: $maxEvents")
        log("  Command: ${getEventCmd.joinToString(" ") { "%02x".format(it) }}")

        runOnUiThread { statusText.text = "Fetching events... ($totalEventsReceived received)" }

        sendCommand(getEventCmd)
    }

    private fun sendTimeSyncRequest() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  TIME_SYNC REQUEST (0x12)                        ║")
        log("╚═══════════════════════════════════════════════════╝")

        // Get current UTC time in milliseconds
        val currentTimeMillis = System.currentTimeMillis()
        val currentTimeSec = currentTimeMillis / 1000

        // Get timezone offset in milliseconds
        val timeZone = java.util.TimeZone.getDefault()
        val tzOffsetMillis = timeZone.getOffset(currentTimeMillis)
        val tzOffsetSec = tzOffsetMillis / 1000

        // Convert timezone to 30-minute units (as per Oura protocol)
        val tzIn30MinUnits = (tzOffsetMillis / 1800000).toByte()

        log("  Current UTC time: $currentTimeMillis ms ($currentTimeSec sec)")
        log("  Timezone offset: $tzOffsetMillis ms ($tzOffsetSec sec)")
        log("  Timezone in 30-min units: $tzIn30MinUnits")
        log("  Date: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", java.util.Locale.US).format(java.util.Date(currentTimeMillis))}")

        // Build TIME_SYNC request (0x12)
        // Format: 12 09 <utc_time_sec:8-bytes LE> <tz_30min_units:1-byte>
        val timeSyncCmd = ByteArray(11)
        timeSyncCmd[0] = 0x12  // TIME_SYNC REQUEST_TAG
        timeSyncCmd[1] = 0x09  // length

        // UTC time in seconds (8 bytes, little endian)
        timeSyncCmd[2] = (currentTimeSec and 0xFF).toByte()
        timeSyncCmd[3] = ((currentTimeSec shr 8) and 0xFF).toByte()
        timeSyncCmd[4] = ((currentTimeSec shr 16) and 0xFF).toByte()
        timeSyncCmd[5] = ((currentTimeSec shr 24) and 0xFF).toByte()
        timeSyncCmd[6] = ((currentTimeSec shr 32) and 0xFF).toByte()
        timeSyncCmd[7] = ((currentTimeSec shr 40) and 0xFF).toByte()
        timeSyncCmd[8] = ((currentTimeSec shr 48) and 0xFF).toByte()
        timeSyncCmd[9] = ((currentTimeSec shr 56) and 0xFF).toByte()

        // Timezone offset in 30-minute units (1 byte)
        timeSyncCmd[10] = tzIn30MinUnits

        log("→ Sending TIME_SYNC request")
        log("  Command: ${timeSyncCmd.joinToString(" ") { "%02x".format(it) }}")
        log("  Expected response: Event 0x42 (TIME_SYNC_IND) with ring timestamp")

        runOnUiThread { statusText.text = "Syncing time..." }

        sendCommand(timeSyncCmd)
    }

    private fun displaySleepFacts() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  ANALYZING SLEEP DATA                            ║")
        log("╚═══════════════════════════════════════════════════╝")

        // Count different event types
        var sleepPeriodInfo = 0
        var sleepSummary1 = 0
        var sleepPhaseInfo = 0
        var sleepSummary2 = 0
        var sleepPhaseDetails = 0
        var sleepHr = 0
        var sleepSummary4 = 0
        var sleepPhaseData = 0
        var sleepTemp = 0
        var otherEvents = 0

        for (event in eventData) {
            if (event.isEmpty()) continue
            when (event[0].toInt() and 0xFF) {
                0x48 -> sleepPeriodInfo++
                0x49 -> sleepSummary1++
                0x4B -> sleepPhaseInfo++
                0x4C -> sleepSummary2++
                0x4E -> sleepPhaseDetails++
                0x55 -> sleepHr++
                0x58 -> sleepSummary4++
                0x5A -> sleepPhaseData++
                0x75 -> sleepTemp++
                else -> otherEvents++
            }
        }

        val totalSleepEvents = sleepPeriodInfo + sleepSummary1 + sleepPhaseInfo +
                               sleepSummary2 + sleepPhaseDetails + sleepHr +
                               sleepSummary4 + sleepPhaseData + sleepTemp

        log("  Total events: $eventCount")
        log("  Sleep-related events: $totalSleepEvents")
        log("  Sleep Period Info: $sleepPeriodInfo")
        log("  Sleep Summary 1: $sleepSummary1")
        log("  Sleep Phase Info: $sleepPhaseInfo")
        log("  Sleep Summary 2: $sleepSummary2")
        log("  Sleep Phase Details: $sleepPhaseDetails")
        log("  Sleep HR: $sleepHr")
        log("  Sleep Summary 4: $sleepSummary4")
        log("  Sleep Phase Data: $sleepPhaseData")
        log("  Sleep Temp: $sleepTemp")
        log("  Other events: $otherEvents")

        // Display compact facts in heartbeat panel
        runOnUiThread {
            statusText.text = "Data retrieved"

            // Main display: Total events
            bpmText.text = "$eventCount EVENTS"

            // Build compact facts string
            val facts = buildString {
                if (totalSleepEvents > 0) {
                    append("Sleep: $totalSleepEvents | ")
                }
                if (sleepPeriodInfo > 0) append("Period: $sleepPeriodInfo | ")
                if (sleepSummary1 > 0) append("Sum1: $sleepSummary1 | ")
                if (sleepSummary2 > 0) append("Sum2: $sleepSummary2 | ")
                if (sleepSummary4 > 0) append("Sum4: $sleepSummary4")
            }.trimEnd('|', ' ')

            val details = buildString {
                if (sleepPhaseInfo > 0) append("Phase: $sleepPhaseInfo | ")
                if (sleepPhaseDetails > 0) append("Details: $sleepPhaseDetails | ")
                if (sleepPhaseData > 0) append("PhaseData: $sleepPhaseData")
            }.trimEnd('|', ' ')

            val sensors = buildString {
                if (sleepHr > 0) append("HR: $sleepHr | ")
                if (sleepTemp > 0) append("Temp: $sleepTemp | ")
                if (otherEvents > 0) append("Other: $otherEvents")
            }.trimEnd('|', ' ')

            // Secondary info display
            ibiText.text = facts

            // Tertiary info display
            countText.text = if (details.isNotEmpty() || sensors.isNotEmpty()) {
                buildString {
                    if (details.isNotEmpty()) append(details)
                    if (details.isNotEmpty() && sensors.isNotEmpty()) append(" | ")
                    if (sensors.isNotEmpty()) append(sensors)
                }
            } else {
                "No sleep data"
            }
        }

        log("═══════════════════════════════════════════════════")
    }

    private fun parseAndShowEventData() {
        log("╔═══════════════════════════════════════════════════╗")
        log("║  GENERIC EVENT BROWSER - ALL EVENTS              ║")
        log("╚═══════════════════════════════════════════════════╝")
        log("Total events: ${eventData.size}")
        log("")

        // Count events by type
        val eventCounts = mutableMapOf<Int, Int>()
        for (event in eventData) {
            if (event.isNotEmpty()) {
                val tag = event[0].toInt() and 0xFF
                eventCounts[tag] = (eventCounts[tag] ?: 0) + 1
            }
        }

        log("Event Summary:")
        for ((tag, count) in eventCounts.toSortedMap()) {
            val name = getEventTypeName(tag)
            log("  0x%02x (%3d): %-30s x%d".format(tag, tag, name, count))
        }
        log("")

        // Parse and display each event
        for ((index, event) in eventData.withIndex()) {
            if (event.isEmpty()) continue

            val tag = event[0].toInt() and 0xFF
            val name = getEventTypeName(tag)
            val payload = if (event.size > 1) event.copyOfRange(1, event.size) else byteArrayOf()

            log("────────────────────────────────────────────────────")
            log("Event #${index + 1}: $name (0x%02x)".format(tag))
            log("Size: ${event.size} bytes")

            if (payload.isNotEmpty()) {
                // Parse protobuf fields generically
                val fields = parseProtobufGeneric(payload)

                if (fields.isNotEmpty()) {
                    log("Fields:")
                    for ((fieldNum, values) in fields.toSortedMap()) {
                        val fieldName = getFieldName(tag, fieldNum)
                        if (values.size == 1) {
                            log("  Field %2d (%s): %s".format(fieldNum, fieldName, formatValue(values[0], fieldNum)))
                        } else {
                            log("  Field %2d (%s): [array of ${values.size}]".format(fieldNum, fieldName))
                            for ((i, value) in values.take(5).withIndex()) {
                                log("    [%d] = %s".format(i, formatValue(value, fieldNum)))
                            }
                            if (values.size > 5) {
                                log("    ... and ${values.size - 5} more")
                            }
                        }
                    }
                } else {
                    log("  (No parseable fields - raw binary data)")
                }

                // Show hex dump for first 32 bytes
                if (payload.size <= 32) {
                    log("Hex: ${payload.joinToString(" ") { "%02x".format(it) }}")
                } else {
                    log("Hex: ${payload.take(32).joinToString(" ") { "%02x".format(it) }} ... (+${payload.size - 32})")
                }
            } else {
                log("  (Empty payload)")
            }
        }

        log("════════════════════════════════════════════════════")
        log("✅ Displayed ${eventData.size} events")

        // Update UI
        runOnUiThread {
            statusText.text = "Browsing ${eventData.size} events"
            bpmText.text = "${eventData.size}\nEVENTS"
            ibiText.text = "${eventCounts.size} types"
            countText.text = "Check debug log"
        }
    }

    // Get event type name from tag
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

    // Get field name hint
    private fun getFieldName(eventTag: Int, fieldNum: Int): String {
        return if (fieldNum == 1) "timestamp" else "field$fieldNum"
    }

    // Format value with smart heuristics
    private fun formatValue(value: Long, fieldNum: Int): String {
        // Field 1 is usually timestamp
        if (fieldNum == 1 && value > 1000000000 && value < 2000000000) {
            val date = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).apply {
                timeZone = java.util.TimeZone.getTimeZone("UTC")
            }.format(java.util.Date(value * 1000))
            return "$value (UTC: $date)"
        }
        return value.toString()
    }

    // Enhanced generic protobuf parser that collects repeated fields
    private fun parseProtobufGeneric(data: ByteArray): Map<Int, List<Long>> {
        val fields = mutableMapOf<Int, MutableList<Long>>()
        var pos = 0

        while (pos < data.size) {
            // Read field header
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
                        pos += 8
                    } else {
                        break
                    }
                }
                2 -> { // Length-delimited
                    val (length, lengthSize) = readVarint(data, pos)
                    if (lengthSize > 0) {
                        pos += lengthSize
                        if (pos + length.toInt() <= data.size) {
                            // Store length as value for now
                            fields.getOrPut(fieldNumber) { mutableListOf() }.add(length)
                            pos += length.toInt()
                        } else {
                            break
                        }
                    } else {
                        break
                    }
                }
                5 -> { // 32-bit
                    if (pos + 4 <= data.size) {
                        pos += 4
                    } else {
                        break
                    }
                }
                else -> break
            }
        }

        return fields
    }

    // Simple Protobuf wire format parser
    private fun parseProtobuf(data: ByteArray): Map<Int, Long> {
        val fields = mutableMapOf<Int, Long>()
        var pos = 0

        while (pos < data.size) {
            if (pos >= data.size) break

            // Read field header (varint encoding)
            val (header, headerSize) = readVarint(data, pos)
            if (headerSize == 0) break
            pos += headerSize

            val fieldNumber = (header shr 3).toInt()
            val wireType = (header and 0x7).toInt()

            when (wireType) {
                0 -> { // Varint
                    val (value, valueSize) = readVarint(data, pos)
                    if (valueSize > 0) {
                        fields[fieldNumber] = value
                        pos += valueSize
                    } else {
                        break
                    }
                }
                1 -> { // 64-bit
                    if (pos + 8 <= data.size) {
                        pos += 8
                    } else {
                        break
                    }
                }
                2 -> { // Length-delimited
                    val (length, lengthSize) = readVarint(data, pos)
                    if (lengthSize > 0) {
                        pos += lengthSize
                        if (pos + length.toInt() <= data.size) {
                            pos += length.toInt()
                        } else {
                            break
                        }
                    } else {
                        break
                    }
                }
                5 -> { // 32-bit
                    if (pos + 4 <= data.size) {
                        pos += 4
                    } else {
                        break
                    }
                }
                else -> break
            }
        }

        return fields
    }

    // Read a varint from byte array
    private fun readVarint(data: ByteArray, startPos: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var pos = startPos

        while (pos < data.size && shift < 64) {
            val byte = data[pos].toLong() and 0xFF
            result = result or ((byte and 0x7F) shl shift)
            pos++
            shift += 7

            if ((byte and 0x80) == 0L) {
                return Pair(result, pos - startPos)
            }
        }

        return Pair(0, 0) // Failed to read
    }

    // ========================================================================
    // PROTOBUF DECODER FOR SLEEP_PERIOD_INFO_2 (0x6a)
    // ========================================================================

    private data class ProtobufVarintResult(val value: Long, val bytesRead: Int)
    private data class ProtobufFixed32Result(val value: Long, val bytesRead: Int)
    private data class ProtobufFixed64Result(val value: Long, val bytesRead: Int)

    private fun decodeProtobufVarint(data: ByteArray, offset: Int): ProtobufVarintResult {
        var result = 0L
        var shift = 0
        var pos = offset

        while (pos < data.size) {
            val byte = data[pos].toInt() and 0xFF
            pos++
            result = result or ((byte and 0x7F).toLong() shl shift)
            if ((byte and 0x80) == 0) {
                return ProtobufVarintResult(result, pos - offset)
            }
            shift += 7
        }
        return ProtobufVarintResult(0, 0) // Failed
    }

    private fun decodeProtobufFixed32(data: ByteArray, offset: Int): ProtobufFixed32Result {
        if (offset + 4 > data.size) {
            return ProtobufFixed32Result(0, 0)
        }
        val value = ((data[offset].toInt() and 0xFF) or
                    ((data[offset + 1].toInt() and 0xFF) shl 8) or
                    ((data[offset + 2].toInt() and 0xFF) shl 16) or
                    ((data[offset + 3].toInt() and 0xFF) shl 24)).toLong() and 0xFFFFFFFFL
        return ProtobufFixed32Result(value, 4)
    }

    private fun decodeProtobufFixed64(data: ByteArray, offset: Int): ProtobufFixed64Result {
        if (offset + 8 > data.size) {
            return ProtobufFixed64Result(0, 0)
        }
        var value = 0L
        for (i in 0..7) {
            value = value or ((data[offset + i].toLong() and 0xFF) shl (i * 8))
        }
        return ProtobufFixed64Result(value, 8)
    }

    private fun bytesToFloat(bytes: Long): Float {
        return java.lang.Float.intBitsToFloat(bytes.toInt())
    }

    private fun decodeSleepPeriodInfo2Minimal(data: ByteArray) {
        try {
            log("╔═══════════════════════════════════════════════════╗")
            log("║  SLEEP_PERIOD_INFO_2 (0x6a) - SUMMARY           ║")
            log("╚═══════════════════════════════════════════════════╝")
            log("  Raw size: ${data.size} bytes")
            log("  Hex: ${data.joinToString("") { "%02x".format(it) }}")

            // Quick parse to count samples
            var sampleCount = 0
            var offset = 1  // Skip 0x6a tag
            while (offset < data.size) {
                val tagResult = decodeProtobufVarint(data, offset)
                if (tagResult.bytesRead == 0) break
                offset += tagResult.bytesRead

                val fieldNumber = (tagResult.value shr 3).toInt()
                val wireType = (tagResult.value and 0x07).toInt()

                if (fieldNumber == 1 && wireType == 2) {  // timestamp field (packed)
                    val lengthResult = decodeProtobufVarint(data, offset)
                    offset += lengthResult.bytesRead
                    sampleCount = lengthResult.value.toInt() / 8  // 8 bytes per int64
                    offset += lengthResult.value.toInt()
                } else if (wireType == 2) {
                    val lengthResult = decodeProtobufVarint(data, offset)
                    offset += lengthResult.bytesRead
                    offset += lengthResult.value.toInt()
                } else if (wireType == 0) {
                    val skipResult = decodeProtobufVarint(data, offset)
                    offset += skipResult.bytesRead
                } else if (wireType == 1) {
                    offset += 8
                } else if (wireType == 5) {
                    offset += 4
                }
            }

            log("  Estimated samples: $sampleCount")
            log("  ✓ Decode successful (use Python decoder for full details)")
            log("═══════════════════════════════════════════════════")
        } catch (e: Exception) {
            log("  ❌ Minimal decode error: ${e.message}")
        }
    }

    private fun decodeSleepPeriodInfo2(data: ByteArray) {
        try {
            log("╔═══════════════════════════════════════════════════╗")
            log("║  DECODING SLEEP_PERIOD_INFO_2 (0x6a)             ║")
            log("╚═══════════════════════════════════════════════════╝")
            log("  Decoder called! Data size: ${data.size} bytes")

            val timestamps = mutableListOf<Long>()
        val averageHr = mutableListOf<Float>()
        val hrTrend = mutableListOf<Float>()
        val mzci = mutableListOf<Float>()
        val dzci = mutableListOf<Float>()
        val breath = mutableListOf<Float>()
        val breathV = mutableListOf<Float>()
        val motionCount = mutableListOf<Int>()
        val sleepState = mutableListOf<Int>()
        val cv = mutableListOf<Float>()

        var offset = 1  // Skip event tag byte (0x6a)

        while (offset < data.size) {
            // Read field tag (field number + wire type)
            val tagResult = decodeProtobufVarint(data, offset)
            if (tagResult.bytesRead == 0) break
            offset += tagResult.bytesRead

            val fieldNumber = (tagResult.value shr 3).toInt()
            val wireType = (tagResult.value and 0x07).toInt()

            when (fieldNumber) {
                1 -> { // timestamp (repeated int64)
                    if (wireType == 2) { // Packed repeated
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufFixed64(data, offset)
                            offset += valueResult.bytesRead
                            timestamps.add(valueResult.value)
                        }
                    } else if (wireType == 1) { // 64-bit
                        val valueResult = decodeProtobufFixed64(data, offset)
                        offset += valueResult.bytesRead
                        timestamps.add(valueResult.value)
                    }
                }
                2 -> { // average_hr (repeated float)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufFixed32(data, offset)
                            offset += valueResult.bytesRead
                            averageHr.add(bytesToFloat(valueResult.value))
                        }
                    } else if (wireType == 5) {
                        val valueResult = decodeProtobufFixed32(data, offset)
                        offset += valueResult.bytesRead
                        averageHr.add(bytesToFloat(valueResult.value))
                    }
                }
                3 -> { // hr_trend (repeated float)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufFixed32(data, offset)
                            offset += valueResult.bytesRead
                            hrTrend.add(bytesToFloat(valueResult.value))
                        }
                    }
                }
                4 -> { // mzci (repeated float)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufFixed32(data, offset)
                            offset += valueResult.bytesRead
                            mzci.add(bytesToFloat(valueResult.value))
                        }
                    }
                }
                5 -> { // dzci (repeated float)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufFixed32(data, offset)
                            offset += valueResult.bytesRead
                            dzci.add(bytesToFloat(valueResult.value))
                        }
                    }
                }
                6 -> { // breath (repeated float)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufFixed32(data, offset)
                            offset += valueResult.bytesRead
                            breath.add(bytesToFloat(valueResult.value))
                        }
                    }
                }
                7 -> { // breath_v (repeated float)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufFixed32(data, offset)
                            offset += valueResult.bytesRead
                            breathV.add(bytesToFloat(valueResult.value))
                        }
                    }
                }
                8 -> { // motion_count (repeated int32)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufVarint(data, offset)
                            offset += valueResult.bytesRead
                            motionCount.add(valueResult.value.toInt())
                        }
                    }
                }
                9 -> { // sleep_state (repeated int32)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufVarint(data, offset)
                            offset += valueResult.bytesRead
                            sleepState.add(valueResult.value.toInt())
                        }
                    }
                }
                10 -> { // cv (repeated float)
                    if (wireType == 2) {
                        val lengthResult = decodeProtobufVarint(data, offset)
                        offset += lengthResult.bytesRead
                        val end = offset + lengthResult.value.toInt()
                        while (offset < end) {
                            val valueResult = decodeProtobufFixed32(data, offset)
                            offset += valueResult.bytesRead
                            cv.add(bytesToFloat(valueResult.value))
                        }
                    }
                }
                else -> {
                    // Skip unknown field
                    when (wireType) {
                        0 -> { // Varint
                            val skipResult = decodeProtobufVarint(data, offset)
                            offset += skipResult.bytesRead
                        }
                        1 -> offset += 8  // 64-bit
                        2 -> { // Length-delimited
                            val lengthResult = decodeProtobufVarint(data, offset)
                            offset += lengthResult.bytesRead
                            offset += lengthResult.value.toInt()
                        }
                        5 -> offset += 4  // 32-bit
                    }
                }
            }
        }

        // Print decoded results
        val numSamples = timestamps.size
        log("")
        log("═══════════════════════════════════════════════════")
        log("  Total samples: $numSamples")
        log("  Duration: ~$numSamples minutes")
        log("")

        if (numSamples == 0) {
            log("  ⚠️  No data found!")
            log("═══════════════════════════════════════════════════")
            return
        }

        // Print first and last timestamp
        if (timestamps.isNotEmpty()) {
            val firstTs = timestamps.first()
            val lastTs = timestamps.last()
            val firstDate = java.util.Date(firstTs)
            val lastDate = java.util.Date(lastTs)
            val dateFormat = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
            log("  First sample: ${dateFormat.format(firstDate)}")
            log("  Last sample:  ${dateFormat.format(lastDate)}")
        }

        log("")
        log("─────────────────────────────────────────────────────")
        log("  METRIC SUMMARY")
        log("─────────────────────────────────────────────────────")

        // Helper to print stats
        fun printStats(name: String, values: List<Float>) {
            if (values.isEmpty()) return
            val avg = values.average().toFloat()
            val min = values.minOrNull() ?: 0f
            val max = values.maxOrNull() ?: 0f
            log("")
            log("  $name:")
            log("    Count: ${values.size}")
            log("    Range: ${"%.2f".format(min)} - ${"%.2f".format(max)}")
            log("    Average: ${"%.2f".format(avg)}")
        }

        fun printIntStats(name: String, values: List<Int>) {
            if (values.isEmpty()) return
            val avg = values.average()
            val min = values.minOrNull() ?: 0
            val max = values.maxOrNull() ?: 0
            log("")
            log("  $name:")
            log("    Count: ${values.size}")
            log("    Range: $min - $max")
            log("    Average: ${"%.2f".format(avg)}")
        }

        printStats("AVERAGE HR", averageHr)
        printStats("HR TREND", hrTrend)
        printStats("MZCI (HRV)", mzci)
        printStats("DZCI (HRV)", dzci)
        printStats("BREATH RATE", breath)
        printStats("BREATH VARIABILITY", breathV)
        printIntStats("MOTION COUNT", motionCount)
        printIntStats("SLEEP STATE", sleepState)
        printStats("PPG QUALITY (CV)", cv)

        // Print first 5 samples in detail
        log("")
        log("─────────────────────────────────────────────────────")
        log("  FIRST 5 SAMPLES (DETAILED)")
        log("─────────────────────────────────────────────────────")

        val sleepStateNames = mapOf(0 to "Awake", 1 to "Light", 2 to "Deep", 3 to "REM")
        val dateFormat = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)

        for (i in 0 until minOf(5, numSamples)) {
            log("")
            log("  Sample ${i + 1}:")
            if (i < timestamps.size) {
                val date = java.util.Date(timestamps[i])
                log("    Time: ${dateFormat.format(date)}")
            }
            if (i < averageHr.size) {
                log("    Heart Rate: ${"%.1f".format(averageHr[i])} BPM")
            }
            if (i < breath.size) {
                log("    Breathing Rate: ${"%.1f".format(breath[i])} breaths/min")
            }
            if (i < sleepState.size) {
                val state = sleepState[i]
                val stateName = sleepStateNames[state] ?: "Unknown"
                log("    Sleep State: $state ($stateName)")
            }
            if (i < motionCount.size) {
                log("    Motion Count: ${motionCount[i]}")
            }
            if (i < mzci.size) {
                log("    MZCI (HRV): ${"%.2f".format(mzci[i])}")
            }
            if (i < dzci.size) {
                log("    DZCI (HRV): ${"%.2f".format(dzci[i])}")
            }
            if (i < cv.size) {
                log("    PPG Quality (CV): ${"%.4f".format(cv[i])}")
            }
        }

        log("")
        log("═══════════════════════════════════════════════════")
        } catch (e: Exception) {
            log("  ❌ DECODER EXCEPTION: ${e.message}")
            log("  Stack trace: ${e.stackTraceToString()}")
        }
    }

    private fun stopMonitoring() {
        log("=== STOP MONITORING ===")
        sendCommand(CMD_STOP)

        // Reset authentication and connection state
        isAuthenticated = false
        authNonce = null
        initState = InitState.IDLE
        isConnected = false
        pendingOperation = null

        // Check BLUETOOTH_CONNECT/SCAN only on Android 12+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                log("ERROR: Missing BLUETOOTH_CONNECT permission for stop")
                return
            }
        }

        // Stop scan if still running
        bluetoothAdapter.bluetoothLeScanner?.let { scanner ->
            stopScan(scanner)
        }
        scanCallback = null

        log("Disconnecting from device...")
        bluetoothGatt?.disconnect()
        bluetoothGatt?.close()
        bluetoothGatt = null

        statusText.text = "Stopped"
        log("Cleanup complete. Total heartbeats: $heartbeatCount")
    }

    override fun onDestroy() {
        super.onDestroy()
        log("Activity destroyed - cleaning up")
        try {
            unregisterReceiver(commandReceiver)
            Log.d(TAG, "ADB command receiver unregistered")
        } catch (e: Exception) {
            Log.e(TAG, "Error unregistering receiver: ${e.message}")
        }
        stopMonitoring()
    }
}
