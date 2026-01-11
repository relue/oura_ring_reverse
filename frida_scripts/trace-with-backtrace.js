/**
 * Enhanced BLE Trace with Java Backtraces
 * Shows which Java methods call each BLE operation
 */

Java.perform(function() {
    console.log("\n[*] Starting BLE trace with backtraces...\n");

    // Helper function to print Java backtrace
    function printBacktrace(title) {
        console.log("\n[BACKTRACE] " + title);
        console.log("═══════════════════════════════════════");

        try {
            var threadClass = Java.use("java.lang.Thread");
            var exceptionClass = Java.use("java.lang.Exception");
            var exception = exceptionClass.$new();
            var stackTrace = exception.getStackTrace();

            for (var i = 0; i < Math.min(stackTrace.length, 15); i++) {
                var frame = stackTrace[i];
                var className = frame.getClassName();
                var methodName = frame.getMethodName();
                var fileName = frame.getFileName();
                var lineNumber = frame.getLineNumber();

                // Highlight Oura-specific classes
                if (className.indexOf("com.ouraring") !== -1) {
                    console.log("[" + i + "] ⭐ " + className + "." + methodName +
                               " (" + fileName + ":" + lineNumber + ")");
                } else if (className.indexOf("com.idevicesinc.sweetblue") !== -1) {
                    console.log("[" + i + "] 🔵 " + className + "." + methodName +
                               " (" + fileName + ":" + lineNumber + ")");
                } else {
                    console.log("[" + i + "]    " + className + "." + methodName +
                               " (" + fileName + ":" + lineNumber + ")");
                }
            }
            console.log("═══════════════════════════════════════\n");
        } catch(e) {
            console.log("[!] Backtrace error: " + e);
            console.log("═══════════════════════════════════════\n");
        }
    }

    // Helper to format hex data
    function hexDump(data) {
        if (!data || data.length === 0) return "<empty>";
        var hex = "";
        for (var i = 0; i < data.length; i++) {
            hex += ("0" + (data[i] & 0xFF).toString(16)).slice(-2) + " ";
        }
        return hex.trim();
    }

    // ========================================
    // HOOK: P_BleDeviceImpl.invokeReadWriteCallback
    // This captures ALL read/write/notification events
    // ========================================
    try {
        var P_BleDeviceImpl = Java.use('com.idevicesinc.sweetblue.internal.P_BleDeviceImpl');

        P_BleDeviceImpl.invokeReadWriteCallback.overload('com.idevicesinc.sweetblue.ReadWriteListener', 'com.idevicesinc.sweetblue.ReadWriteListener$ReadWriteEvent').implementation = function(listener, event) {

            try {
                var typeStr = event.type() ? event.type().toString() : "UNKNOWN";
                var targetStr = event.target() ? event.target().toString() : "UNKNOWN";
                var statusStr = event.status() ? event.status().toString() : "UNKNOWN";

                console.log('\n[BLE] ╔═══════════════════════════════════════╗');
                console.log('[BLE] ║  ' + typeStr + ' Event                    ║');
                console.log('[BLE] ╚═══════════════════════════════════════╝');
                console.log('[BLE]   Type: ' + typeStr);
                console.log('[BLE]   Target: ' + targetStr);
                console.log('[BLE]   Status: ' + statusStr);

                var serviceUuid = event.serviceUuid();
                var charUuid = event.charUuid();

                if (serviceUuid) {
                    console.log('[BLE]   Service: ' + serviceUuid);
                }
                if (charUuid) {
                    console.log('[BLE]   Char: ' + charUuid);
                }

                var data = event.data();
                if (data && data.length > 0) {
                    console.log('[BLE]   Data (' + data.length + ' bytes): ' + hexDump(data));
                }

                // Print backtrace for WRITE operations and NOTIFICATIONS
                if (typeStr.indexOf("WRITE") !== -1 || typeStr.indexOf("NOTIFICATION") !== -1) {
                    printBacktrace(typeStr + " at " + charUuid);
                }

                console.log('[BLE] ═══════════════════════════════════════\n');
            } catch(e) {
                console.log('[!] Event parse error: ' + e);
            }

            return this.invokeReadWriteCallback(listener, event);
        };

        console.log('[+] P_BleDeviceImpl.invokeReadWriteCallback hooked with backtrace');
    } catch(e) {
        console.log('[-] P_BleDeviceImpl hook failed: ' + e);
    }

    // ========================================
    // HOOK: BleDevice.write (additional detail)
    // ========================================
    try {
        var BleDevice = Java.use('com.idevicesinc.sweetblue.BleDevice');

        BleDevice.write.overload('com.idevicesinc.sweetblue.BleWrite').implementation = function(bleWrite) {
            try {
                var charUuid = bleWrite.getCharacteristicUuid();
                var serviceUuid = bleWrite.getServiceUuid();
                var data = bleWrite.getData();

                console.log('\n[WRITE] ✍️  BleDevice.write() called');
                console.log('[WRITE]   Service: ' + serviceUuid);
                console.log('[WRITE]   Char: ' + charUuid);
                if (data) {
                    console.log('[WRITE]   Data: ' + hexDump(data));
                }

                // Show who's calling this write
                printBacktrace("WRITE from BleDevice.write()");

            } catch(e) {
                console.log('[WRITE] Parse error: ' + e);
            }
            return this.write(bleWrite);
        };

        console.log('[+] BleDevice.write hooked with backtrace');
    } catch(e) {
        console.log('[-] BleDevice.write hook failed: ' + e);
    }

    // ========================================
    // HOOK: RingOperation.getRequest (see outgoing commands)
    // ========================================
    try {
        var RingOperation = Java.use('com.ouraring.ourakit.operations.RingOperation');

        RingOperation.getRequest.implementation = function() {
            var request = this.getRequest();

            if (request && request.length > 0) {
                var className = this.$className;
                console.log('\n[CMD] 📤 RingOperation.getRequest()');
                console.log('[CMD]   Class: ' + className);
                console.log('[CMD]   Request: ' + hexDump(request));

                printBacktrace("Command from " + className);
            }

            return request;
        };

        console.log('[+] RingOperation.getRequest hooked');
    } catch(e) {
        console.log('[-] RingOperation hook failed: ' + e);
    }

    // ========================================
    // HOOK: DeviceListenerImpl.onCharacteristicChanged
    // LOW LEVEL notification capture - this is critical!
    // ========================================
    try {
        var DeviceListenerImpl = Java.use('com.idevicesinc.sweetblue.internal.android.DeviceListenerImpl');

        DeviceListenerImpl.onCharacteristicChanged.implementation = function(gatt, characteristic) {
            try {
                var serviceUuid = characteristic.getService().getUuid().toString();
                var charUuid = characteristic.getUuid().toString();
                var value = characteristic.getValue();

                var hexValue = '';
                if (value) {
                    for (var i = 0; i < value.length; i++) {
                        hexValue += ('0' + (value[i] & 0xFF).toString(16)).slice(-2) + ' ';
                    }
                }

                console.log('\n[NOTIFY] ╔═══════════════════════════════════════╗');
                console.log('[NOTIFY] ║  🔔 NOTIFICATION (LOW LEVEL)         ║');
                console.log('[NOTIFY] ╚═══════════════════════════════════════╝');
                console.log('[NOTIFY]   Service: ' + serviceUuid);
                console.log('[NOTIFY]   Char: ' + charUuid);
                console.log('[NOTIFY]   Data (' + value.length + ' bytes): ' + hexValue);

                // Print backtrace for ALL notifications
                printBacktrace("NOTIFICATION from " + charUuid);

                console.log('[NOTIFY] ═══════════════════════════════════════\n');
            } catch(e) {
                console.log('[NOTIFY] Parse error: ' + e);
            }
            return this.onCharacteristicChanged(gatt, characteristic);
        };

        console.log('[+] DeviceListenerImpl.onCharacteristicChanged hooked (LOW LEVEL notifications)');
    } catch(e) {
        console.log('[-] DeviceListenerImpl hook failed: ' + e);
    }

    console.log("\n[*] Backtrace hooks ready! 🎯");
    console.log("[*] ⭐ = Oura code | 🔵 = SweetBlue library\n");
});
