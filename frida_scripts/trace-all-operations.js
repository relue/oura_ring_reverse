/**
 * Comprehensive RingOperation Tracer
 * Hooks all command-sending classes to show complete call chain
 */

Java.perform(function() {
    console.log("\n[*] Starting comprehensive operation trace...\n");

    // Helper to format hex data
    function hexDump(data) {
        if (!data || data.length === 0) return "<empty>";
        var hex = "";
        for (var i = 0; i < data.length; i++) {
            hex += ("0" + (data[i] & 0xFF).toString(16)).slice(-2) + " ";
        }
        return hex.trim();
    }

    // Helper for backtrace
    function printBacktrace(title) {
        console.log("\n[TRACE] " + title);
        console.log("═".repeat(60));
        try {
            var exceptionClass = Java.use("java.lang.Exception");
            var exception = exceptionClass.$new();
            var stackTrace = exception.getStackTrace();

            for (var i = 0; i < Math.min(stackTrace.length, 20); i++) {
                var frame = stackTrace[i];
                var className = frame.getClassName();
                var methodName = frame.getMethodName();
                var fileName = frame.getFileName();
                var lineNumber = frame.getLineNumber();

                var marker = "   ";
                if (className.indexOf("com.ouraring.oura") !== -1) {
                    marker = "⭐ ";
                } else if (className.indexOf("com.ouraring.ourakit") !== -1) {
                    marker = "🔧 ";
                } else if (className.indexOf("com.idevicesinc.sweetblue") !== -1) {
                    marker = "🔵 ";
                }

                console.log("[" + i + "] " + marker + className + "." + methodName +
                           " (" + fileName + ":" + lineNumber + ")");
            }
            console.log("═".repeat(60));
        } catch(e) {
            console.log("[!] Backtrace error: " + e);
        }
    }

    // ========================================
    // HOOK: ResetMemory (Factory Reset - 0x1a)
    // ========================================
    try {
        var ResetMemory = Java.use('com.ouraring.ourakit.operations.ResetMemory');

        ResetMemory.getRequest.implementation = function() {
            var request = this.getRequest();

            if (request) {
                console.log('\n[FACTORY RESET] ╔═══════════════════════════════════════╗');
                console.log('[FACTORY RESET] ║  🏭 ResetMemory.getRequest()          ║');
                console.log('[FACTORY RESET] ╚═══════════════════════════════════════╝');
                console.log('[FACTORY RESET]   Request Tag: 0x1a (26)');
                console.log('[FACTORY RESET]   Data: ' + hexDump(request));
                console.log('[FACTORY RESET]   BLE Factory Reset: ' + this.bleFactoryReset.value);

                printBacktrace("Factory Reset Command");
            }

            return request;
        };

        ResetMemory.parseResponse.implementation = function(response) {
            console.log('\n[FACTORY RESET] Response received:');
            console.log('[FACTORY RESET]   Data: ' + hexDump(response));
            var result = this.parseResponse(response);
            console.log('[FACTORY RESET]   Parse result: ' + result);
            return result;
        };

        console.log('[+] ResetMemory hooked');
    } catch(e) {
        console.log('[-] ResetMemory hook failed: ' + e);
    }

    // ========================================
    // HOOK: SetFeatureMode (0x22)
    // ========================================
    try {
        var SetFeatureMode = Java.use('com.ouraring.ourakit.operations.SetFeatureMode');

        SetFeatureMode.getRequest.implementation = function() {
            var request = this.getRequest();

            if (request) {
                console.log('\n[FEATURE MODE] ╔═══════════════════════════════════════╗');
                console.log('[FEATURE MODE] ║  SetFeatureMode.getRequest()         ║');
                console.log('[FEATURE MODE] ╚═══════════════════════════════════════╝');
                console.log('[FEATURE MODE]   Request Tag: 0x22 (34)');
                console.log('[FEATURE MODE]   Data: ' + hexDump(request));

                printBacktrace("SetFeatureMode Command");
            }

            return request;
        };

        console.log('[+] SetFeatureMode hooked');
    } catch(e) {
        console.log('[-] SetFeatureMode hook failed: ' + e);
    }

    // ========================================
    // HOOK: SetFeatureSubscription (0x26)
    // ========================================
    try {
        var SetFeatureSubscription = Java.use('com.ouraring.ourakit.operations.SetFeatureSubscription');

        SetFeatureSubscription.getRequest.implementation = function() {
            var request = this.getRequest();

            if (request) {
                console.log('\n[SUBSCRIPTION] ╔═══════════════════════════════════════╗');
                console.log('[SUBSCRIPTION] ║  SetFeatureSubscription.getRequest() ║');
                console.log('[SUBSCRIPTION] ╚═══════════════════════════════════════╝');
                console.log('[SUBSCRIPTION]   Request Tag: 0x26 (38)');
                console.log('[SUBSCRIPTION]   Data: ' + hexDump(request));

                printBacktrace("SetFeatureSubscription Command");
            }

            return request;
        };

        console.log('[+] SetFeatureSubscription hooked');
    } catch(e) {
        console.log('[-] SetFeatureSubscription hook failed: ' + e);
    }

    // ========================================
    // HOOK: GetFeatureStatus (0x20)
    // ========================================
    try {
        var GetFeatureStatus = Java.use('com.ouraring.ourakit.operations.GetFeatureStatus');

        GetFeatureStatus.getRequest.implementation = function() {
            var request = this.getRequest();

            if (request) {
                console.log('\n[STATUS] ╔═══════════════════════════════════════╗');
                console.log('[STATUS] ║  GetFeatureStatus.getRequest()       ║');
                console.log('[STATUS] ╚═══════════════════════════════════════╝');
                console.log('[STATUS]   Request Tag: 0x20 (32)');
                console.log('[STATUS]   Data: ' + hexDump(request));

                printBacktrace("GetFeatureStatus Command");
            }

            return request;
        };

        console.log('[+] GetFeatureStatus hooked');
    } catch(e) {
        console.log('[-] GetFeatureStatus hook failed: ' + e);
    }

    // ========================================
    // HOOK: Base RingOperation.getRequest()
    // ========================================
    try {
        var RingOperation = Java.use('com.ouraring.ourakit.operations.RingOperation');

        RingOperation.getRequest.implementation = function() {
            var request = this.getRequest();

            if (request && request.length > 0) {
                var className = this.$className;
                var tag = request[0] & 0xFF;

                // Skip if already logged by specific hooks
                if (className.indexOf('ResetMemory') === -1 &&
                    className.indexOf('SetFeatureMode') === -1 &&
                    className.indexOf('SetFeatureSubscription') === -1 &&
                    className.indexOf('GetFeatureStatus') === -1) {

                    console.log('\n[OPERATION] 📤 ' + className);
                    console.log('[OPERATION]   Tag: 0x' + tag.toString(16) + ' (' + tag + ')');
                    console.log('[OPERATION]   Data: ' + hexDump(request));
                }
            }

            return request;
        };

        console.log('[+] Base RingOperation.getRequest() hooked');
    } catch(e) {
        console.log('[-] RingOperation hook failed: ' + e);
    }

    // ========================================
    // HOOK: RingModel.factoryReset()
    // ========================================
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.factoryReset.implementation = function() {
            console.log('\n[HIGH LEVEL] ╔═══════════════════════════════════════╗');
            console.log('[HIGH LEVEL] ║  🎯 RingModel.factoryReset()         ║');
            console.log('[HIGH LEVEL] ╚═══════════════════════════════════════╝');
            console.log('[HIGH LEVEL]   MAC: ' + this.macAddress.value);

            printBacktrace("RingModel.factoryReset()");

            var result = this.factoryReset();

            console.log('[HIGH LEVEL]   Result state: ' + result);
            return result;
        };

        console.log('[+] RingModel.factoryReset() hooked');
    } catch(e) {
        console.log('[-] RingModel hook failed: ' + e);
    }

    // ========================================
    // HOOK: State Machine Transitions
    // ========================================
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.safelyTriggerTransition.implementation = function(transition) {
            var transitionStr = transition.toString();

            console.log('\n[STATE MACHINE] ⚡ Transition: ' + transitionStr);

            if (transitionStr.indexOf('FACTORY_RESET') !== -1) {
                printBacktrace("FACTORY_RESET Transition");
            }

            return this.safelyTriggerTransition(transition);
        };

        console.log('[+] RingModel.safelyTriggerTransition() hooked');
    } catch(e) {
        console.log('[-] safelyTriggerTransition hook failed: ' + e);
    }

    // ========================================
    // HOOK: Low-level BLE write for reference
    // ========================================
    try {
        var BleDevice = Java.use('com.idevicesinc.sweetblue.BleDevice');

        BleDevice.write.overload('com.idevicesinc.sweetblue.BleWrite').implementation = function(bleWrite) {
            var charUuid = bleWrite.getCharacteristicUuid();
            var data = bleWrite.getData();

            if (charUuid && charUuid.toString().indexOf('98ed0002') !== -1) {
                console.log('\n[BLE WRITE] ✍️  ' + hexDump(data));
            }

            return this.write(bleWrite);
        };

        console.log('[+] BleDevice.write hooked (minimal)');
    } catch(e) {
        console.log('[-] BleDevice hook failed: ' + e);
    }

    console.log("\n[*] All operation hooks ready! 🎯\n");
    console.log("Legend:");
    console.log("  ⭐ = Oura app code (com.ouraring.oura.*)");
    console.log("  🔧 = OuraKit operations (com.ouraring.ourakit.*)");
    console.log("  🔵 = SweetBlue BLE library\n");
});
