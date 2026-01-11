/**
 * Force BLE Factory Reset on Ring
 *
 * This script forces the official Oura app to send a FULL BLE factory reset
 * command (0x1a 0x01 0x01) to the ring, which will clear the stored auth key.
 *
 * Usage:
 *   1. Start frida: frida -U Gadget -l force_ble_factory_reset.js
 *   2. Connect to ring in official app
 *   3. Trigger factory reset in app (or let script auto-trigger)
 *   4. Verify reset command sent
 *   5. Kill and restart app, then try setup again
 */

Java.perform(function() {
    console.log("\n[*] BLE Factory Reset Override Script Loaded");
    console.log("[*] This will force a FULL factory reset that clears auth key\n");

    try {
        // Hook ResetMemory to force bleFactoryReset=true
        var ResetMemory = Java.use('com.ouraring.ourakit.operations.ResetMemory');

        // Intercept constructor to always use BLE factory reset
        ResetMemory.$init.overload('boolean').implementation = function(bleFactoryReset) {
            console.log("\n╔════════════════════════════════════════════════════════╗");
            console.log("║  🔧 OVERRIDING ResetMemory CONSTRUCTOR                ║");
            console.log("╚════════════════════════════════════════════════════════╝");
            console.log("[*] Original bleFactoryReset: " + bleFactoryReset);
            console.log("[*] FORCING bleFactoryReset = true");
            console.log("[!] This will send [0x1a, 0x01, 0x01] to CLEAR AUTH KEY\n");

            // Always call with true to force BLE factory reset
            return this.$init(true);
        };

        console.log('[+] ResetMemory constructor hooked (force bleFactoryReset=true)');

        // Also hook getRequest to confirm what's being sent
        ResetMemory.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[→] ═══════════════════════════════════════════════════");
            console.log("[→]   ResetMemory.getRequest() - Sending to ring:");

            if (request && request.length > 0) {
                var hex = "";
                for (var i = 0; i < request.length; i++) {
                    hex += (request[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                }
                console.log("[→]   Command: " + hex.trim());

                // Check if it's the correct BLE factory reset command
                if (request.length >= 3 &&
                    (request[0] & 0xFF) === 0x1a &&
                    (request[1] & 0xFF) === 0x01 &&
                    (request[2] & 0xFF) === 0x01) {
                    console.log("[→]   ✅ CORRECT: Full BLE factory reset!");
                    console.log("[→]   This will clear the auth key from ring");
                } else if (request.length >= 2 &&
                           (request[0] & 0xFF) === 0x1a &&
                           (request[1] & 0xFF) === 0x00) {
                    console.log("[→]   ⚠️  WARNING: Data reset only (keeps auth key)");
                } else {
                    console.log("[→]   ℹ️  Unknown command format");
                }
            }
            console.log("[→] ═══════════════════════════════════════════════════\n");

            return request;
        };

        console.log('[+] ResetMemory.getRequest() hooked (monitor commands)');

        // Hook parseResponse to see result
        ResetMemory.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 3) {
                var status = response[2] & 0xFF;
                console.log("\n[←] ═══════════════════════════════════════════════════");
                console.log("[←]   ResetMemory response from ring:");

                var hex = "";
                for (var i = 0; i < response.length; i++) {
                    hex += (response[i] & 0xFF).toString(16).padStart(2, '0') + " ";
                }
                console.log("[←]   Response: " + hex.trim());
                console.log("[←]   Status: 0x" + status.toString(16).padStart(2, '0'));

                if (status === 0) {
                    console.log("[←]   ✅ SUCCESS - Ring fully reset!");
                    console.log("[←]   Auth key has been cleared from ring");
                    console.log("[←]   You can now setup the ring as new");
                } else {
                    console.log("[←]   ❌ FAILED - Status: " + status);
                }
                console.log("[←] ═══════════════════════════════════════════════════\n");
            }

            return result;
        };

        console.log('[+] ResetMemory.parseResponse() hooked (monitor results)');

    } catch(e) {
        console.log('[-] Hook failed: ' + e);
        console.log('    Stack: ' + e.stack);
    }

    // Also provide a way to manually trigger factory reset
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        console.log('\n[*] Manual trigger available:');
        console.log('[*] To manually trigger reset, find RingModel instance and call:');
        console.log('[*]   ringModel.bleFactoryReset()');

        // Try to hook bleFactoryReset to see when it's called
        RingModel.bleFactoryReset.implementation = function() {
            console.log("\n╔════════════════════════════════════════════════════════╗");
            console.log("║  🚀 BLE FACTORY RESET TRIGGERED                       ║");
            console.log("╚════════════════════════════════════════════════════════╝");
            console.log("[*] RingModel.bleFactoryReset() called");
            console.log("[*] This should send the full reset command\n");

            return this.bleFactoryReset();
        };

        console.log('[+] RingModel.bleFactoryReset() hooked (trigger monitor)');

    } catch(e) {
        console.log('[-] RingModel hook failed: ' + e);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ Ready to intercept factory reset!");
    console.log("📱 Now trigger factory reset in the Oura app");
    console.log("════════════════════════════════════════════════════════\n");
});
