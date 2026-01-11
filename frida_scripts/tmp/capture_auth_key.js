/**
 * Frida Script: Capture Authentication Key
 *
 * This script intercepts the SetAuthKey operation and logs the 16-byte key
 * that the official Oura app sends to the ring.
 *
 * Usage:
 *   frida -U Gadget -l capture_auth_key.js
 *
 * Then trigger ring setup in official app.
 * The auth key will be printed - save it for your custom app!
 */

Java.perform(function() {
    console.log("\n[*] Auth Key Capture Script Loaded");
    console.log("[*] Waiting for SetAuthKey operation...\n");

    try {
        // Hook SetAuthKey constructor
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.$init.implementation = function(key) {
            console.log("\n╔════════════════════════════════════════════════════════╗");
            console.log("║  🔑 AUTH KEY CAPTURED!                                ║");
            console.log("╚════════════════════════════════════════════════════════╝");

            // Print key in multiple formats
            if (key && key.length === 16) {
                // Hex format
                var hex = "";
                for (var i = 0; i < key.length; i++) {
                    hex += ("0" + (key[i] & 0xFF).toString(16)).slice(-2);
                    if (i < key.length - 1) hex += " ";
                }
                console.log("Hex:    " + hex);

                // Java byte array format (for easy copy-paste)
                var javaArray = "new byte[]{";
                for (var i = 0; i < key.length; i++) {
                    javaArray += "(byte)0x" + ("0" + (key[i] & 0xFF).toString(16)).slice(-2);
                    if (i < key.length - 1) javaArray += ", ";
                }
                javaArray += "}";
                console.log("\nJava:   " + javaArray);

                // Kotlin byte array format
                var kotlinArray = "byteArrayOf(";
                for (var i = 0; i < key.length; i++) {
                    kotlinArray += "0x" + ("0" + (key[i] & 0xFF).toString(16)).slice(-2);
                    if (i < key.length - 1) kotlinArray += ", ";
                }
                kotlinArray += ")";
                console.log("\nKotlin: " + kotlinArray);

                console.log("\n" + "═".repeat(56));
                console.log("✓ Save this key for your custom app!");
                console.log("═".repeat(56) + "\n");
            } else {
                console.log("⚠ Invalid key length: " + (key ? key.length : "null"));
            }

            // Call original constructor
            return this.$init(key);
        };

        console.log('[+] SetAuthKey constructor hooked');

        // Also hook the getRequest to see when it's sent
        SetAuthKey.getRequest.implementation = function() {
            var request = this.getRequest();
            if (request) {
                console.log("\n[→] SetAuthKey.getRequest() called - sending to ring");
                console.log("    Command: 0x24 (SetAuthKey)");
            }
            return request;
        };

        console.log('[+] SetAuthKey.getRequest() hooked');

        // Hook response handler
        SetAuthKey.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 3) {
                var status = response[2] & 0xFF;
                console.log("\n[←] SetAuthKey response received");
                console.log("    Status: 0x" + status.toString(16));
                console.log("    " + (status === 0 ? "✓ SUCCESS" :
                                      status === 5 ? "⚠ PRODUCTION_TEST_MODE (acceptable)" :
                                      "✗ FAILED"));
            }

            return result;
        };

        console.log('[+] SetAuthKey.parseResponse() hooked');

    } catch(e) {
        console.log('[-] Hook failed: ' + e);
    }

    console.log("\n[*] Ready! Now setup a ring in the official app.\n");
});
