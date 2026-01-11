/**
 * Frida Script: Read Stored Auth Key from Database
 *
 * This script reads the authentication key that's already stored
 * in the official Oura app's database.
 *
 * Usage:
 *   frida -U Gadget -l read_stored_auth_key.js
 *
 * No action needed - it will dump all stored ring configurations
 * with their auth keys immediately.
 */

Java.perform(function() {
    console.log("\n[*] Reading stored auth keys from database...\n");

    try {
        // Get RingConfigurationManager
        var RingConfigurationObserver = Java.use('com.ouraring.oura.model.db.ringconfiguration.RingConfigurationObserver');
        var DbRingConfiguration = Java.use('com.ouraring.core.realm.model.dist.android.DbRingConfiguration');

        console.log("[*] Attempting to read from RingConfigurationObserver cache...\n");

        // Try to get cached value
        try {
            var cachedValue = RingConfigurationObserver.INSTANCE.value.getCachedValue();

            if (cachedValue) {
                console.log("╔════════════════════════════════════════════════════════╗");
                console.log("║  🔑 STORED AUTH KEY FOUND!                            ║");
                console.log("╚════════════════════════════════════════════════════════╝");

                var macAddress = cachedValue.getMacAddress();
                var authKey = cachedValue.getAuthKey();
                var serialNumber = cachedValue.getSerialNumber();
                var authenticated = cachedValue.getAuthenticated();

                console.log("MAC Address:    " + macAddress);
                console.log("Serial Number:  " + serialNumber);
                console.log("Authenticated:  " + authenticated);

                if (authKey && authKey.length > 0) {
                    // Hex format
                    var hex = "";
                    for (var i = 0; i < authKey.length; i++) {
                        hex += ("0" + (authKey[i] & 0xFF).toString(16)).slice(-2);
                        if (i < authKey.length - 1) hex += " ";
                    }
                    console.log("\nAuth Key (Hex): " + hex);

                    // Java format
                    var javaArray = "new byte[]{";
                    for (var i = 0; i < authKey.length; i++) {
                        javaArray += "(byte)0x" + ("0" + (authKey[i] & 0xFF).toString(16)).slice(-2);
                        if (i < authKey.length - 1) javaArray += ", ";
                    }
                    javaArray += "}";
                    console.log("\nJava Format:\n" + javaArray);

                    // Kotlin format
                    var kotlinArray = "byteArrayOf(";
                    for (var i = 0; i < authKey.length; i++) {
                        kotlinArray += "0x" + ("0" + (authKey[i] & 0xFF).toString(16)).slice(-2);
                        if (i < authKey.length - 1) kotlinArray += ", ";
                    }
                    kotlinArray += ")";
                    console.log("\nKotlin Format:\n" + kotlinArray);

                    console.log("\n" + "═".repeat(56));
                    console.log("✓ Use this key in your custom app!");
                    console.log("═".repeat(56) + "\n");
                } else {
                    console.log("\n⚠ Auth key is empty or null");
                    console.log("  Ring may not have been set up yet.");
                    console.log("  Try running capture_auth_key.js during setup.\n");
                }
            } else {
                console.log("⚠ No cached ring configuration found");
                console.log("  Official app may not have connected to ring yet.\n");
            }
        } catch(e) {
            console.log("⚠ Could not read cached value: " + e);
            console.log("  Official app may need to connect to ring first.\n");
        }

    } catch(e) {
        console.log('[-] Script failed: ' + e);
        console.log('    Stack: ' + e.stack);
    }

    console.log("\n[*] Done!\n");
});
