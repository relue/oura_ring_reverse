/**
 * Check if database has auth key stored
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  💾 DATABASE AUTH KEY CHECK                          ║");
    console.log("╚════════════════════════════════════════════════════════╝\n");

    function hexDump(byteArray) {
        if (!byteArray) return "<null>";
        var hex = "";
        for (var i = 0; i < byteArray.length; i++) {
            hex += (byteArray[i] & 0xFF).toString(16).padStart(2, '0') + " ";
        }
        return hex.trim();
    }

    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.hasPairedRing.implementation = function(bypassBondCheck) {
            console.log("\n[DATABASE] ═══════════════════════════════════════════════");
            console.log("[DATABASE]   Checking hasPairedRing(bypassBondCheck=" + bypassBondCheck + ")");

            // Try to get ring configuration from database
            try {
                var configManager = this.getRingConfigurationManager();
                console.log("[DATABASE]   RingConfigurationManager obtained");

                // Check if initialized
                var isInitialized = configManager.i();
                console.log("[DATABASE]   Is initialized: " + isInitialized);

                if (isInitialized) {
                    var config = configManager.d();
                    console.log("[DATABASE]   DbRingConfiguration obtained");

                    var authKey = config.getAuthKey();
                    if (authKey) {
                        console.log("[DATABASE]   ⚠️  AUTH KEY FOUND IN DATABASE!");
                        console.log("[DATABASE]   Auth Key: " + hexDump(authKey));
                        console.log("[DATABASE]   Length: " + authKey.length + " bytes");
                        console.log("[DATABASE]   This is why hasPairedRing() might return true!");
                    } else {
                        console.log("[DATABASE]   ✅ No auth key in database");
                    }
                }
            } catch(e) {
                console.log("[DATABASE]   Error reading database: " + e);
            }

            // Get bond address
            try {
                var bondAddress = this.bondAddress.value;
                console.log("[DATABASE]   Bond Address: " + bondAddress);
                console.log("[DATABASE]   Bond Address Length: " + bondAddress.length());
            } catch(e) {
                console.log("[DATABASE]   Bond Address: <unavailable>");
            }

            // Check bonding state
            try {
                var bonded = this.isBonded();
                console.log("[DATABASE]   isBonded(): " + bonded);
            } catch(e) {
                console.log("[DATABASE]   isBonded(): <error>");
            }

            var result = this.hasPairedRing(bypassBondCheck);

            console.log("[DATABASE]   RESULT: " + result);
            if (result) {
                console.log("[DATABASE]   ❌ Will SKIP SetAuthKey");
            } else {
                console.log("[DATABASE]   ✅ Will SEND SetAuthKey");
            }
            console.log("[DATABASE] ═══════════════════════════════════════════════\n");

            return result;
        };
        console.log('[+] hasPairedRing() hooked with database inspection');

    } catch(e) {
        console.log('[-] Hook failed: ' + e);
        console.log('    Stack: ' + e.stack);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ Database check hook ready!");
    console.log("📱 Now perform ring setup in the Oura app");
    console.log("════════════════════════════════════════════════════════\n");
});
