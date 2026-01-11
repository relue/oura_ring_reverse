/**
 * Comprehensive Auth Capture Script
 * Captures auth key generation, SetAuthKey command, and database storage
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  🔐 COMPREHENSIVE AUTH KEY CAPTURE                    ║");
    console.log("╚════════════════════════════════════════════════════════╝\n");

    // Helper to format hex data
    function hexDump(data) {
        if (!data || data.length === 0) return "<empty>";
        var hex = "";
        for (var i = 0; i < data.length; i++) {
            hex += ("0" + (data[i] & 0xFF).toString(16)).slice(-2);
            if (i < data.length - 1) hex += " ";
        }
        return hex.trim();
    }

    // ========================================
    // HOOK 1: Auth Key Generation (v0.k())
    // ========================================
    try {
        var v0 = Java.use('com.ouraring.oura.ringtracker.v0');

        v0.k.implementation = function() {
            console.log("\n[1] ╔═══════════════════════════════════════════════════════╗");
            console.log("[1] ║  🎲 AUTH KEY GENERATION (v0.k())                      ║");
            console.log("[1] ╚═══════════════════════════════════════════════════════╝");

            var authKey = this.k();

            if (authKey && authKey.length === 16) {
                console.log("[1] ✅ Generated 16-byte auth key:");
                console.log("[1]   Hex:    " + hexDump(authKey));

                // Java format
                var javaArray = "new byte[]{";
                for (var i = 0; i < authKey.length; i++) {
                    javaArray += "(byte)0x" + ("0" + (authKey[i] & 0xFF).toString(16)).slice(-2);
                    if (i < authKey.length - 1) javaArray += ", ";
                }
                javaArray += "}";
                console.log("[1]   Java:   " + javaArray);

                // Kotlin format
                var kotlinArray = "byteArrayOf(";
                for (var i = 0; i < authKey.length; i++) {
                    kotlinArray += "0x" + ("0" + (authKey[i] & 0xFF).toString(16)).slice(-2);
                    if (i < authKey.length - 1) kotlinArray += ", ";
                }
                kotlinArray += ")";
                console.log("[1]   Kotlin: " + kotlinArray);
            } else {
                console.log("[1] ⚠️  Invalid key length: " + (authKey ? authKey.length : "null"));
            }

            return authKey;
        };

        console.log('[+] v0.k() (key generation) hooked');
    } catch(e) {
        console.log('[-] v0.k() hook failed: ' + e);
    }

    // ========================================
    // HOOK 2: SetAuthKey Constructor
    // ========================================
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.$init.implementation = function(key) {
            console.log("\n[2] ╔═══════════════════════════════════════════════════════╗");
            console.log("[2] ║  📤 SetAuthKey CONSTRUCTOR                            ║");
            console.log("[2] ╚═══════════════════════════════════════════════════════╝");

            if (key && key.length === 16) {
                console.log("[2] ✅ SetAuthKey initialized with 16-byte key:");
                console.log("[2]   Hex:    " + hexDump(key));

                var javaArray = "new byte[]{";
                for (var i = 0; i < key.length; i++) {
                    javaArray += "(byte)0x" + ("0" + (key[i] & 0xFF).toString(16)).slice(-2);
                    if (i < key.length - 1) javaArray += ", ";
                }
                javaArray += "}";
                console.log("[2]   Java:   " + javaArray);

                var kotlinArray = "byteArrayOf(";
                for (var i = 0; i < key.length; i++) {
                    kotlinArray += "0x" + ("0" + (key[i] & 0xFF).toString(16)).slice(-2);
                    if (i < key.length - 1) kotlinArray += ", ";
                }
                kotlinArray += ")";
                console.log("[2]   Kotlin: " + kotlinArray);
            } else {
                console.log("[2] ⚠️  Invalid key length: " + (key ? key.length : "null"));
            }

            return this.$init(key);
        };

        console.log('[+] SetAuthKey.$init() hooked');
    } catch(e) {
        console.log('[-] SetAuthKey.$init() hook failed: ' + e);
    }

    // ========================================
    // HOOK 3: SetAuthKey.getRequest()
    // ========================================
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.getRequest.implementation = function() {
            var request = this.getRequest();

            if (request) {
                console.log("\n[3] ╔═══════════════════════════════════════════════════════╗");
                console.log("[3] ║  🚀 SetAuthKey SENDING TO RING                        ║");
                console.log("[3] ╚═══════════════════════════════════════════════════════╝");
                console.log("[3]   Command Tag: 0x24 (SetAuthKey)");
                console.log("[3]   Full Packet: " + hexDump(request));

                if (request.length >= 17) {
                    var keyBytes = [];
                    for (var i = 1; i < 17; i++) {
                        keyBytes.push(request[i]);
                    }
                    console.log("[3]   Auth Key:    " + hexDump(keyBytes));
                }
            }

            return request;
        };

        console.log('[+] SetAuthKey.getRequest() hooked');
    } catch(e) {
        console.log('[-] SetAuthKey.getRequest() hook failed: ' + e);
    }

    // ========================================
    // HOOK 4: SetAuthKey.parseResponse()
    // ========================================
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 3) {
                var status = response[2] & 0xFF;
                console.log("\n[4] ╔═══════════════════════════════════════════════════════╗");
                console.log("[4] ║  📥 SetAuthKey RESPONSE FROM RING                     ║");
                console.log("[4] ╚═══════════════════════════════════════════════════════╝");
                console.log("[4]   Response: " + hexDump(response));
                console.log("[4]   Status:   0x" + status.toString(16));

                if (status === 0) {
                    console.log("[4]   ✅ SUCCESS - Auth key stored in ring!");
                } else if (status === 5) {
                    console.log("[4]   ⚠️  PRODUCTION_TEST_MODE (acceptable)");
                } else {
                    console.log("[4]   ❌ FAILED - Status: " + status);
                }
            }

            return result;
        };

        console.log('[+] SetAuthKey.parseResponse() hooked');
    } catch(e) {
        console.log('[-] SetAuthKey.parseResponse() hook failed: ' + e);
    }

    // ========================================
    // HOOK 5: Database Storage (d1.I())
    // ========================================
    try {
        var d1 = Java.use('com.ouraring.core.realm.timeseries.d1');

        d1.I.implementation = function(dbRingConfiguration) {
            console.log("\n[5] ╔═══════════════════════════════════════════════════════╗");
            console.log("[5] ║  💾 STORING AUTH KEY IN DATABASE                     ║");
            console.log("[5] ╚═══════════════════════════════════════════════════════╝");

            if (dbRingConfiguration) {
                try {
                    var authKey = dbRingConfiguration.getAuthKey();
                    var macAddress = dbRingConfiguration.getMacAddress();
                    var serialNumber = dbRingConfiguration.getSerialNumber();

                    console.log("[5]   MAC Address:    " + macAddress);
                    console.log("[5]   Serial Number:  " + serialNumber);

                    if (authKey && authKey.length > 0) {
                        console.log("[5]   Auth Key (Hex): " + hexDump(authKey));

                        var javaArray = "new byte[]{";
                        for (var i = 0; i < authKey.length; i++) {
                            javaArray += "(byte)0x" + ("0" + (authKey[i] & 0xFF).toString(16)).slice(-2);
                            if (i < authKey.length - 1) javaArray += ", ";
                        }
                        javaArray += "}";
                        console.log("[5]   Java Format:    " + javaArray);

                        var kotlinArray = "byteArrayOf(";
                        for (var i = 0; i < authKey.length; i++) {
                            kotlinArray += "0x" + ("0" + (authKey[i] & 0xFF).toString(16)).slice(-2);
                            if (i < authKey.length - 1) kotlinArray += ", ";
                        }
                        kotlinArray += ")";
                        console.log("[5]   Kotlin Format:  " + kotlinArray);

                        console.log("[5]   ✅ Auth key will be stored in database");
                    } else {
                        console.log("[5]   ⚠️  Auth key is empty");
                    }
                } catch(e) {
                    console.log("[5]   Error reading config: " + e);
                }
            }

            return this.I(dbRingConfiguration);
        };

        console.log('[+] d1.I() (database storage) hooked');
    } catch(e) {
        console.log('[-] d1.I() hook failed: ' + e);
    }

    // ========================================
    // HOOK 6: GetAuthNonce
    // ========================================
    try {
        var GetAuthNonce = Java.use('com.ouraring.ourakit.operations.GetAuthNonce');

        GetAuthNonce.getRequest.implementation = function() {
            var request = this.getRequest();
            console.log("\n[6] 📤 GetAuthNonce: " + hexDump(request));
            return request;
        };

        GetAuthNonce.parseResponse.implementation = function(response) {
            if (response && response.length >= 19) {
                var nonce = [];
                for (var i = 3; i < 19; i++) {
                    nonce.push(response[i]);
                }
                console.log("[6] 📥 Nonce received: " + hexDump(nonce));
            }
            return this.parseResponse(response);
        };

        console.log('[+] GetAuthNonce hooked');
    } catch(e) {
        console.log('[-] GetAuthNonce hook failed: ' + e);
    }

    // ========================================
    // HOOK 7: Authenticate
    // ========================================
    try {
        var Authenticate = Java.use('com.ouraring.ourakit.operations.Authenticate');

        Authenticate.getRequest.implementation = function() {
            var request = this.getRequest();
            if (request && request.length >= 20) {
                var encrypted = [];
                for (var i = 3; i < 19; i++) {
                    encrypted.push(request[i]);
                }
                console.log("\n[7] 📤 Authenticate (encrypted nonce): " + hexDump(encrypted));
            }
            return request;
        };

        Authenticate.parseResponse.implementation = function(response) {
            if (response && response.length >= 4) {
                var status = response[3] & 0xFF;
                console.log("[7] 📥 Authenticate response: Status = 0x" + status.toString(16) +
                           (status === 0 ? " ✅ SUCCESS" : " ❌ FAILED"));
            }
            return this.parseResponse(response);
        };

        console.log('[+] Authenticate hooked');
    } catch(e) {
        console.log('[-] Authenticate hook failed: ' + e);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ All authentication hooks ready!");
    console.log("📱 Now perform ring setup in the Oura app");
    console.log("════════════════════════════════════════════════════════\n");
});
