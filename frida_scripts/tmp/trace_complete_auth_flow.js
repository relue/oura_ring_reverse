/**
 * Complete Authentication Flow Tracer
 * Hooks all steps: GetAuthNonce → Encrypt → Authenticate
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  🔐 COMPLETE AUTHENTICATION FLOW TRACER              ║");
    console.log("╚════════════════════════════════════════════════════════╝\n");

    function hexDump(byteArray) {
        if (!byteArray) return "<null>";
        var hex = "";
        for (var i = 0; i < byteArray.length; i++) {
            hex += (byteArray[i] & 0xFF).toString(16).padStart(2, '0') + " ";
        }
        return hex.trim();
    }

    function hexDumpCompact(byteArray) {
        if (!byteArray) return "<null>";
        var hex = "";
        for (var i = 0; i < byteArray.length; i++) {
            hex += (byteArray[i] & 0xFF).toString(16).padStart(2, '0');
        }
        return hex;
    }

    var hookCount = 0;

    // ==================================================
    // STEP 1: GetAuthNonce - Request nonce from ring
    // ==================================================
    try {
        var GetAuthNonce = Java.use('com.ouraring.ourakit.operations.GetAuthNonce');

        // Hook constructor
        GetAuthNonce.$init.implementation = function() {
            console.log("\n╔═══════════════════════════════════════════════════╗");
            console.log("║  STEP 1: GetAuthNonce() Constructor              ║");
            console.log("╚═══════════════════════════════════════════════════╝");
            console.log("   Creating GetAuthNonce operation");
            console.log("   → Will request 16-byte random nonce from ring");
            console.log("═══════════════════════════════════════════════════\n");
            return this.$init();
        };

        // Hook getRequest
        GetAuthNonce.getRequest.implementation = function() {
            var request = this.getRequest();
            console.log("\n╔═══════════════════════════════════════════════════╗");
            console.log("║  STEP 1a: GetAuthNonce.getRequest()              ║");
            console.log("╚═══════════════════════════════════════════════════╝");
            console.log("   Command: " + hexDump(request));
            console.log("   Expected: 2f 01 2b");
            console.log("   📤 SENDING TO RING");
            console.log("═══════════════════════════════════════════════════\n");
            return request;
        };

        // Hook parseResponse
        GetAuthNonce.parseResponse.implementation = function(response) {
            console.log("\n╔═══════════════════════════════════════════════════╗");
            console.log("║  STEP 1b: GetAuthNonce.parseResponse()           ║");
            console.log("╚═══════════════════════════════════════════════════╝");
            console.log("   📥 RECEIVED FROM RING");
            console.log("   Response: " + hexDump(response));
            console.log("   Length: " + response.length + " bytes");

            if (response && response.length >= 18) {
                console.log("   Breakdown:");
                console.log("     Byte 0 (Tag):     0x" + (response[0] & 0xFF).toString(16).padStart(2, '0') + " (expected 0x2f)");
                console.log("     Byte 1 (Subcmd):  0x" + (response[1] & 0xFF).toString(16).padStart(2, '0') + " (expected 0x02)");
                console.log("     Byte 2 (ExtTag):  0x" + (response[2] & 0xFF).toString(16).padStart(2, '0') + " (expected 0x2c)");

                var nonceBytes = [];
                for (var i = 0; i < 16; i++) {
                    nonceBytes.push((response[3 + i] & 0xFF).toString(16).padStart(2, '0'));
                }
                console.log("     Nonce (16 bytes): " + nonceBytes.join(' '));
                console.log("   🔑 Ring generated random nonce!");
                console.log("   → This nonce will be encrypted with auth key");
            }
            console.log("═══════════════════════════════════════════════════\n");

            return this.parseResponse(response);
        };

        // Hook onCompleted to see nonce passed to next stage
        GetAuthNonce.onCompleted.implementation = function(result) {
            if (result && result.length === 16) {
                console.log("\n╔═══════════════════════════════════════════════════╗");
                console.log("║  STEP 1c: GetAuthNonce.onCompleted()             ║");
                console.log("╚═══════════════════════════════════════════════════╝");
                console.log("   Extracted Nonce: " + hexDump(result));
                console.log("   → Passing to encryption stage");
                console.log("═══════════════════════════════════════════════════\n");
            }
            return this.onCompleted(result);
        };

        console.log('[+] GetAuthNonce hooks installed');
        hookCount += 4;
    } catch(e) {
        console.log('[-] GetAuthNonce hook failed: ' + e);
    }

    // ==================================================
    // STEP 2: AES Encryption - Encrypt nonce with auth key
    // ==================================================
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');

        // Hook SecretKeySpec creation (shows the auth key)
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
            if (algorithm === "AES") {
                console.log("\n╔═══════════════════════════════════════════════════╗");
                console.log("║  STEP 2: SecretKeySpec (Auth Key Setup)          ║");
                console.log("╚═══════════════════════════════════════════════════╝");
                console.log("   Algorithm: " + algorithm);
                console.log("   Auth Key: " + hexDump(key));
                console.log("   Key Length: " + key.length + " bytes");
                console.log("═══════════════════════════════════════════════════\n");
            }
            return this.$init(key, algorithm);
        };

        // Hook Cipher.init (shows encryption mode)
        Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
            var modeStr = (mode === 1) ? "ENCRYPT" : (mode === 2) ? "DECRYPT" : "MODE_" + mode;

            if (mode === 1) {  // ENCRYPT mode
                console.log("\n╔═══════════════════════════════════════════════════╗");
                console.log("║  STEP 2a: Cipher.init() - ENCRYPT mode           ║");
                console.log("╚═══════════════════════════════════════════════════╝");
                console.log("   Mode: " + modeStr);
                console.log("   Algorithm: " + this.getAlgorithm());
                console.log("   🔒 Ready to encrypt nonce");
                console.log("═══════════════════════════════════════════════════\n");
            }

            return this.init(mode, key);
        };

        // Hook Cipher.doFinal (shows encryption operation)
        Cipher.doFinal.overload('[B').implementation = function(input) {
            var algorithm = this.getAlgorithm();
            var output = this.doFinal(input);

            // Only log AES operations (likely authentication)
            if (algorithm.indexOf("AES") >= 0 && input.length === 16) {
                console.log("\n╔═══════════════════════════════════════════════════╗");
                console.log("║  STEP 2b: Cipher.doFinal() - ENCRYPTING NONCE    ║");
                console.log("╚═══════════════════════════════════════════════════╝");
                console.log("   Algorithm: " + algorithm);
                console.log("   Input (Nonce): " + hexDump(input));
                console.log("   Output (Encrypted): " + hexDump(output));
                console.log("   🔐 Nonce encrypted with auth key!");
                console.log("═══════════════════════════════════════════════════\n");
            }

            return output;
        };

        console.log('[+] AES encryption hooks installed');
        hookCount += 3;
    } catch(e) {
        console.log('[-] AES encryption hook failed: ' + e);
    }

    // ==================================================
    // STEP 3: Authenticate - Send encrypted nonce to ring
    // ==================================================
    try {
        var Authenticate = Java.use('com.ouraring.ourakit.operations.Authenticate');

        // Hook constructor (receives encrypted nonce)
        Authenticate.$init.implementation = function(encryptedNonce) {
            console.log("\n╔═══════════════════════════════════════════════════╗");
            console.log("║  STEP 3: Authenticate() Constructor               ║");
            console.log("╚═══════════════════════════════════════════════════╝");
            console.log("   Encrypted Nonce: " + hexDump(encryptedNonce));
            console.log("   Length: " + encryptedNonce.length + " bytes");
            console.log("   → Will send to ring for verification");
            console.log("═══════════════════════════════════════════════════\n");
            return this.$init(encryptedNonce);
        };

        // Hook getRequest (builds the command)
        Authenticate.getRequest.implementation = function() {
            var request = this.getRequest();

            if (request) {
                console.log("\n╔═══════════════════════════════════════════════════╗");
                console.log("║  STEP 3a: Authenticate.getRequest()               ║");
                console.log("╚═══════════════════════════════════════════════════╝");
                console.log("   Full Command: " + hexDump(request));
                console.log("   Length: " + request.length + " bytes (should be 19)");
                console.log("   Breakdown:");
                console.log("     Byte 0:     0x" + (request[0] & 0xFF).toString(16).padStart(2, '0') + " (tag, expected 0x2f)");
                console.log("     Byte 1:     0x" + (request[1] & 0xFF).toString(16).padStart(2, '0') + " (subcmd, expected 0x11)");
                console.log("     Byte 2:     0x" + (request[2] & 0xFF).toString(16).padStart(2, '0') + " (ext tag, expected 0x2d)");

                if (request.length >= 19) {
                    var encNonce = [];
                    for (var i = 3; i < 19; i++) {
                        encNonce.push((request[i] & 0xFF).toString(16).padStart(2, '0'));
                    }
                    console.log("     Encrypted:  " + encNonce.join(' '));
                }
                console.log("   📤 SENDING TO RING for verification");
                console.log("═══════════════════════════════════════════════════\n");
            }

            return request;
        };

        // Hook parseResponse (ring's verification result)
        Authenticate.parseResponse.implementation = function(response) {
            console.log("\n╔═══════════════════════════════════════════════════╗");
            console.log("║  STEP 3b: Authenticate.parseResponse()            ║");
            console.log("╚═══════════════════════════════════════════════════╝");
            console.log("   📥 RECEIVED FROM RING");
            console.log("   Response: " + hexDump(response));
            console.log("   Length: " + response.length + " bytes");

            if (response && response.length >= 4) {
                console.log("   Breakdown:");
                console.log("     Byte 0 (Tag):     0x" + (response[0] & 0xFF).toString(16).padStart(2, '0') + " (expected 0x2f)");
                console.log("     Byte 1 (Subcmd):  0x" + (response[1] & 0xFF).toString(16).padStart(2, '0'));
                console.log("     Byte 2 (ExtTag):  0x" + (response[2] & 0xFF).toString(16).padStart(2, '0') + " (expected 0x2e)");
                console.log("     Byte 3 (Status):  0x" + (response[3] & 0xFF).toString(16).padStart(2, '0'));

                var status = response[3] & 0xFF;
                if (status === 0) {
                    console.log("   ✅ AUTHENTICATION SUCCESS!");
                } else {
                    console.log("   ❌ AUTHENTICATION FAILED - Status: " + status);
                }
            }
            console.log("═══════════════════════════════════════════════════\n");

            return this.parseResponse(response);
        };

        console.log('[+] Authenticate hooks installed');
        hookCount += 3;
    } catch(e) {
        console.log('[-] Authenticate hook failed: ' + e);
    }

    // ==================================================
    // Database Auth Key Access
    // ==================================================
    try {
        var DbRingConfiguration = Java.use('com.ouraring.core.realm.model.dist.android.DbRingConfiguration');

        DbRingConfiguration.getAuthKey.implementation = function() {
            var authKey = this.getAuthKey();
            console.log("\n[DB] Reading auth key from database: " + hexDump(authKey));
            return authKey;
        };

        console.log('[+] Database auth key hook installed');
        hookCount++;
    } catch(e) {
        console.log('[-] Database hook failed: ' + e);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ " + hookCount + " hooks installed!");
    console.log("🔐 Ready to trace complete authentication flow");
    console.log("════════════════════════════════════════════════════════\n");
});
