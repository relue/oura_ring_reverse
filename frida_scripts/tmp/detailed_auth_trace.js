/**
 * Detailed Authentication Trace
 * Shows all auth keys, nonces, and encrypted communications
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  🔐 DETAILED AUTHENTICATION TRACE                    ║");
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
        // Hook 1: Auth key generation
        var v0 = Java.use('com.ouraring.ourakit.operations.v0');

        v0.k.implementation = function() {
            var authKey = this.k();

            console.log("\n[KEY-GEN] ╔═══════════════════════════════════════════════════════╗");
            console.log("[KEY-GEN] ║  🔑 Auth Key Generation                               ║");
            console.log("[KEY-GEN] ╚═══════════════════════════════════════════════════════╝");

            if (authKey && authKey.length === 16) {
                console.log("[KEY-GEN]   ✅ Generated 16-byte auth key:");
                console.log("[KEY-GEN]   Hex: " + hexDump(authKey));
                console.log("[KEY-GEN]   ➡️  This should be sent to ring via SetAuthKey");
            } else {
                console.log("[KEY-GEN]   ❌ Invalid auth key: " + authKey);
            }

            return authKey;
        };
        console.log('[+] v0.k() (key generation) hooked');

        // Hook 2: SetAuthKey constructor
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.$init.overload('[B').implementation = function(authKey) {
            console.log("\n[SETAUTH] ╔═══════════════════════════════════════════════════════╗");
            console.log("[SETAUTH] ║  📤 SetAuthKey Constructor Called                     ║");
            console.log("[SETAUTH] ╚═══════════════════════════════════════════════════════╝");
            console.log("[SETAUTH]   Auth Key: " + hexDump(authKey));
            console.log("[SETAUTH]   ⚠️  THIS IS THE KEY BEING SET ON RING");

            return this.$init(authKey);
        };
        console.log('[+] SetAuthKey.$init() hooked');

        // Hook 3: SetAuthKey.getRequest (command sent to ring)
        SetAuthKey.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[SETAUTH] ╔═══════════════════════════════════════════════════════╗");
            console.log("[SETAUTH] ║  📤 SetAuthKey Request - Sending to Ring              ║");
            console.log("[SETAUTH] ╚═══════════════════════════════════════════════════════╝");
            console.log("[SETAUTH]   Command: " + hexDump(request));
            console.log("[SETAUTH]   Expected format: [0x24, 0x10, <16 bytes of key>]");

            return request;
        };
        console.log('[+] SetAuthKey.getRequest() hooked');

        // Hook 4: SetAuthKey.parseResponse
        SetAuthKey.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 3) {
                var status = response[2] & 0xFF;
                console.log("\n[SETAUTH] ╔═══════════════════════════════════════════════════════╗");
                console.log("[SETAUTH] ║  📥 SetAuthKey Response from Ring                     ║");
                console.log("[SETAUTH] ╚═══════════════════════════════════════════════════════╝");
                console.log("[SETAUTH]   Response: " + hexDump(response));
                console.log("[SETAUTH]   Status: 0x" + status.toString(16).padStart(2, '0'));

                if (status === 0) {
                    console.log("[SETAUTH]   ✅ SUCCESS - Key stored in ring!");
                } else {
                    console.log("[SETAUTH]   ❌ FAILED - Status: " + status);
                }
            }

            return result;
        };
        console.log('[+] SetAuthKey.parseResponse() hooked');

        // Hook 5: GetAuthNonce (request nonce)
        var GetAuthNonce = Java.use('com.ouraring.ourakit.operations.GetAuthNonce');

        GetAuthNonce.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[NONCE] ╔═══════════════════════════════════════════════════════╗");
            console.log("[NONCE] ║  📤 GetAuthNonce - Request                            ║");
            console.log("[NONCE] ╚═══════════════════════════════════════════════════════╝");
            console.log("[NONCE]   Command: " + hexDump(request));
            console.log("[NONCE]   ➡️  Asking ring for random nonce");

            return request;
        };
        console.log('[+] GetAuthNonce.getRequest() hooked');

        // Hook 6: GetAuthNonce response (nonce received)
        GetAuthNonce.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 19) {
                var status = response[2] & 0xFF;
                var nonce = Java.array('byte', 16);
                for (var i = 0; i < 16; i++) {
                    nonce[i] = response[3 + i];
                }

                console.log("\n[NONCE] ╔═══════════════════════════════════════════════════════╗");
                console.log("[NONCE] ║  📥 GetAuthNonce - Response from Ring                 ║");
                console.log("[NONCE] ╚═══════════════════════════════════════════════════════╝");
                console.log("[NONCE]   Status: 0x" + status.toString(16).padStart(2, '0'));
                console.log("[NONCE]   Nonce (16 bytes): " + hexDump(nonce));
                console.log("[NONCE]   ➡️  App will encrypt this nonce with stored auth key");
            }

            return result;
        };
        console.log('[+] GetAuthNonce.parseResponse() hooked');

        // Hook 7: Authenticate (send encrypted nonce)
        var Authenticate = Java.use('com.ouraring.ourakit.operations.Authenticate');

        Authenticate.$init.overload('[B', '[B').implementation = function(authKey, nonce) {
            console.log("\n[AUTH] ╔═══════════════════════════════════════════════════════╗");
            console.log("[AUTH] ║  🔐 Authenticate Constructor                          ║");
            console.log("[AUTH] ╚═══════════════════════════════════════════════════════╝");
            console.log("[AUTH]   Auth Key Used: " + hexDump(authKey));
            console.log("[AUTH]   Nonce to Encrypt: " + hexDump(nonce));
            console.log("[AUTH]   ⚠️  THIS IS THE KEY APP THINKS IT SHOULD USE");

            return this.$init(authKey, nonce);
        };
        console.log('[+] Authenticate.$init() hooked');

        // Hook 8: Authenticate request (encrypted response sent)
        Authenticate.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[AUTH] ╔═══════════════════════════════════════════════════════╗");
            console.log("[AUTH] ║  📤 Authenticate - Sending Encrypted Response         ║");
            console.log("[AUTH] ╚═══════════════════════════════════════════════════════╝");
            console.log("[AUTH]   Command: " + hexDump(request));
            console.log("[AUTH]   Format: [0x2f, 0x11, <16 bytes encrypted nonce>]");
            console.log("[AUTH]   ➡️  Ring will decrypt and verify");

            return request;
        };
        console.log('[+] Authenticate.getRequest() hooked');

        // Hook 9: Authenticate response
        Authenticate.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 3) {
                var status = response[2] & 0xFF;
                console.log("\n[AUTH] ╔═══════════════════════════════════════════════════════╗");
                console.log("[AUTH] ║  📥 Authenticate - Response from Ring                 ║");
                console.log("[AUTH] ╚═══════════════════════════════════════════════════════╝");
                console.log("[AUTH]   Response: " + hexDump(response));
                console.log("[AUTH]   Status: 0x" + status.toString(16).padStart(2, '0'));

                if (status === 0) {
                    console.log("[AUTH]   ✅ SUCCESS - Auth keys match!");
                    console.log("[AUTH]   ✅ Ring and app have same auth key");
                } else {
                    console.log("[AUTH]   ❌ FAILED - Keys don't match! Status: " + status);
                }
            }

            return result;
        };
        console.log('[+] Authenticate.parseResponse() hooked');

        // Hook 10: hasPairedRing to see when it decides to skip SetAuthKey
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.hasPairedRing.implementation = function(bypassBondCheck) {
            var result = this.hasPairedRing(bypassBondCheck);

            console.log("\n[DECISION] ═══════════════════════════════════════════════════");
            console.log("[DECISION]   hasPairedRing(bypassBondCheck=" + bypassBondCheck + ") = " + result);

            if (result) {
                console.log("[DECISION]   ❌ WILL SKIP SetAuthKey - going to CONNECTING state");
                console.log("[DECISION]   ❌ No new key will be generated or sent!");
            } else {
                console.log("[DECISION]   ✅ WILL SEND SetAuthKey - going to STARTING state");
                console.log("[DECISION]   ✅ New key will be generated and sent to ring");
            }
            console.log("[DECISION] ═══════════════════════════════════════════════════");

            return result;
        };
        console.log('[+] hasPairedRing() hooked');

    } catch(e) {
        console.log('[-] Hook failed: ' + e);
        console.log('    Stack: ' + e.stack);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ All authentication hooks ready!");
    console.log("📱 Now perform ring setup in the Oura app");
    console.log("════════════════════════════════════════════════════════\n");
});
