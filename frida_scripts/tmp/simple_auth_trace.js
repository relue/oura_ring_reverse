/**
 * Simple Authentication Trace
 * Only hooks classes we know exist for sure
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  🔐 SIMPLE AUTHENTICATION TRACE                      ║");
    console.log("╚════════════════════════════════════════════════════════╝\n");

    function hexDump(byteArray) {
        if (!byteArray) return "<null>";
        var hex = "";
        for (var i = 0; i < byteArray.length; i++) {
            hex += (byteArray[i] & 0xFF).toString(16).padStart(2, '0') + " ";
        }
        return hex.trim();
    }

    var hookCount = 0;

    // Hook 1: SetAuthKey constructor
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.$init.overload('[B').implementation = function(authKey) {
            console.log("\n[SETAUTH] ╔═══════════════════════════════════════════════════════╗");
            console.log("[SETAUTH] ║  📤 SetAuthKey Constructor Called                     ║");
            console.log("[SETAUTH] ╚═══════════════════════════════════════════════════════╝");
            console.log("[SETAUTH]   Auth Key: " + hexDump(authKey));
            console.log("[SETAUTH]   Length: " + authKey.length + " bytes");
            console.log("[SETAUTH]   ⚠️  THIS IS THE KEY BEING SET ON RING");

            return this.$init(authKey);
        };
        console.log('[+] SetAuthKey.$init() hooked');
        hookCount++;

        // Hook getRequest to see command sent
        SetAuthKey.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[SETAUTH] ╔═══════════════════════════════════════════════════════╗");
            console.log("[SETAUTH] ║  📤 SetAuthKey.getRequest() - Sending to Ring         ║");
            console.log("[SETAUTH] ╚═══════════════════════════════════════════════════════╝");
            console.log("[SETAUTH]   Command: " + hexDump(request));
            console.log("[SETAUTH]   Expected: [0x24, 0x10, <16 bytes of key>]");

            return request;
        };
        console.log('[+] SetAuthKey.getRequest() hooked');
        hookCount++;

        // Hook parseResponse
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
        hookCount++;

    } catch(e) {
        console.log('[-] SetAuthKey hook failed: ' + e);
    }

    // Hook 2: GetAuthNonce
    try {
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
        hookCount++;

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
        hookCount++;

    } catch(e) {
        console.log('[-] GetAuthNonce hook failed: ' + e);
    }

    // Hook 3: Authenticate
    try {
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
        hookCount++;

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
        hookCount++;

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
        hookCount++;

    } catch(e) {
        console.log('[-] Authenticate hook failed: ' + e);
    }

    // Hook 4: hasPairedRing decision
    try {
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
        hookCount++;

    } catch(e) {
        console.log('[-] hasPairedRing hook failed: ' + e);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ " + hookCount + " hooks installed successfully!");
    console.log("📱 Now perform ring setup in the Oura app");
    console.log("════════════════════════════════════════════════════════\n");
});
