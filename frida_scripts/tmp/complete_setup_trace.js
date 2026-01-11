/**
 * Complete Ring Setup Trace
 * Shows all operations, Bluetooth states, auth flow, and state machine
 * NO backtraces for cleaner output
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  📡 COMPLETE RING SETUP TRACE                        ║");
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

    // ==================================================
    // AUTH KEY EXISTENCE CHECK (THE CRITICAL DECISION!)
    // ==================================================
    try {
        var h0 = Java.use('com.ouraring.core.features.ringconfiguration.h0');

        h0.apply.implementation = function(obj) {
            // Case 7 is the auth key existence check
            try {
                var caseNumber = -1;
                if (this.f19462a && this.f19462a.value !== undefined) {
                    caseNumber = this.f19462a.value;
                } else if (this.f19462a !== undefined) {
                    caseNumber = this.f19462a;
                }

                if (caseNumber === 7) {
                    var exists = obj;
                    console.log("\n[DB-CHECK] ╔═══════════════════════════════════════════════════╗");
                    console.log("[DB-CHECK] ║  💾 AUTH KEY EXISTENCE CHECK                     ║");
                    console.log("[DB-CHECK] ╚═══════════════════════════════════════════════════╝");
                    console.log("[DB-CHECK]   Auth key exists in DB: " + exists);

                    if (exists) {
                        console.log("[DB-CHECK]   ❌ DECISION: Skip SetAuthKey (key exists)");
                        console.log("[DB-CHECK]   ❌ Will return success without sending command");
                    } else {
                        console.log("[DB-CHECK]   ✅ DECISION: Will generate and send new SetAuthKey");
                    }
                }
            } catch(e) {
                // Silently ignore - case number check failed
            }

            var result = this.apply(obj);
            return result;
        };
        console.log('[+] Auth key existence check hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] h0 hook failed: ' + e);
    }

    // ==================================================
    // DATABASE AUTH KEY READS
    // ==================================================
    try {
        var DbRingConfiguration = Java.use('com.ouraring.core.realm.model.dist.android.DbRingConfiguration');

        DbRingConfiguration.getAuthKey.implementation = function() {
            var authKey = this.getAuthKey();

            console.log("\n[DB-READ] ═══════════════════════════════════════════════");
            console.log("[DB-READ]   DbRingConfiguration.getAuthKey()");
            if (authKey && authKey.length > 0) {
                console.log("[DB-READ]   Auth Key: " + hexDump(authKey));
                console.log("[DB-READ]   Length: " + authKey.length + " bytes");
                if (authKey.length > 1) {
                    console.log("[DB-READ]   ✅ Valid key (length > 1)");
                } else {
                    console.log("[DB-READ]   ⚠️  Invalid key (length <= 1)");
                }
            } else {
                console.log("[DB-READ]   Auth Key: NULL or EMPTY");
                console.log("[DB-READ]   ⚠️  No valid key in database");
            }
            console.log("[DB-READ] ═══════════════════════════════════════════════");

            return authKey;
        };
        console.log('[+] DbRingConfiguration.getAuthKey() hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] DbRingConfiguration hook failed: ' + e);
    }

    // ==================================================
    // DATABASE & DECISION LOGIC
    // ==================================================
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.hasPairedRing.implementation = function(bypassBondCheck) {
            console.log("\n[DECISION] ═══════════════════════════════════════════════");

            // Check database
            try {
                var configManager = this.getRingConfigurationManager();
                if (configManager.i()) {
                    var config = configManager.d();
                    var authKey = config.getAuthKey();
                    if (authKey && authKey.length > 0) {
                        console.log("[DECISION]   Database Auth Key: " + hexDump(authKey));
                        console.log("[DECISION]   Length: " + authKey.length + " bytes");
                    } else {
                        console.log("[DECISION]   Database Auth Key: EMPTY");
                    }
                }
            } catch(e) {}

            // Check bond state
            try {
                var bonded = this.isBonded();
                console.log("[DECISION]   isBonded(): " + bonded);
            } catch(e) {}

            var result = this.hasPairedRing(bypassBondCheck);
            console.log("[DECISION]   hasPairedRing(bypass=" + bypassBondCheck + ") = " + result);

            if (result) {
                console.log("[DECISION]   ❌ SKIP SetAuthKey → CONNECTING state");
            } else {
                console.log("[DECISION]   ✅ SEND SetAuthKey → STARTING state");
            }
            console.log("[DECISION] ═══════════════════════════════════════════════");

            return result;
        };
        console.log('[+] hasPairedRing() hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] hasPairedRing hook failed: ' + e);
    }

    // ==================================================
    // BLUETOOTH STATE
    // ==================================================
    try {
        var BluetoothDevice = Java.use('android.bluetooth.BluetoothDevice');

        BluetoothDevice.getBondState.implementation = function() {
            var state = this.getBondState();
            var stateStr = ["BOND_NONE", "BOND_BONDING", "BOND_BONDED"][state - 10] || "UNKNOWN";

            console.log("\n[BT-STATE] Device: " + this.getAddress() + " → " + stateStr + " (" + state + ")");

            return state;
        };
        console.log('[+] BluetoothDevice.getBondState() hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] BluetoothDevice hook failed: ' + e);
    }

    // ==================================================
    // STATE MACHINE
    // ==================================================
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.init.implementation = function(connectSource) {
            console.log("\n[STATE] ╔═══════════════════════════════════════════════════╗");
            console.log("[STATE] ║  🚀 RingModel.init()                             ║");
            console.log("[STATE] ╚═══════════════════════════════════════════════════╝");
            console.log("[STATE]   ConnectSource: " + connectSource);
            console.log("[STATE]   isInitialised: " + this.isRingStateMachineInitialised());

            return this.init(connectSource);
        };
        console.log('[+] RingModel.init() hooked');
        hookCount++;

        RingModel.safelyTriggerTransition.implementation = function(transition) {
            console.log("\n[STATE] ⚡ Transition: " + transition);
            var result = this.safelyTriggerTransition(transition);
            console.log("[STATE] → New State: " + result);
            return result;
        };
        console.log('[+] State transitions hooked');
        hookCount++;

    } catch(e) {
        console.log('[-] State machine hook failed: ' + e);
    }

    // ==================================================
    // SetAuthKey (0x24)
    // ==================================================
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.$init.overload('[B').implementation = function(authKey) {
            console.log("\n[SETAUTH] ╔═══════════════════════════════════════════════════╗");
            console.log("[SETAUTH] ║  📤 SetAuthKey Constructor                        ║");
            console.log("[SETAUTH] ╚═══════════════════════════════════════════════════╝");
            console.log("[SETAUTH]   Auth Key: " + hexDump(authKey));
            console.log("[SETAUTH]   ⚠️  NEW KEY BEING SET ON RING");

            return this.$init(authKey);
        };

        SetAuthKey.getRequest.implementation = function() {
            var request = this.getRequest();
            console.log("\n[SETAUTH] 📤 Request: " + hexDump(request));
            return request;
        };

        SetAuthKey.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);
            var status = response && response.length >= 3 ? (response[2] & 0xFF) : -1;

            console.log("\n[SETAUTH] 📥 Response: " + hexDump(response));
            console.log("[SETAUTH]   Status: 0x" + status.toString(16).padStart(2, '0'));

            if (status === 0) {
                console.log("[SETAUTH]   ✅ SUCCESS - Key stored in ring!");
            } else {
                console.log("[SETAUTH]   ❌ FAILED - Status: " + status);
            }

            return result;
        };

        console.log('[+] SetAuthKey hooked');
        hookCount += 3;
    } catch(e) {
        console.log('[-] SetAuthKey hook failed: ' + e);
    }

    // ==================================================
    // GetAuthNonce (0x2f 0x01 0x2b)
    // ==================================================
    try {
        var GetAuthNonce = Java.use('com.ouraring.ourakit.operations.GetAuthNonce');

        GetAuthNonce.getRequest.implementation = function() {
            var request = this.getRequest();
            console.log("\n[NONCE] ╔═══════════════════════════════════════════════════╗");
            console.log("[NONCE] ║  📤 GetAuthNonce - Request                        ║");
            console.log("[NONCE] ╚═══════════════════════════════════════════════════╝");
            console.log("[NONCE]   Command: " + hexDump(request));

            return request;
        };

        GetAuthNonce.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 19) {
                var status = response[2] & 0xFF;
                var nonce = Java.array('byte', 16);
                for (var i = 0; i < 16; i++) {
                    nonce[i] = response[3 + i];
                }

                console.log("\n[NONCE] ╔═══════════════════════════════════════════════════╗");
                console.log("[NONCE] ║  📥 GetAuthNonce - Response                       ║");
                console.log("[NONCE] ╚═══════════════════════════════════════════════════╝");
                console.log("[NONCE]   Status: 0x" + status.toString(16).padStart(2, '0'));
                console.log("[NONCE]   Nonce: " + hexDump(nonce));
                console.log("[NONCE]   ➡️  App will encrypt this with auth key");
            }

            return result;
        };

        console.log('[+] GetAuthNonce hooked');
        hookCount += 2;
    } catch(e) {
        console.log('[-] GetAuthNonce hook failed: ' + e);
    }

    // ==================================================
    // Authenticate (0x2f 0x11 0x2d)
    // ==================================================
    try {
        var Authenticate = Java.use('com.ouraring.ourakit.operations.Authenticate');

        Authenticate.$init.overload('[B').implementation = function(encryptedNonce) {
            console.log("\n[AUTH] ╔═══════════════════════════════════════════════════╗");
            console.log("[AUTH] ║  🔐 Authenticate Constructor                      ║");
            console.log("[AUTH] ╚═══════════════════════════════════════════════════╝");
            console.log("[AUTH]   Encrypted Nonce: " + hexDump(encryptedNonce));
            console.log("[AUTH]   ➡️  Sending to ring for verification");

            return this.$init(encryptedNonce);
        };

        Authenticate.getRequest.implementation = function() {
            var request = this.getRequest();
            console.log("\n[AUTH] 📤 Request: " + hexDump(request));
            return request;
        };

        Authenticate.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 3) {
                var status = response[3] & 0xFF;
                console.log("\n[AUTH] ╔═══════════════════════════════════════════════════╗");
                console.log("[AUTH] ║  📥 Authenticate - Response                       ║");
                console.log("[AUTH] ╚═══════════════════════════════════════════════════╝");
                console.log("[AUTH]   Response: " + hexDump(response));
                console.log("[AUTH]   Status: 0x" + status.toString(16).padStart(2, '0'));

                if (status === 0) {
                    console.log("[AUTH]   ✅ SUCCESS - Keys match!");
                } else {
                    console.log("[AUTH]   ❌ FAILED - Keys don't match! Status: " + status);
                }
            }

            return result;
        };

        console.log('[+] Authenticate hooked');
        hookCount += 3;
    } catch(e) {
        console.log('[-] Authenticate hook failed: ' + e);
    }

    // ==================================================
    // BLE Connect
    // ==================================================
    try {
        var v0 = Java.use('com.ouraring.ourakit.operations.v0');

        v0.a.implementation = function(shouldReconnect, useGattConnect) {
            console.log("\n[BLE] ╔═══════════════════════════════════════════════════╗");
            console.log("[BLE] ║  🔌 BLE Connect                                   ║");
            console.log("[BLE] ╚═══════════════════════════════════════════════════╝");
            console.log("[BLE]   shouldReconnect: " + shouldReconnect);
            console.log("[BLE]   useGattConnect: " + useGattConnect);

            return this.a(shouldReconnect, useGattConnect);
        };

        console.log('[+] BLE connect hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] BLE connect hook failed: ' + e);
    }

    // ==================================================
    // RingBondConnector
    // ==================================================
    try {
        var RingBondConnector = Java.use('com.ouraring.ourakit.operations.RingBondConnector');

        RingBondConnector.connect.implementation = function(macAddress, callback) {
            console.log("\n[BOND] ╔═══════════════════════════════════════════════════╗");
            console.log("[BOND] ║  🔗 Starting BLE Bonding                          ║");
            console.log("[BOND] ╚═══════════════════════════════════════════════════╝");
            console.log("[BOND]   MAC Address: " + macAddress);

            return this.connect(macAddress, callback);
        };

        console.log('[+] RingBondConnector hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] RingBondConnector hook failed: ' + e);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ " + hookCount + " hooks installed!");
    console.log("📱 Now perform ring setup in the Oura app");
    console.log("════════════════════════════════════════════════════════\n");
});
