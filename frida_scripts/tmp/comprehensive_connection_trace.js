/**
 * Comprehensive Connection Trace
 *
 * Traces all the key decision points that determine whether SetAuthKey is sent:
 * - hasPairedRing() checks
 * - isBonded() checks
 * - State machine transitions (STARTING vs CONNECTING)
 * - Auth key reads from database
 * - All authentication operations
 * - BLE connection operations
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  🔍 COMPREHENSIVE CONNECTION TRACE                    ║");
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

    // Helper to get stack trace
    function getStackTrace() {
        var stack = Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()
        );
        return stack;
    }

    // ========================================
    // HOOK 1: hasPairedRing() - THE KEY DECISION
    // ========================================
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.hasPairedRing.implementation = function(bypassBondCheck) {
            var result = this.hasPairedRing(bypassBondCheck);

            console.log("\n[1] ╔═══════════════════════════════════════════════════════╗");
            console.log("[1] ║  🎯 hasPairedRing() - THE KEY DECISION               ║");
            console.log("[1] ╚═══════════════════════════════════════════════════════╝");
            console.log("[1]   bypassBondCheck: " + bypassBondCheck);
            console.log("[1]   RESULT: " + result);

            try {
                console.log("[1]   MAC Address: " + this.macAddress.value);
            } catch(e) {
                console.log("[1]   MAC Address: <unavailable>");
            }

            try {
                console.log("[1]   Bond Address: " + this.bondAddress.value);
            } catch(e) {
                console.log("[1]   Bond Address: <unavailable>");
            }

            if (result) {
                console.log("[1]   ➡️  Will go to CONNECTING (skip SetAuthKey!)");
            } else {
                console.log("[1]   ➡️  Will go to STARTING (send SetAuthKey)");
            }

            return result;
        };

        console.log('[+] hasPairedRing() hooked');
    } catch(e) {
        console.log('[-] hasPairedRing() hook failed: ' + e);
    }

    // ========================================
    // HOOK 2: isBonded() - Android BLE Bond Check
    // ========================================
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.isBonded.implementation = function() {
            var result = this.isBonded();

            console.log("\n[2] ╔═══════════════════════════════════════════════════════╗");
            console.log("[2] ║  📱 isBonded() - Android BLE Bond State              ║");
            console.log("[2] ╚═══════════════════════════════════════════════════════╝");
            console.log("[2]   RESULT: " + result);

            try {
                console.log("[2]   MAC Address: " + this.macAddress.value);
            } catch(e) {
                console.log("[2]   MAC Address: <unavailable>");
            }

            if (result) {
                console.log("[2]   ⚠️  Ring is BONDED at Android OS level");
                console.log("[2]   This causes hasPairedRing() to return true");
            } else {
                console.log("[2]   ℹ️  Ring is NOT bonded at Android OS level");
            }

            return result;
        };

        console.log('[+] isBonded() hooked');
    } catch(e) {
        console.log('[-] isBonded() hook failed: ' + e);
    }

    // ========================================
    // HOOK 3: RingModel.init() - State Machine Initialization
    // ========================================
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');
        var ConnectSource = Java.use('com.ouraring.ourakit.ConnectSource');

        RingModel.init.implementation = function(connectSource) {
            console.log("\n[3] ╔═══════════════════════════════════════════════════════╗");
            console.log("[3] ║  🚀 RingModel.init() - Starting State Machine        ║");
            console.log("[3] ╚═══════════════════════════════════════════════════════╝");
            console.log("[3]   ConnectSource: " + connectSource);
            console.log("[3]   isRingStateMachineInitialised: " + this.isRingStateMachineInitialised());

            try {
                console.log("[3]   MAC Address: " + this.macAddress.value);
            } catch(e) {
                console.log("[3]   MAC Address: <unavailable>");
            }

            return this.init(connectSource);
        };

        console.log('[+] RingModel.init() hooked');
    } catch(e) {
        console.log('[-] RingModel.init() hook failed: ' + e);
    }

    // ========================================
    // HOOK 4: State Machine Transitions
    // ========================================
    try {
        var RingModel = Java.use('com.ouraring.oura.model.RingModel');

        RingModel.safelyTriggerTransition.implementation = function(transition) {
            console.log("\n[4] ╔═══════════════════════════════════════════════════════╗");
            console.log("[4] ║  ⚡ State Machine Transition                          ║");
            console.log("[4] ╚═══════════════════════════════════════════════════════╝");
            console.log("[4]   Transition: " + transition);

            try {
                var currentState = this.stateMachineRelay.f18677a.get();
                console.log("[4]   Current State: " + currentState);
            } catch(e) {
                console.log("[4]   Current State: <unavailable>");
            }

            var result = this.safelyTriggerTransition(transition);

            console.log("[4]   New State: " + result);

            return result;
        };

        console.log('[+] safelyTriggerTransition() hooked');
    } catch(e) {
        console.log('[-] safelyTriggerTransition() hook failed: ' + e);
    }

    // ========================================
    // HOOK 5: Read Existing Auth Key from Database
    // ========================================
    try {
        var RingConfigurationObserver = Java.use('com.ouraring.oura.model.db.ringconfiguration.RingConfigurationObserver');

        RingConfigurationObserver.getCachedValue.implementation = function() {
            var result = this.getCachedValue();

            if (result) {
                try {
                    var authKey = result.getAuthKey();
                    var macAddress = result.getMacAddress();
                    var authenticated = result.getAuthenticated();

                    console.log("\n[5] ╔═══════════════════════════════════════════════════════╗");
                    console.log("[5] ║  💾 Reading Auth Key from Database                   ║");
                    console.log("[5] ╚═══════════════════════════════════════════════════════╝");
                    console.log("[5]   MAC Address: " + macAddress);
                    console.log("[5]   Authenticated: " + authenticated);

                    if (authKey && authKey.length > 0) {
                        console.log("[5]   Auth Key (Hex): " + hexDump(authKey));
                        console.log("[5]   ⚠️  Existing key found! App will use this for auth");
                    } else {
                        console.log("[5]   Auth Key: <empty>");
                        console.log("[5]   ℹ️  No existing key - fresh setup expected");
                    }
                } catch(e) {
                    console.log("[5]   Error reading cached value: " + e);
                }
            }

            return result;
        };

        console.log('[+] RingConfigurationObserver.getCachedValue() hooked');
    } catch(e) {
        console.log('[-] RingConfigurationObserver hook failed: ' + e);
    }

    // ========================================
    // HOOK 6: v0.a() - BLE Connect Operation
    // ========================================
    try {
        var v0 = Java.use('com.ouraring.oura.ringtracker.v0');

        v0.a.overload('boolean', 'boolean').implementation = function(shouldReconnect, useGattConnect) {
            console.log("\n[6] ╔═══════════════════════════════════════════════════════╗");
            console.log("[6] ║  🔌 v0.a() - BLE Connect Operation                   ║");
            console.log("[6] ╚═══════════════════════════════════════════════════════╝");
            console.log("[6]   shouldReconnect: " + shouldReconnect);
            console.log("[6]   useGattConnect: " + useGattConnect);

            var result = this.a(shouldReconnect, useGattConnect);

            console.log("[6]   ➡️  Connect operation initiated");

            return result;
        };

        console.log('[+] v0.a() (connect) hooked');
    } catch(e) {
        console.log('[-] v0.a() hook failed: ' + e);
    }

    // ========================================
    // HOOK 7: Auth Key Generation (v0.k())
    // ========================================
    try {
        var v0 = Java.use('com.ouraring.oura.ringtracker.v0');

        v0.k.implementation = function() {
            var authKey = this.k();

            console.log("\n[7] ╔═══════════════════════════════════════════════════════╗");
            console.log("[7] ║  🎲 NEW AUTH KEY GENERATED                            ║");
            console.log("[7] ╚═══════════════════════════════════════════════════════╝");

            if (authKey && authKey.length === 16) {
                console.log("[7]   ✅ Generated 16-byte auth key:");
                console.log("[7]   Hex: " + hexDump(authKey));
                console.log("[7]   ➡️  This key will be sent to ring via SetAuthKey");

                // Java format
                var javaArray = "new byte[]{";
                for (var i = 0; i < authKey.length; i++) {
                    javaArray += "(byte)0x" + ("0" + (authKey[i] & 0xFF).toString(16)).slice(-2);
                    if (i < authKey.length - 1) javaArray += ", ";
                }
                javaArray += "}";
                console.log("[7]   Java: " + javaArray);
            } else {
                console.log("[7]   ⚠️  Invalid key length: " + (authKey ? authKey.length : "null"));
            }

            return authKey;
        };

        console.log('[+] v0.k() (key generation) hooked');
    } catch(e) {
        console.log('[-] v0.k() hook failed: ' + e);
    }

    // ========================================
    // HOOK 8: SetAuthKey Constructor
    // ========================================
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.$init.implementation = function(key) {
            console.log("\n[8] ╔═══════════════════════════════════════════════════════╗");
            console.log("[8] ║  📤 SetAuthKey CREATED - Will Send to Ring           ║");
            console.log("[8] ╚═══════════════════════════════════════════════════════╝");

            if (key && key.length === 16) {
                console.log("[8]   Auth Key (Hex): " + hexDump(key));
                console.log("[8]   ➡️  This proves we reached STARTING state!");
            } else {
                console.log("[8]   ⚠️  Invalid key length: " + (key ? key.length : "null"));
            }

            return this.$init(key);
        };

        console.log('[+] SetAuthKey.$init() hooked');
    } catch(e) {
        console.log('[-] SetAuthKey.$init() hook failed: ' + e);
    }

    // ========================================
    // HOOK 9: SetAuthKey.getRequest() - Command Sent
    // ========================================
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[9] ╔═══════════════════════════════════════════════════════╗");
            console.log("[9] ║  🚀 SetAuthKey SENDING TO RING                        ║");
            console.log("[9] ╚═══════════════════════════════════════════════════════╝");
            console.log("[9]   Command: 0x24 (SetAuthKey)");
            console.log("[9]   Full Packet: " + hexDump(request));

            if (request.length >= 17) {
                var keyBytes = [];
                for (var i = 1; i < 17; i++) {
                    keyBytes.push(request[i]);
                }
                console.log("[9]   Auth Key in Packet: " + hexDump(keyBytes));
            }

            return request;
        };

        console.log('[+] SetAuthKey.getRequest() hooked');
    } catch(e) {
        console.log('[-] SetAuthKey.getRequest() hook failed: ' + e);
    }

    // ========================================
    // HOOK 10: SetAuthKey.parseResponse()
    // ========================================
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 3) {
                var status = response[2] & 0xFF;
                console.log("\n[10] ╔══════════════════════════════════════════════════════╗");
                console.log("[10] ║  📥 SetAuthKey RESPONSE FROM RING                    ║");
                console.log("[10] ╚══════════════════════════════════════════════════════╝");
                console.log("[10]  Response: " + hexDump(response));
                console.log("[10]  Status: 0x" + status.toString(16));

                if (status === 0) {
                    console.log("[10]  ✅ SUCCESS - Auth key stored in ring!");
                } else if (status === 5) {
                    console.log("[10]  ⚠️  PRODUCTION_TEST_MODE (acceptable)");
                } else {
                    console.log("[10]  ❌ FAILED - Status: " + status);
                }
            }

            return result;
        };

        console.log('[+] SetAuthKey.parseResponse() hooked');
    } catch(e) {
        console.log('[-] SetAuthKey.parseResponse() hook failed: ' + e);
    }

    // ========================================
    // HOOK 11: GetAuthNonce - Authentication Start
    // ========================================
    try {
        var GetAuthNonce = Java.use('com.ouraring.ourakit.operations.GetAuthNonce');

        GetAuthNonce.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[11] ╔══════════════════════════════════════════════════════╗");
            console.log("[11] ║  🔐 GetAuthNonce - Starting Authentication           ║");
            console.log("[11] ╚══════════════════════════════════════════════════════╝");
            console.log("[11]  Command: " + hexDump(request));
            console.log("[11]  ➡️  Requesting nonce for challenge-response");

            return request;
        };

        GetAuthNonce.parseResponse.implementation = function(response) {
            if (response && response.length >= 19) {
                var nonce = [];
                for (var i = 3; i < 19; i++) {
                    nonce.push(response[i]);
                }
                console.log("[11]  📥 Nonce received: " + hexDump(nonce));
                console.log("[11]  ➡️  Will encrypt with auth key for Authenticate");
            }
            return this.parseResponse(response);
        };

        console.log('[+] GetAuthNonce hooked');
    } catch(e) {
        console.log('[-] GetAuthNonce hook failed: ' + e);
    }

    // ========================================
    // HOOK 12: Authenticate - Challenge Response
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
                console.log("\n[12] ╔══════════════════════════════════════════════════════╗");
                console.log("[12] ║  🔐 Authenticate - Sending Challenge Response        ║");
                console.log("[12] ╚══════════════════════════════════════════════════════╝");
                console.log("[12]  Encrypted nonce: " + hexDump(encrypted));
                console.log("[12]  ➡️  Ring will verify this was encrypted with correct key");
            }

            return request;
        };

        Authenticate.parseResponse.implementation = function(response) {
            if (response && response.length >= 4) {
                var status = response[3] & 0xFF;
                console.log("[12]  📥 Authenticate response: Status = 0x" + status.toString(16));

                if (status === 0) {
                    console.log("[12]  ✅ SUCCESS - Authentication passed!");
                    console.log("[12]  ➡️  App and ring have matching auth keys");
                } else {
                    console.log("[12]  ❌ FAILED - Authentication rejected!");
                    console.log("[12]  ⚠️  Auth keys don't match");
                }
            }

            return this.parseResponse(response);
        };

        console.log('[+] Authenticate hooked');
    } catch(e) {
        console.log('[-] Authenticate hook failed: ' + e);
    }

    // ========================================
    // HOOK 13: BLE Bond State Changes
    // ========================================
    try {
        var BluetoothDevice = Java.use('android.bluetooth.BluetoothDevice');

        BluetoothDevice.getBondState.implementation = function() {
            var state = this.getBondState();
            var stateStr = "";

            switch(state) {
                case 10: stateStr = "BOND_NONE"; break;
                case 11: stateStr = "BOND_BONDING"; break;
                case 12: stateStr = "BOND_BONDED"; break;
                default: stateStr = "UNKNOWN(" + state + ")";
            }

            console.log("\n[13] ╔══════════════════════════════════════════════════════╗");
            console.log("[13] ║  📱 BluetoothDevice.getBondState()                   ║");
            console.log("[13] ╚══════════════════════════════════════════════════════╝");
            console.log("[13]  Device: " + this.getAddress());
            console.log("[13]  Bond State: " + stateStr + " (" + state + ")");

            return state;
        };

        console.log('[+] BluetoothDevice.getBondState() hooked');
    } catch(e) {
        console.log('[-] BluetoothDevice.getBondState() hook failed: ' + e);
    }

    // ========================================
    // HOOK 14: RingBondConnector - BLE Bonding
    // ========================================
    try {
        var RingBondConnector = Java.use('com.ouraring.ourakit.RingBondConnector');

        RingBondConnector.connect.implementation = function(address, callback) {
            console.log("\n[14] ╔══════════════════════════════════════════════════════╗");
            console.log("[14] ║  🔗 RingBondConnector.connect()                      ║");
            console.log("[14] ╚══════════════════════════════════════════════════════╝");
            console.log("[14]  Address: " + address);
            console.log("[14]  ➡️  Starting BLE bonding process");

            return this.connect(address, callback);
        };

        console.log('[+] RingBondConnector.connect() hooked');
    } catch(e) {
        console.log('[-] RingBondConnector.connect() hook failed: ' + e);
    }

    // ========================================
    // HOOK 15: Database Storage (d1.I())
    // ========================================
    try {
        var d1 = Java.use('com.ouraring.core.realm.timeseries.d1');

        d1.I.implementation = function(dbRingConfiguration) {
            console.log("\n[15] ╔══════════════════════════════════════════════════════╗");
            console.log("[15] ║  💾 Storing Ring Configuration in Database           ║");
            console.log("[15] ╚══════════════════════════════════════════════════════╝");

            if (dbRingConfiguration) {
                try {
                    var authKey = dbRingConfiguration.getAuthKey();
                    var macAddress = dbRingConfiguration.getMacAddress();
                    var serialNumber = dbRingConfiguration.getSerialNumber();

                    console.log("[15]  MAC Address: " + macAddress);
                    console.log("[15]  Serial Number: " + serialNumber);

                    if (authKey && authKey.length > 0) {
                        console.log("[15]  Auth Key (Hex): " + hexDump(authKey));
                        console.log("[15]  ✅ Auth key will be stored in database");
                    } else {
                        console.log("[15]  ⚠️  Auth key is empty");
                    }
                } catch(e) {
                    console.log("[15]  Error reading config: " + e);
                }
            }

            return this.I(dbRingConfiguration);
        };

        console.log('[+] d1.I() (database storage) hooked');
    } catch(e) {
        console.log('[-] d1.I() hook failed: ' + e);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ All 15 hooks ready!");
    console.log("📱 Now perform ring setup in the Oura app");
    console.log("════════════════════════════════════════════════════════\n");
});
