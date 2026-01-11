/**
 * DETAILED AUTHENTICATION PROTOCOL TRACE
 * Decodes every message between phone and ring during authentication
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  🔐 DETAILED AUTHENTICATION PROTOCOL TRACE           ║");
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

    function decodeCommand(bytes) {
        if (!bytes || bytes.length < 2) return "UNKNOWN";

        var cmd = bytes[0] & 0xFF;
        var subcmd = bytes.length > 1 ? (bytes[1] & 0xFF) : 0;

        // Command mapping
        if (cmd === 0x2f) {
            if (subcmd === 0x01) return "GetAuthNonce (Request nonce from ring)";
            if (subcmd === 0x02) return "GetAuthNonce Response (Ring sends nonce)";
            if (subcmd === 0x11) return "Authenticate (Send encrypted nonce to ring)";
        }
        if (cmd === 0x24) return "SetAuthKey (Store new auth key in ring)";
        if (cmd === 0x25) return "SetAuthKey Response";

        return "UNKNOWN (0x" + cmd.toString(16).padStart(2, '0') + ")";
    }

    var hookCount = 0;
    var messageCounter = 0;

    // ==================================================
    // RAW BLE CHARACTERISTIC WRITES (Phone → Ring)
    // ==================================================
    try {
        var BluetoothGattCharacteristic = Java.use('android.bluetooth.BluetoothGattCharacteristic');

        // Hook setValue to see raw bytes being prepared
        BluetoothGattCharacteristic.setValue.overload('[B').implementation = function(value) {
            var uuid = this.getUuid().toString();

            // Only log Oura ring characteristic (98ed0002)
            if (uuid.indexOf("98ed0002") >= 0) {
                messageCounter++;
                console.log("\n[MSG #" + messageCounter + "] ═══════════════════════════════════════════════");
                console.log("[BLE-TX] 📤 PHONE → RING");
                console.log("[BLE-TX]   Characteristic: " + uuid);
                console.log("[BLE-TX]   Raw Bytes: " + hexDump(value));
                console.log("[BLE-TX]   Length: " + value.length + " bytes");
                console.log("[BLE-TX]   Command: " + decodeCommand(value));

                // Detailed breakdown
                if (value.length >= 1) {
                    console.log("[BLE-TX]   Breakdown:");
                    console.log("[BLE-TX]     Byte 0 (Command):    0x" + (value[0] & 0xFF).toString(16).padStart(2, '0'));
                    if (value.length >= 2) {
                        console.log("[BLE-TX]     Byte 1 (Subcommand): 0x" + (value[1] & 0xFF).toString(16).padStart(2, '0'));
                    }
                    if (value.length >= 3) {
                        console.log("[BLE-TX]     Byte 2 (OpCode):     0x" + (value[2] & 0xFF).toString(16).padStart(2, '0'));
                    }
                    if (value.length > 3) {
                        var payloadBytes = [];
                        for (var i = 3; i < value.length; i++) {
                            payloadBytes.push((value[i] & 0xFF).toString(16).padStart(2, '0'));
                        }
                        console.log("[BLE-TX]     Payload (" + (value.length - 3) + " bytes): " + payloadBytes.join(' '));
                    }
                }
                console.log("[BLE-TX] ═══════════════════════════════════════════════\n");
            }

            return this.setValue(value);
        };
        console.log('[+] BLE characteristic writes hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] BLE write hook failed: ' + e);
    }

    // ==================================================
    // SWEETBLUE LOW-LEVEL NOTIFICATIONS (Ring → Phone)
    // ==================================================
    try {
        var DeviceListenerImpl = Java.use('com.idevicesinc.sweetblue.internal.android.DeviceListenerImpl');

        DeviceListenerImpl.onCharacteristicChanged.implementation = function(gatt, characteristic) {
            var uuid = characteristic.getUuid().toString();
            var value = characteristic.getValue();

            // Only log Oura ring characteristic (98ed0003)
            if (uuid.indexOf("98ed0003") >= 0 && value) {
                messageCounter++;
                console.log("\n[MSG #" + messageCounter + "] ═══════════════════════════════════════════════");
                console.log("[BLE-RX] 📥 RING → PHONE (SweetBlue)");
                console.log("[BLE-RX]   Characteristic: " + uuid);
                console.log("[BLE-RX]   Raw Bytes: " + hexDump(value));
                console.log("[BLE-RX]   Length: " + value.length + " bytes");
                console.log("[BLE-RX]   Command: " + decodeCommand(value));

                // Detailed breakdown
                if (value.length >= 1) {
                    console.log("[BLE-RX]   Breakdown:");
                    console.log("[BLE-RX]     Byte 0 (Command):    0x" + (value[0] & 0xFF).toString(16).padStart(2, '0'));
                    if (value.length >= 2) {
                        console.log("[BLE-RX]     Byte 1 (Subcommand): 0x" + (value[1] & 0xFF).toString(16).padStart(2, '0'));
                    }
                    if (value.length >= 3) {
                        console.log("[BLE-RX]     Byte 2 (OpCode):     0x" + (value[2] & 0xFF).toString(16).padStart(2, '0'));
                    }

                    if (value.length >= 2 && value[0] === 0x2f && value[1] === 0x02) {
                        // GetAuthNonce response - extract nonce
                        if (value.length >= 19) {
                            var nonceBytes = [];
                            for (var i = 0; i < 16; i++) {
                                nonceBytes.push((value[3 + i] & 0xFF).toString(16).padStart(2, '0'));
                            }
                            console.log("[BLE-RX]     Status:              0x" + (value[2] & 0xFF).toString(16).padStart(2, '0'));
                            console.log("[BLE-RX]     Nonce (16 bytes):    " + nonceBytes.join(' '));
                            console.log("[BLE-RX]     🔑 Ring generated random nonce");
                        }
                    } else if (value.length > 3) {
                        var payloadBytes = [];
                        for (var i = 3; i < value.length; i++) {
                            payloadBytes.push((value[i] & 0xFF).toString(16).padStart(2, '0'));
                        }
                        console.log("[BLE-RX]     Payload (" + (value.length - 3) + " bytes): " + payloadBytes.join(' '));
                    }
                }
                console.log("[BLE-RX] ═══════════════════════════════════════════════\n");
            }

            return this.onCharacteristicChanged(gatt, characteristic);
        };
        console.log('[+] SweetBlue notifications hooked (LOW LEVEL)');
        hookCount++;
    } catch(e) {
        console.log('[-] SweetBlue notification hook failed: ' + e);
    }

    // ==================================================
    // GetAuthNonce - Request nonce from ring
    // ==================================================
    try {
        var GetAuthNonce = Java.use('com.ouraring.ourakit.operations.GetAuthNonce');

        GetAuthNonce.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[APP-LAYER] ╔═══════════════════════════════════════════════════╗");
            console.log("[APP-LAYER] ║  GetAuthNonce - Preparing Request                ║");
            console.log("[APP-LAYER] ╚═══════════════════════════════════════════════════╝");
            console.log("[APP-LAYER]   Request bytes: " + hexDump(request));
            console.log("[APP-LAYER]   → Phone asks ring for random nonce");
            console.log("[APP-LAYER] ═══════════════════════════════════════════════════\n");

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

                console.log("\n[APP-LAYER] ╔═══════════════════════════════════════════════════╗");
                console.log("[APP-LAYER] ║  GetAuthNonce - Processing Response               ║");
                console.log("[APP-LAYER] ╚═══════════════════════════════════════════════════╝");
                console.log("[APP-LAYER]   Response bytes: " + hexDump(response));
                console.log("[APP-LAYER]   Status: 0x" + status.toString(16).padStart(2, '0') + (status === 0 ? " (SUCCESS)" : " (FAILED)"));
                console.log("[APP-LAYER]   Nonce received: " + hexDump(nonce));
                console.log("[APP-LAYER]   Nonce (hex string): " + hexDumpCompact(nonce));
                console.log("[APP-LAYER]   ← Ring sent random nonce");
                console.log("[APP-LAYER]   ➡️  Phone will now encrypt this nonce with auth key");
                console.log("[APP-LAYER] ═══════════════════════════════════════════════════\n");
            }

            return result;
        };

        console.log('[+] GetAuthNonce hooked');
        hookCount += 2;
    } catch(e) {
        console.log('[-] GetAuthNonce hook failed: ' + e);
    }

    // ==================================================
    // AES ENCRYPTION - Nonce encryption with auth key
    // ==================================================
    try {
        var Cipher = Java.use('javax.crypto.Cipher');

        Cipher.doFinal.overload('[B').implementation = function(input) {
            var output = this.doFinal(input);

            // Only log if it's AES and input is 16 bytes (likely the nonce)
            var algorithm = this.getAlgorithm();
            if (algorithm.indexOf("AES") >= 0 && input && input.length === 16) {
                console.log("\n[CRYPTO] ╔═══════════════════════════════════════════════════╗");
                console.log("[CRYPTO] ║  AES Encryption                                   ║");
                console.log("[CRYPTO] ╚═══════════════════════════════════════════════════╝");
                console.log("[CRYPTO]   Algorithm: " + algorithm);
                console.log("[CRYPTO]   Input (Nonce): " + hexDump(input));
                console.log("[CRYPTO]   Input (hex):   " + hexDumpCompact(input));
                console.log("[CRYPTO]   Output (Encrypted): " + hexDump(output));
                console.log("[CRYPTO]   Output (hex):      " + hexDumpCompact(output));
                console.log("[CRYPTO]   🔐 Phone encrypted nonce with auth key");
                console.log("[CRYPTO] ═══════════════════════════════════════════════════\n");
            }

            return output;
        };

        console.log('[+] AES encryption hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] AES encryption hook failed: ' + e);
    }

    // ==================================================
    // Authenticate - Send encrypted nonce to ring
    // ==================================================
    try {
        var Authenticate = Java.use('com.ouraring.ourakit.operations.Authenticate');

        Authenticate.$init.overload('[B').implementation = function(encryptedNonce) {
            console.log("\n[APP-LAYER] ╔═══════════════════════════════════════════════════╗");
            console.log("[APP-LAYER] ║  Authenticate - Preparing                         ║");
            console.log("[APP-LAYER] ╚═══════════════════════════════════════════════════╝");
            console.log("[APP-LAYER]   Encrypted Nonce: " + hexDump(encryptedNonce));
            console.log("[APP-LAYER]   Encrypted (hex):  " + hexDumpCompact(encryptedNonce));
            console.log("[APP-LAYER]   → Phone sending encrypted nonce to ring");
            console.log("[APP-LAYER] ═══════════════════════════════════════════════════\n");

            return this.$init(encryptedNonce);
        };

        Authenticate.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[APP-LAYER] ╔═══════════════════════════════════════════════════╗");
            console.log("[APP-LAYER] ║  Authenticate - Sending Request                   ║");
            console.log("[APP-LAYER] ╚═══════════════════════════════════════════════════╝");
            console.log("[APP-LAYER]   Request bytes: " + hexDump(request));
            console.log("[APP-LAYER]   Format: [0x2f] [0x11] [0x2d] [16-byte encrypted nonce]");
            console.log("[APP-LAYER] ═══════════════════════════════════════════════════\n");

            return request;
        };

        Authenticate.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);

            if (response && response.length >= 3) {
                var status = response[3] & 0xFF;

                console.log("\n[APP-LAYER] ╔═══════════════════════════════════════════════════╗");
                console.log("[APP-LAYER] ║  Authenticate - Processing Response               ║");
                console.log("[APP-LAYER] ╚═══════════════════════════════════════════════════╝");
                console.log("[APP-LAYER]   Response bytes: " + hexDump(response));
                console.log("[APP-LAYER]   Status: 0x" + status.toString(16).padStart(2, '0') + (status === 0 ? " (SUCCESS)" : " (FAILED)"));

                if (status === 0) {
                    console.log("[APP-LAYER]   ✅ AUTHENTICATION SUCCESS!");
                    console.log("[APP-LAYER]   Ring decrypted nonce and it matched");
                    console.log("[APP-LAYER]   Both ring and phone have the same auth key");
                } else {
                    console.log("[APP-LAYER]   ❌ AUTHENTICATION FAILED!");
                    console.log("[APP-LAYER]   Ring's auth key doesn't match phone's");
                }
                console.log("[APP-LAYER] ═══════════════════════════════════════════════════\n");
            }

            return result;
        };

        console.log('[+] Authenticate hooked');
        hookCount += 3;
    } catch(e) {
        console.log('[-] Authenticate hook failed: ' + e);
    }

    // ==================================================
    // SetAuthKey - Store auth key in ring
    // ==================================================
    try {
        var SetAuthKey = Java.use('com.ouraring.ourakit.operations.SetAuthKey');

        SetAuthKey.$init.overload('[B').implementation = function(authKey) {
            console.log("\n[APP-LAYER] ╔═══════════════════════════════════════════════════╗");
            console.log("[APP-LAYER] ║  SetAuthKey - Preparing                           ║");
            console.log("[APP-LAYER] ╚═══════════════════════════════════════════════════╝");
            console.log("[APP-LAYER]   Auth Key: " + hexDump(authKey));
            console.log("[APP-LAYER]   Auth Key (hex): " + hexDumpCompact(authKey));
            console.log("[APP-LAYER]   Length: " + authKey.length + " bytes");
            console.log("[APP-LAYER]   → Phone will store this key in ring's flash");
            console.log("[APP-LAYER] ═══════════════════════════════════════════════════\n");

            return this.$init(authKey);
        };

        SetAuthKey.getRequest.implementation = function() {
            var request = this.getRequest();

            console.log("\n[APP-LAYER] ╔═══════════════════════════════════════════════════╗");
            console.log("[APP-LAYER] ║  SetAuthKey - Sending Request                     ║");
            console.log("[APP-LAYER] ╚═══════════════════════════════════════════════════╝");
            console.log("[APP-LAYER]   Request bytes: " + hexDump(request));
            console.log("[APP-LAYER]   Format: [0x24] [16-byte auth key]");
            console.log("[APP-LAYER] ═══════════════════════════════════════════════════\n");

            return request;
        };

        SetAuthKey.parseResponse.implementation = function(response) {
            var result = this.parseResponse(response);
            var status = response && response.length >= 3 ? (response[2] & 0xFF) : -1;

            console.log("\n[APP-LAYER] ╔═══════════════════════════════════════════════════╗");
            console.log("[APP-LAYER] ║  SetAuthKey - Processing Response                 ║");
            console.log("[APP-LAYER] ╚═══════════════════════════════════════════════════╝");
            console.log("[APP-LAYER]   Response bytes: " + hexDump(response));
            console.log("[APP-LAYER]   Status: 0x" + status.toString(16).padStart(2, '0') + (status === 0 ? " (SUCCESS)" : " (FAILED)"));

            if (status === 0) {
                console.log("[APP-LAYER]   ✅ AUTH KEY STORED IN RING!");
                console.log("[APP-LAYER]   Ring saved key to flash memory");
            } else {
                console.log("[APP-LAYER]   ❌ FAILED TO STORE KEY");
            }
            console.log("[APP-LAYER] ═══════════════════════════════════════════════════\n");

            return result;
        };

        console.log('[+] SetAuthKey hooked');
        hookCount += 3;
    } catch(e) {
        console.log('[-] SetAuthKey hook failed: ' + e);
    }

    // ==================================================
    // Database auth key for comparison
    // ==================================================
    try {
        var DbRingConfiguration = Java.use('com.ouraring.core.realm.model.dist.android.DbRingConfiguration');

        DbRingConfiguration.getAuthKey.implementation = function() {
            var authKey = this.getAuthKey();

            if (authKey && authKey.length > 0) {
                console.log("\n[DATABASE] ═══════════════════════════════════════════════");
                console.log("[DATABASE]   Auth key read from database");
                console.log("[DATABASE]   Key: " + hexDump(authKey));
                console.log("[DATABASE]   Key (hex): " + hexDumpCompact(authKey));
                console.log("[DATABASE]   This is the key phone will use to encrypt nonce");
                console.log("[DATABASE] ═══════════════════════════════════════════════\n");
            }

            return authKey;
        };
        console.log('[+] Database auth key reads hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] Database hook failed: ' + e);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ " + hookCount + " hooks installed!");
    console.log("🔐 Authentication protocol will be fully decoded");
    console.log("📱 Now perform ring setup/connection");
    console.log("════════════════════════════════════════════════════════\n");
});
