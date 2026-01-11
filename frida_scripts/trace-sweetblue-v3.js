/**
 * Comprehensive SweetBlue Library Trace v3 for Oura Ring
 *
 * Fixed: Hooks internal SweetBlue classes instead of listener interfaces
 * Now captures BOTH writes AND responses/notifications
 */

Java.perform(function() {
    console.log("\n[*] Starting SweetBlue BLE trace v3 for Oura Ring...\n");

    // ========================================
    // 1. TRACE BleManager - Scan Operations
    // ========================================
    try {
        var BleManager = Java.use('com.idevicesinc.sweetblue.BleManager');

        BleManager.startScan.overload().implementation = function() {
            console.log('\n[SB] ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★');
            console.log('[SB] ★★★ SWEETBLUE SCAN STARTED ★★★');
            console.log('[SB] ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★\n');
            return this.startScan();
        };

        BleManager.startScan.overload('com.idevicesinc.sweetblue.ScanOptions').implementation = function(scanOptions) {
            console.log('\n[SB] ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★');
            console.log('[SB] ★★★ SWEETBLUE SCAN STARTED ★★★');
            if (scanOptions) {
                console.log('[SB] Scan options provided: ' + scanOptions.toString());
            }
            console.log('[SB] ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★\n');
            return this.startScan(scanOptions);
        };

        BleManager.stopScan.overload().implementation = function() {
            console.log('\n[SB] ▓▓▓ SWEETBLUE SCAN STOPPED ▓▓▓\n');
            return this.stopScan();
        };

        console.log('[+] BleManager tracing enabled');
    } catch(e) {
        console.log('[-] BleManager trace failed: ' + e);
    }

    // ========================================
    // 2. TRACE DiscoveryListener - Fixed with proper overload
    // ========================================
    try {
        var DiscoveryListener = Java.use('com.idevicesinc.sweetblue.DiscoveryListener');

        DiscoveryListener.onEvent.overload('com.idevicesinc.sweetblue.DiscoveryListener$DiscoveryEvent').implementation = function(discoveryEvent) {
            try {
                var device = discoveryEvent.device();
                var lifecycle = discoveryEvent.lifeCycle().toString();
                var macAddress = discoveryEvent.macAddress();
                var rssi = discoveryEvent.rssi();
                var deviceName = device.getName_override();

                console.log('\n[SB] ════════════════════════════════════');
                console.log('[SB] DEVICE ' + lifecycle);
                console.log('[SB]   Name: ' + (deviceName ? deviceName : 'Unknown'));
                console.log('[SB]   MAC: ' + macAddress);
                console.log('[SB]   RSSI: ' + rssi + ' dBm');
                console.log('[SB] ════════════════════════════════════\n');
            } catch(e) {
                console.log('[SB] Error parsing discovery event: ' + e);
            }
            return this.onEvent(discoveryEvent);
        };

        console.log('[+] DiscoveryListener tracing enabled');
    } catch(e) {
        console.log('[-] DiscoveryListener trace failed: ' + e);
    }

    // ========================================
    // 3. TRACE BleDevice - Connection & Operations
    // ========================================
    try {
        var BleDevice = Java.use('com.idevicesinc.sweetblue.BleDevice');

        // Connect
        BleDevice.connect.overload().implementation = function() {
            var macAddress = this.getMacAddress();
            var name = this.getName_override();
            console.log('\n[SB] ►►► CONNECTING to device ◄◄◄');
            console.log('[SB]   Name: ' + (name ? name : 'Unknown'));
            console.log('[SB]   MAC: ' + macAddress + '\n');
            return this.connect();
        };

        // Disconnect
        BleDevice.disconnect.overload().implementation = function() {
            var macAddress = this.getMacAddress();
            console.log('\n[SB] ▬▬▬ DISCONNECTING from: ' + macAddress + ' ▬▬▬\n');
            return this.disconnect();
        };

        // Read characteristic
        BleDevice.read.overload('com.idevicesinc.sweetblue.BleRead').implementation = function(bleRead) {
            try {
                var charUuid = bleRead.getCharacteristicUuid();
                var serviceUuid = bleRead.getServiceUuid();
                console.log('[SB] 📖 Reading characteristic:');
                console.log('[SB]    Service: ' + serviceUuid);
                console.log('[SB]    Char: ' + charUuid);
            } catch(e) {
                console.log('[SB] Read (parsing error): ' + e);
            }
            return this.read(bleRead);
        };

        // Write characteristic
        BleDevice.write.overload('com.idevicesinc.sweetblue.BleWrite').implementation = function(bleWrite) {
            try {
                var charUuid = bleWrite.getCharacteristicUuid();
                var serviceUuid = bleWrite.getServiceUuid();
                var data = bleWrite.getData();

                var hexValue = '';
                if (data && data.getData) {
                    var byteArray = data.getData();
                    if (byteArray) {
                        for (var i = 0; i < byteArray.length; i++) {
                            hexValue += ('0' + (byteArray[i] & 0xFF).toString(16)).slice(-2) + ' ';
                        }
                    }
                }

                console.log('[SB] ✍️  Writing characteristic:');
                console.log('[SB]    Service: ' + serviceUuid);
                console.log('[SB]    Char: ' + charUuid);
                console.log('[SB]    Data: ' + hexValue);
            } catch(e) {
                console.log('[SB] Write (parsing error): ' + e);
            }
            return this.write(bleWrite);
        };

        // Enable notify
        BleDevice.enableNotify.overload('com.idevicesinc.sweetblue.BleNotify').implementation = function(bleNotify) {
            try {
                var charUuid = bleNotify.getCharacteristicUuid();
                var serviceUuid = bleNotify.getServiceUuid();
                console.log('[SB] 🔔 Enabling notifications:');
                console.log('[SB]    Service: ' + serviceUuid);
                console.log('[SB]    Char: ' + charUuid);
            } catch(e) {
                console.log('[SB] Enable notify (parsing error): ' + e);
            }
            return this.enableNotify(bleNotify);
        };

        // Disable notify
        BleDevice.disableNotify.overload('com.idevicesinc.sweetblue.BleNotify').implementation = function(bleNotify) {
            try {
                var charUuid = bleNotify.getCharacteristicUuid();
                var serviceUuid = bleNotify.getServiceUuid();
                console.log('[SB] 🔕 Disabling notifications:');
                console.log('[SB]    Service: ' + serviceUuid);
                console.log('[SB]    Char: ' + charUuid);
            } catch(e) {
                console.log('[SB] Disable notify (parsing error): ' + e);
            }
            return this.disableNotify(bleNotify);
        };

        console.log('[+] BleDevice tracing enabled');
    } catch(e) {
        console.log('[-] BleDevice trace failed: ' + e);
    }

    // ========================================
    // 4. TRACE DeviceListenerImpl - LOW LEVEL notification capture
    // ========================================
    try {
        var DeviceListenerImpl = Java.use('com.idevicesinc.sweetblue.internal.android.DeviceListenerImpl');

        DeviceListenerImpl.onCharacteristicChanged.implementation = function(gatt, characteristic) {
            try {
                var serviceUuid = characteristic.getService().getUuid().toString();
                var charUuid = characteristic.getUuid().toString();
                var value = characteristic.getValue();

                var hexValue = '';
                if (value) {
                    for (var i = 0; i < value.length; i++) {
                        hexValue += ('0' + (value[i] & 0xFF).toString(16)).slice(-2) + ' ';
                    }
                }

                console.log('\n[SB] ═══════════════════════════════════════');
                console.log('[SB] 🔔 NOTIFICATION RECEIVED (LOW LEVEL):');
                console.log('[SB]   Service: ' + serviceUuid);
                console.log('[SB]   Char: ' + charUuid);
                console.log('[SB]   Data: ' + hexValue);
                console.log('[SB] ═══════════════════════════════════════\n');
            } catch(e) {
                console.log('[SB] onCharacteristicChanged (parsing error): ' + e);
            }
            return this.onCharacteristicChanged(gatt, characteristic);
        };

        console.log('[+] DeviceListenerImpl (LOW LEVEL) tracing enabled');
    } catch(e) {
        console.log('[-] DeviceListenerImpl trace failed: ' + e);
    }

    // ========================================
    // 5. TRACE P_BleDeviceImpl.invokeReadWriteCallback - HIGH LEVEL event capture
    // ========================================
    try {
        var P_BleDeviceImpl = Java.use('com.idevicesinc.sweetblue.internal.P_BleDeviceImpl');

        P_BleDeviceImpl.invokeReadWriteCallback.implementation = function(readWriteListener, readWriteEvent) {
            try {
                var type = readWriteEvent.type().toString();
                var target = readWriteEvent.target().toString();
                var status = readWriteEvent.status().toString();
                var serviceUuid = readWriteEvent.serviceUuid();
                var charUuid = readWriteEvent.charUuid();
                var data = readWriteEvent.data();

                var hexValue = '';
                if (data) {
                    for (var i = 0; i < data.length; i++) {
                        hexValue += ('0' + (data[i] & 0xFF).toString(16)).slice(-2) + ' ';
                    }
                }

                console.log('\n[SB] ╔═══════════════════════════════════════╗');
                console.log('[SB] ║  ReadWriteEvent (HIGH LEVEL)         ║');
                console.log('[SB] ╚═══════════════════════════════════════╝');
                console.log('[SB]   Type: ' + type);
                console.log('[SB]   Target: ' + target);
                console.log('[SB]   Status: ' + status);
                console.log('[SB]   Service: ' + serviceUuid);
                console.log('[SB]   Char: ' + charUuid);
                if (hexValue) {
                    console.log('[SB]   Data: ' + hexValue);
                }
                console.log('[SB] ═══════════════════════════════════════\n');
            } catch(e) {
                console.log('[SB] invokeReadWriteCallback (parsing error): ' + e);
            }
            return this.invokeReadWriteCallback(readWriteListener, readWriteEvent);
        };

        console.log('[+] P_BleDeviceImpl.invokeReadWriteCallback (HIGH LEVEL) tracing enabled');
    } catch(e) {
        console.log('[-] P_BleDeviceImpl trace failed: ' + e);
    }

    // ========================================
    // 6. TRACE DeviceConnectListener - Fixed with proper overload
    // ========================================
    try {
        var DeviceConnectListener = Java.use('com.idevicesinc.sweetblue.DeviceConnectListener');

        DeviceConnectListener.onEvent.overload('com.idevicesinc.sweetblue.DeviceConnectListener$ConnectEvent').implementation = function(connectEvent) {
            try {
                var device = connectEvent.device();
                var macAddress = device.getMacAddress();
                var name = device.getName_override();
                var status = connectEvent.status().toString();

                console.log('\n[SB] ═══════════════════════════════════════');
                console.log('[SB] CONNECTION STATE CHANGE');
                console.log('[SB]   Device: ' + (name ? name : 'Unknown'));
                console.log('[SB]   MAC: ' + macAddress);
                console.log('[SB]   Status: ' + status);
                console.log('[SB] ═══════════════════════════════════════\n');
            } catch(e) {
                console.log('[SB] DeviceConnectListener (parsing error): ' + e);
            }
            return this.onEvent(connectEvent);
        };

        console.log('[+] DeviceConnectListener tracing enabled');
    } catch(e) {
        console.log('[-] DeviceConnectListener trace failed: ' + e);
    }

    // ========================================
    // 7. TRACE BondListener - Fixed with proper overload
    // ========================================
    try {
        var BondListener = Java.use('com.idevicesinc.sweetblue.BondListener');

        BondListener.onEvent.overload('com.idevicesinc.sweetblue.BondListener$BondEvent').implementation = function(bondEvent) {
            try {
                var device = bondEvent.device();
                var macAddress = device.getMacAddress();
                var name = device.getName_override();
                var state = bondEvent.state().toString();
                var status = bondEvent.status().toString();

                console.log('\n[SB] ═══════════════════════════════════════');
                console.log('[SB] BOND/PAIRING EVENT');
                console.log('[SB]   Device: ' + (name ? name : 'Unknown'));
                console.log('[SB]   MAC: ' + macAddress);
                console.log('[SB]   State: ' + state);
                console.log('[SB]   Status: ' + status);
                console.log('[SB] ═══════════════════════════════════════\n');
            } catch(e) {
                console.log('[SB] BondListener (parsing error): ' + e);
            }
            return this.onEvent(bondEvent);
        };

        console.log('[+] BondListener tracing enabled');
    } catch(e) {
        console.log('[-] BondListener trace failed: ' + e);
    }

    console.log('\n[*] SweetBlue BLE trace v3 ready! Start ring interaction in the app.\n');
    console.log('[*] This version hooks INTERNAL SweetBlue classes to capture notifications.\n');
});
