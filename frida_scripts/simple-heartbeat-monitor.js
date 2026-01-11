/**
 * Simple Heartbeat Monitor
 * Lightweight script - only hooks raw BLE notifications
 * Extracts and displays BPM from heartbeat packets
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════╗");
    console.log("║     OURA RING HEARTBEAT MONITOR          ║");
    console.log("╚════════════════════════════════════════════╝\n");

    // Helper: Convert byte array to hex string
    function toHex(data) {
        var hex = '';
        for (var i = 0; i < data.length; i++) {
            hex += ('0' + (data[i] & 0xFF).toString(16)).slice(-2) + ' ';
        }
        return hex.trim();
    }

    // Hook the low-level BLE notification handler
    try {
        var DeviceListenerImpl = Java.use('com.idevicesinc.sweetblue.internal.android.DeviceListenerImpl');

        DeviceListenerImpl.onCharacteristicChanged.implementation = function(gatt, characteristic) {
            try {
                var charUuid = characteristic.getUuid().toString();

                // Only process Oura's notify characteristic
                if (charUuid === '98ed0003-a541-11e4-b6a0-0002a5d5c51b') {
                    var value = characteristic.getValue();

                    // Only show heartbeat packets (2f 0f 28)
                    if (value.length >= 10 && value[0] === 0x2f && value[1] === 0x0f && value[2] === 0x28) {

                        // Extract IBI from bytes 8-9 (12-bit little-endian)
                        var ibi = ((value[9] & 0x0F) << 8) | (value[8] & 0xFF);

                        // Calculate BPM
                        var bpm = (60000 / ibi).toFixed(1);

                        // Extract byte [4] (flag/sequence)
                        var flag = ('0' + (value[4] & 0xFF).toString(16)).slice(-2);

                        // Build annotated packet display
                        var packet = '';
                        for (var i = 0; i < value.length; i++) {
                            var byte = ('0' + (value[i] & 0xFF).toString(16)).slice(-2);
                            if (i === 4) {
                                packet += '[' + byte + '] ';  // Flag byte
                            } else if (i === 8 || i === 9) {
                                packet += '[' + byte + '] ';  // IBI bytes
                            } else {
                                packet += byte + ' ';
                            }
                        }

                        // Display
                        console.log('\n┌──────────────────────────────────────────────────────────┐');
                        console.log('│  💓 HEARTBEAT                                            │');
                        console.log('├──────────────────────────────────────────────────────────┤');
                        console.log('│  BPM: ' + bpm + ' BPM                                      │'.substring(0, 59) + '│');
                        console.log('│  IBI: ' + ibi + ' ms                                       │'.substring(0, 59) + '│');
                        console.log('│  Flag: 0x' + flag + '                                          │'.substring(0, 59) + '│');
                        console.log('├──────────────────────────────────────────────────────────┤');
                        console.log('│  Packet: ' + packet.substring(0, 49) + '│');
                        if (packet.length > 49) {
                            console.log('│          ' + packet.substring(49, 98).padEnd(49) + '│');
                        }
                        console.log('│  Legend: [XX] = changing bytes                           │');
                        console.log('└──────────────────────────────────────────────────────────┘');
                    }
                }
            } catch(e) {
                console.log('[ERROR] ' + e);
            }

            // Call original
            return this.onCharacteristicChanged(gatt, characteristic);
        };

        console.log('[✓] Hooked BLE notification handler');
        console.log('[*] Waiting for heartbeat data...\n');

    } catch(e) {
        console.log('[-] Failed to hook: ' + e);
    }
});
