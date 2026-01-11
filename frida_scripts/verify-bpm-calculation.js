/**
 * Verify BPM Calculation - Hook App's Actual Code
 * Shows exactly what the app does to calculate BPM
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════╗");
    console.log("║   BPM CALCULATION VERIFICATION SCRIPT     ║");
    console.log("╚════════════════════════════════════════════╝\n");

    // Helper: Convert byte array to hex string
    function toHexString(data) {
        var hex = '';
        for (var i = 0; i < data.length; i++) {
            hex += ('0' + (data[i] & 0xFF).toString(16)).slice(-2) + ' ';
        }
        return hex.trim();
    }

    // ========================================
    // 1. Hook IBI Constructor
    // ========================================
    try {
        var IBI = Java.use('com.ouraring.ourakit.domain.IBI');

        IBI.$init.implementation = function(data) {
            console.log('\n[IBI CONSTRUCTOR]');
            console.log('  Input bytes: ' + toHexString(data));
            console.log('  Length: ' + data.length);

            // Call original
            this.$init(data);

            // Show what was calculated
            var ibiValue = this.getIbi();
            console.log('  Calculated IBI: ' + ibiValue);
            console.log('  If valid, BPM = 60000 / ' + ibiValue + ' = ' + (ibiValue ? (60000 / ibiValue.intValue()).toFixed(1) : 'null'));

            return;
        };

        console.log('[✓] Hooked IBI constructor');
    } catch(e) {
        console.log('[-] Failed to hook IBI: ' + e);
    }

    // ========================================
    // 2. Hook LiveHeartRateMeasurer.getBpm
    // ========================================
    try {
        var LiveHeartRateMeasurer = Java.use('com.ouraring.oura.pillars.data.daytimehr.LiveHeartRateMeasurer');

        LiveHeartRateMeasurer.getBpm.implementation = function(payload) {
            var ibi = payload.getIbi();
            var ibiValue = ibi.getIbi();

            console.log('\n[GET BPM]');
            console.log('  IBI object data: ' + toHexString(ibi.getData()));
            console.log('  IBI value: ' + ibiValue);

            // Call original
            var bpm = this.getBpm(payload);

            console.log('  ► Calculated BPM: ' + bpm);
            console.log('  Formula: 60000 / ' + ibiValue + ' = ' + bpm);

            return bpm;
        };

        console.log('[✓] Hooked LiveHeartRateMeasurer.getBpm');
    } catch(e) {
        console.log('[-] Failed to hook getBpm: ' + e);
    }

    // ========================================
    // 3. Hook Raw Notification (for reference)
    // ========================================
    try {
        var DeviceListenerImpl = Java.use('com.idevicesinc.sweetblue.internal.android.DeviceListenerImpl');

        DeviceListenerImpl.onCharacteristicChanged.implementation = function(gatt, characteristic) {
            try {
                var charUuid = characteristic.getUuid().toString();

                if (charUuid === '98ed0003-a541-11e4-b6a0-0002a5d5c51b') {
                    var value = characteristic.getValue();
                    var hexDump = toHexString(value);

                    // Only show 2f 0f 28 packets
                    if (value.length >= 3 && value[0] === 0x2f && value[1] === 0x0f && value[2] === 0x28) {
                        console.log('\n[RAW NOTIFICATION]');
                        console.log('  Full packet: ' + hexDump);
                        console.log('  Length: ' + value.length);

                        // Show both byte positions
                        if (value.length >= 10) {
                            var bytes_8_9 = ((value[9] & 0x0F) << 8) | (value[8] & 0xFF);
                            console.log('  Bytes[8-9]: 0x' + ('0' + (value[8] & 0xFF).toString(16)).slice(-2) +
                                       ' 0x' + ('0' + (value[9] & 0xFF).toString(16)).slice(-2) +
                                       ' → ' + bytes_8_9 + ' → BPM=' + (60000/bytes_8_9).toFixed(1));
                        }

                        if (value.length >= 16) {
                            var bytes_14_15 = ((value[15] & 0xFF) << 8) | (value[14] & 0xFF);
                            console.log('  Bytes[14-15]: 0x' + ('0' + (value[14] & 0xFF).toString(16)).slice(-2) +
                                       ' 0x' + ('0' + (value[15] & 0xFF).toString(16)).slice(-2) +
                                       ' → ' + bytes_14_15);
                        }
                    }
                }
            } catch(e) {
                console.log('[ERROR] ' + e);
            }
            return this.onCharacteristicChanged(gatt, characteristic);
        };

        console.log('[✓] Hooked notification listener');
    } catch(e) {
        console.log('[-] Failed to hook notifications: ' + e);
    }

    console.log('\n[*] Verification script ready! Start heartbeat test in the app.\n');
});
