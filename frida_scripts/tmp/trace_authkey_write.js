/**
 * Trace WHERE the auth key gets WRITTEN to database
 * This will catch the "magic" appearance of the key
 */

Java.perform(function() {
    console.log("\n╔════════════════════════════════════════════════════════╗");
    console.log("║  🔍 AUTH KEY WRITE TRACE                             ║");
    console.log("╚════════════════════════════════════════════════════════╝\n");

    function hexDump(byteArray) {
        if (!byteArray) return "<null>";
        var hex = "";
        for (var i = 0; i < byteArray.length; i++) {
            hex += (byteArray[i] & 0xFF).toString(16).padStart(2, '0') + " ";
        }
        return hex.trim();
    }

    function getStackTrace() {
        var trace = Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()
        );
        return trace;
    }

    var hookCount = 0;

    // ==================================================
    // DATABASE WRITE OPERATIONS
    // ==================================================
    try {
        var DbRingConfiguration = Java.use('com.ouraring.core.realm.model.dist.android.DbRingConfiguration');

        // Hook setAuthKey (if it exists)
        try {
            DbRingConfiguration.setAuthKey.implementation = function(authKey) {
                console.log("\n[DB-WRITE] ╔═══════════════════════════════════════════════════╗");
                console.log("[DB-WRITE] ║  ✍️  DbRingConfiguration.setAuthKey()            ║");
                console.log("[DB-WRITE] ╚═══════════════════════════════════════════════════╝");
                console.log("[DB-WRITE]   Auth Key: " + hexDump(authKey));
                console.log("[DB-WRITE]   Length: " + (authKey ? authKey.length : 0) + " bytes");
                console.log("[DB-WRITE]   🔥 THIS IS WHERE THE KEY GETS WRITTEN!");
                console.log("[DB-WRITE]   Stack trace:");
                console.log(getStackTrace());
                console.log("[DB-WRITE] ══════════════════════════════════════════════════════\n");

                return this.setAuthKey(authKey);
            };
            console.log('[+] DbRingConfiguration.setAuthKey() hooked');
            hookCount++;
        } catch(e) {
            console.log('[-] setAuthKey method not found: ' + e);
        }

        // Hook constructor (might set auth key during initialization)
        try {
            DbRingConfiguration.$init.overload().implementation = function() {
                console.log("\n[DB-CONSTRUCT] DbRingConfiguration created (no args)");
                return this.$init();
            };
            hookCount++;
        } catch(e) {}

    } catch(e) {
        console.log('[-] DbRingConfiguration hook failed: ' + e);
    }

    // ==================================================
    // REALM DATABASE OPERATIONS
    // ==================================================
    try {
        var Realm = Java.use('io.realm.Realm');

        // Hook copyToRealmOrUpdate (writes/updates objects)
        Realm.copyToRealmOrUpdate.overload('io.realm.RealmModel').implementation = function(obj) {
            var objClass = obj.getClass().getName();
            if (objClass.indexOf('DbRingConfiguration') >= 0) {
                console.log("\n[REALM-WRITE] ╔═══════════════════════════════════════════════════╗");
                console.log("[REALM-WRITE] ║  Realm.copyToRealmOrUpdate()                     ║");
                console.log("[REALM-WRITE] ╚═══════════════════════════════════════════════════╝");
                console.log("[REALM-WRITE]   Object: " + objClass);

                try {
                    var authKey = obj.getAuthKey();
                    console.log("[REALM-WRITE]   Auth Key: " + hexDump(authKey));
                    console.log("[REALM-WRITE]   🔥 WRITING TO REALM DATABASE!");
                    console.log("[REALM-WRITE]   Stack trace:");
                    console.log(getStackTrace());
                } catch(e) {
                    console.log("[REALM-WRITE]   Could not read auth key: " + e);
                }
                console.log("[REALM-WRITE] ══════════════════════════════════════════════════════\n");
            }

            return this.copyToRealmOrUpdate(obj);
        };
        console.log('[+] Realm.copyToRealmOrUpdate() hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] Realm hook failed: ' + e);
    }

    // ==================================================
    // RingConfigurationManager
    // ==================================================
    try {
        var RingConfigurationManager = Java.use('com.ouraring.core.features.ringconfiguration.RingConfigurationManager');

        // Hook all public methods to see which one writes the key
        var methods = RingConfigurationManager.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            var method = methods[i];
            var methodName = method.getName();

            // Skip getters and known safe methods
            if (methodName.startsWith('get') || methodName === 'toString') continue;

            console.log('[?] Found RingConfigurationManager method: ' + methodName);
        }

    } catch(e) {
        console.log('[-] RingConfigurationManager inspection failed: ' + e);
    }

    // ==================================================
    // SharedPreferences (alternative storage)
    // ==================================================
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        var SharedPreferencesEditor = Java.use('android.content.SharedPreferences$Editor');

        // Hook getString to see if auth key is read from SharedPreferences
        var getString = SharedPreferences.getString.overload('java.lang.String', 'java.lang.String');
        getString.implementation = function(key, defValue) {
            var value = this.getString(key, defValue);

            if (key && (key.toLowerCase().indexOf('auth') >= 0 || key.toLowerCase().indexOf('ring') >= 0)) {
                console.log("\n[SHARED-PREF] getString()");
                console.log("[SHARED-PREF]   Key: " + key);
                console.log("[SHARED-PREF]   Value: " + (value ? value.substring(0, Math.min(50, value.length)) : "<null>"));
                console.log("[SHARED-PREF] ══════════════════════════════════════════════════════\n");
            }

            return value;
        };
        console.log('[+] SharedPreferences.getString() hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] SharedPreferences hook failed: ' + e);
    }

    // ==================================================
    // File I/O (if auth key is stored in files)
    // ==================================================
    try {
        var FileInputStream = Java.use('java.io.FileInputStream');

        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            if (path && (path.indexOf('auth') >= 0 || path.indexOf('ring') >= 0 || path.indexOf('oura') >= 0)) {
                console.log("\n[FILE-READ] Opening file: " + path);
            }
            return this.$init(path);
        };
        console.log('[+] FileInputStream hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] FileInputStream hook failed: ' + e);
    }

    // ==================================================
    // Network/Cloud Sync
    // ==================================================
    try {
        // Hook Retrofit/OkHttp to see if data comes from API
        var Response = Java.use('okhttp3.Response');

        Response.body.implementation = function() {
            var body = this.body();
            var request = this.request();
            var url = request.url().toString();

            if (url.indexOf('ring') >= 0 || url.indexOf('config') >= 0 || url.indexOf('auth') >= 0) {
                console.log("\n[API-RESPONSE] URL: " + url);
                console.log("[API-RESPONSE]   Code: " + this.code());
                console.log("[API-RESPONSE]   🌐 Possible cloud sync!");
                console.log("[API-RESPONSE] ══════════════════════════════════════════════════════\n");
            }

            return body;
        };
        console.log('[+] OkHttp Response hooked');
        hookCount++;
    } catch(e) {
        console.log('[-] OkHttp hook failed: ' + e);
    }

    // ==================================================
    // State Machine AUTHENTICATING state entry
    // ==================================================
    try {
        var DefaultRingStateMachine = Java.use('com.ouraring.oura.ringtracker.h');

        // We need to find the AUTHENTICATING state OnEnter method
        // This is likely where restoration happens
        console.log('[?] Attempting to hook DefaultRingStateMachine state entry...');

    } catch(e) {
        console.log('[-] State machine hook failed: ' + e);
    }

    console.log("\n════════════════════════════════════════════════════════");
    console.log("✅ " + hookCount + " hooks installed!");
    console.log("🔍 Now perform ring setup - we'll catch the write!");
    console.log("════════════════════════════════════════════════════════\n");
});
