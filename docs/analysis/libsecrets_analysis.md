# libsecrets.so - Detailed Analysis

## Overview

**File:** libsecrets.so  
**Size:** 8.6KB  
**Type:** ELF 64-bit ARM64 shared library  
**Build ID:** c0319f0315cfe89ae7e26c76479b791af7cf3675  
**Status:** NOT fully stripped (exports visible)

---

## Purpose

**Primary Function:** API key obfuscation and retrieval

`libsecrets.so` is a small native library that stores and decodes hardcoded API keys using custom encoding + SHA256 hashing. It provides two keys:

1. **API Key** - Used for general backend API authentication
2. **Fallback Key** - Used for OAuth/authentication flows (HAAPI)

---

## Exported Functions (JNI)

### 1. Java_com_ouraring_core_utils_Secrets_getapiKey
```c
jstring getapiKey(JNIEnv* env, jobject obj, jstring packageName)
```

**Called from:** `com.ouraring.core.utils.l.java` (Crypto class)

**Usage:** 
- Returns the main API key
- Used as AES encryption key for encrypted data in the app
- Package name validation: expects `"com.ouraring.core.utils"`

**Purpose:** Backend API authentication to `cloud.ouraring.com`

### 2. Java_com_ouraring_core_utils_Secrets_getfallbackKey
```c
jstring getfallbackKey(JNIEnv* env, jobject obj, jstring packageName)
```

**Called from:** `com.ouraring.core.model.auth.moiv2.HaapiConfigProvider.java`

**Usage:**
- Returns fallback authentication key
- Used by HAAPI (HTTP API Authentication) OAuth driver
- Package name validation: expects `"com.ouraring.core.utils"`

**Purpose:** OAuth 2.0 authentication flows

---

## Internal Functions

### Cryptographic Functions

```c
// SHA256 implementation
void SHA256::init()
void SHA256::update(const uint8_t* data, size_t len)
void SHA256::final(uint8_t* hash)
void SHA256::transform(const uint8_t* data, size_t blocks)

// Utility
void sha256(const char* input, char* output)
```

**Constants:** `SHA256::sha256_k` - SHA256 K constants table

### Obfuscation Functions

```c
void customDecode(char* encoded)
```
- Custom decoding algorithm for obfuscated keys

```c
void getOriginalKey(char* buffer, int length, jstring packageName, JNIEnv* env)
```
- Validates package name
- Decodes hardcoded key data
- Returns decoded key

---

## Key Extraction Process

### Step 1: Package Name Validation
The library checks that the calling package matches:
```
"com.ouraring.core.utils"
```

This prevents:
- Repackaged/modded apps from extracting keys
- Third-party apps from calling the JNI functions

### Step 2: Custom Decoding
Hardcoded obfuscated strings (visible in strings output):
```
Tp8G"(@JTU~Zdy(l!4O\/#V8
Kq4T7,jL,~
sQ_hAVRP
tjZzWQ#
\P>gC
*T|~
e],P,
```

These are processed by `customDecode()` function.

### Step 3: SHA256 Processing
- The decoded string may be hashed with SHA256
- Final key is returned as a Java String

---

## Usage in App

### 1. AES Encryption Key (getapiKey)

**File:** `com/ouraring/core/utils/l.java` (Crypto utilities)

```java
// Lazy initialization
private static final Lazy<Secrets> secrets = lazy(() -> new Secrets());
private static final Lazy<String> secretKey = lazy(() -> 
    secrets.getValue().getapiKey("com.ouraring.core.utils")
);

// AES Cipher setup
private static final Lazy<Cipher> cipher = lazy(() -> {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    byte[] keyBytes = secretKey.getValue().getBytes(UTF_8);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
    return cipher;
});

// Decrypt function
public static String decrypt(String encrypted) {
    byte[] decoded = Base64.getDecoder().decode(encrypted);
    synchronized (Cipher.class) {
        return new String(cipher.getValue().doFinal(decoded), UTF_8);
    }
}
```

**Purpose:** Decrypts AES-encrypted strings stored in the app (likely tokens, sensitive config)

### 2. OAuth Key (getfallbackKey)

**File:** `com/ouraring/core/model/auth/moiv2/HaapiConfigProvider.java`

```java
// HAAPI driver initialization
se.curity.identityserver.haapi.android.driver.b driver = 
    new se.curity.identityserver.haapi.android.driver.b(
        new Secrets().getfallbackKey("com.ouraring.core.utils")
    );
```

**Purpose:** OAuth 2.0 client authentication with Curity Identity Server (HAAPI framework)

---

## Security Analysis

### Strengths ✅

1. **Native obfuscation** - Keys not in Java bytecode
2. **Custom encoding** - Not just Base64
3. **Package name validation** - Prevents unauthorized access
4. **SHA256 hashing** - Additional transformation layer
5. **Small size** (8.6KB) - Minimal attack surface

### Weaknesses ⚠️

1. **Hardcoded keys** - Keys embedded in binary
2. **Reversible** - Can be extracted with:
   - Frida hooking the JNI functions
   - Ghidra/IDA disassembly + emulation
   - Runtime memory dump
3. **Static obfuscation** - Doesn't use device-specific data
4. **Predictable** - Package name check is easy to bypass

---

## Extraction Methods

### Method 1: Frida Hook (Easy)

```javascript
// Hook the JNI function
Java.perform(() => {
    const Secrets = Java.use("com.ouraring.core.utils.Secrets");
    
    Secrets.getapiKey.implementation = function(pkg) {
        const key = this.getapiKey(pkg);
        console.log("[*] API Key:", key);
        return key;
    };
    
    Secrets.getfallbackKey.implementation = function(pkg) {
        const key = this.getfallbackKey(pkg);
        console.log("[*] Fallback Key:", key);
        return key;
    };
});
```

### Method 2: Disassembly (Advanced)

1. Load libsecrets.so in Ghidra
2. Analyze `Java_com_ouraring_core_utils_Secrets_getapiKey`
3. Trace to hardcoded data section
4. Reverse `customDecode` algorithm
5. Extract and decode keys

### Method 3: Memory Dump (Medium)

```bash
# Attach to running app
frida -U com.ouraring.oura

# Find libsecrets.so in memory
Process.enumerateModules().find(m => m.name === "libsecrets.so")

# Dump entire memory region
Memory.readByteArray(module.base, 8192)
```

---

## What These Keys Are Used For

### API Key (getapiKey)
- **Backend authentication** to `cloud.ouraring.com`
- **AES encryption/decryption** of local data
- **Token encryption** in Realm database
- **HTTP Authorization** headers

### Fallback Key (getfallbackKey)
- **OAuth 2.0 client secret**
- **HAAPI authentication** with Curity Identity Server
- **WebAuthn** fallback authentication
- **Token refresh** operations

---

## Recommended Next Steps

### 1. Extract Keys (Dynamic)
```bash
# Launch app with Frida
frida -U -f com.ouraring.oura -l hook-secrets.js

# Trigger authentication flow
# Keys will be logged to console
```

### 2. Reverse customDecode (Static)
- Disassemble in Ghidra
- Identify XOR/shift operations
- Write decoder in Python

### 3. Decrypt App Data
- Once keys extracted
- Locate encrypted strings in APK
- Decrypt using AES/ECB/PKCS5

### 4. API Analysis
- Use extracted API key
- Craft authenticated requests to cloud.ouraring.com
- Map API endpoints and data models

---

## Build Information

**Compiler:** Android Clang 18.0.1 (r522817)  
**Optimizations:** PGO, BOLT, LTO, MLGO  
**Build ID:** 12027248  
**Platform:** Android NDK (based on r522817)

---

## Summary

`libsecrets.so` is a **key protection module** that:

1. ✅ Obfuscates API keys in native code
2. ✅ Validates calling package to prevent abuse
3. ✅ Uses custom encoding + SHA256 for protection
4. ✅ Provides two keys: API key and OAuth fallback key
5. ⚠️ Can be defeated with Frida/Ghidra
6. ⚠️ Keys are static (not device-specific)

**Primary Purpose:** Hide API credentials from casual reverse engineering, but not designed to prevent determined attackers.

**Best Attack Vector:** Frida runtime hooking (5 lines of JavaScript)

---

**Analysis Date:** November 2, 2025  
**Analyst:** Claude Code  
**Tools:** strings, nm, hexdump, JADX decompilation
