# libsecrets.so - Model Encryption Keys

Tiny library exposing JNI functions for ML model decryption.

**Size:** 8.7 KB
**Location:** `_large_files/native/lib/arm64-v8a/libsecrets.so`

---

## JNI Functions

```
Java_com_ouraring_core_utils_Secrets_getapiKey
Java_com_ouraring_core_utils_Secrets_getfallbackKey
```

---

## Internal Functions

| Function | Description |
|----------|-------------|
| `customDecode(char*)` | Custom decoding logic |
| `getOriginalKey(char*, int, _jstring*, _JNIEnv*)` | Key retrieval |
| `sha256(const char*, char*)` | SHA-256 hashing |

---

## Usage

Keys are used to decrypt `.pt.enc` model files (AES-GCM encryption).

### Key Retrieval Flow

```
1. EncryptionKeyHandler.getKey(label)
   └─> Check local storage for key

2. If missing:
   KeyDeliveryModel.downloadKeys()
   └─> KeyDeliveryService API call
   └─> Save key with label

3. Fallback:
   Secrets.getfallbackKey(packageName)
   └─> Native call to libsecrets.so
```

---

## Java Wrapper

**Source:** `com/ouraring/core/utils/Secrets.java`

```java
public class Secrets {
    static { System.loadLibrary("secrets"); }

    public native String getapiKey(String packageName);
    public native String getfallbackKey(String packageName);
}
```

---

## Related Classes

| Class | Purpose |
|-------|---------|
| `EncryptionKeyHandler` | Key management |
| `KeyDeliveryModel` | Key download from cloud |
| `KeyDeliveryService` | API interface |
| `PytorchModelFactory` | Uses keys for decryption |

---

## Source References

**Decompiled Classes:**
- `com.ouraring.core.utils.Secrets`
- `com.ouraring.core.model.backend.EncryptionKeyHandler`
- `com.ouraring.core.model.backend.KeyDeliveryModel`
- `com.ouraring.pytorch.PytorchModelFactory`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── core/utils/Secrets.java
├── core/model/backend/
│   ├── EncryptionKeyHandler.java
│   └── KeyDeliveryModel.java
└── pytorch/PytorchModelFactory.java
```

---

## See Also

- [ML Models](../ml/_index.md) - Model encryption details
- [ML Encryption](../ml/encryption.md) - Decryption process
