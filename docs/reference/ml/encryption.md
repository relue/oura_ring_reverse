# ML Model Encryption

All models are encrypted with AES-GCM.

---

## Encryption Scheme

```
File Format:
[12-byte IV] [encrypted data + 128-bit auth tag]

Decryption:
cipher = AES/GCM/NoPadding
iv = first 12 bytes
ciphertext = remaining bytes
tag_length = 128 bits
```

---

## Key Retrieval Flow

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

## Current Key Label

```java
CURRENT_KEY_LABEL = "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0"
```

**Source:** `pytorch/PytorchModelFactory.java:37-68`

---

## Model Loading Sequence

```
PytorchModelFactory.getModel(type)
  └─> decryptToTempFile(type.filename, key)
  └─> Module.load(tempPath)
  └─> Create *PytorchModel wrapper
  └─> Delete temp file
```

### Decryption Steps

```java
1. Read IV (12 bytes) from encrypted file
2. Read remaining ciphertext
3. Get key from EncryptionKeyHandler
4. Decrypt with AES-GCM (128-bit tag)
5. Write to temp file
6. Load with PyTorch Module.load()
```

---

## File Naming Convention

```
{model_name}_{version}.pt.enc

Examples:
- sleepnet_1_0_0.pt.enc
- cva_2_0_3.pt.enc
- stress_resilience_2_1_4.pt.enc
```

---

## Source References

**Decompiled Classes:**
- `com.ouraring.pytorch.PytorchModelFactory`
- `com.ouraring.core.model.backend.EncryptionKeyHandler`
- `com.ouraring.core.model.backend.KeyDeliveryModel`
- `com.ouraring.core.utils.Secrets`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── pytorch/PytorchModelFactory.java
├── core/model/backend/
│   ├── EncryptionKeyHandler.java
│   └── KeyDeliveryModel.java
└── core/utils/Secrets.java
```

---

## See Also

- [Native Libraries - Secrets](../native/secrets.md) - libsecrets.so key retrieval
- [ML Models](_index.md) - Model inventory
