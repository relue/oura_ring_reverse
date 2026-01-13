# Oura Ring PyTorch Model Decryption

## Overview

Oura Ring app uses **28 encrypted PyTorch models** for health analytics (sleep staging, HRV analysis, activity detection, etc.). The models are encrypted with AES-256-GCM and bundled in the APK assets.

**Key finding:** The encryption key is shipped inside the APK itself, making decryption trivial once you know where to look.

---

## Encryption Key Location

### secrets.json

**Path in decompiled APK:**
```
_large_files/decompiled/resources/res/raw/secrets.json
```

**Contents:**
```json
[
  {
    "label": "13e4f41f-5882-4dab-805f-f5c71022222a",
    "key": "awpYSTsifG1F0PUBnx6hYPfgvuRjhNEsvY6EkwneiaU=",
    "created": "2024-05-15T11:15:51"
  },
  {
    "label": "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0",
    "key": "kmElv6o7FUVdIB5/7+e1yrkIz27ojzfJ1CwZPTvTfpg=",
    "created": "2024-06-12T18:29:07"
  }
]
```

### Current Active Key

From `PyTorchModelType.java`:
```java
private static final String CURRENT_KEY_LABEL = "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0";
```

**Active Key (Base64):** `kmElv6o7FUVdIB5/7+e1yrkIz27ojzfJ1CwZPTvTfpg=`

**Active Key (Hex):** `926125bfaa3b15455d201e7fefe7b5cab908cf6ee88f37c9d42c193d3bd37e98`

---

## Encryption Details

- **Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Key Size:** 256 bits (32 bytes)
- **IV/Nonce Size:** 12 bytes
- **Auth Tag Size:** 128 bits (16 bytes)
- **File Format:** `[12-byte IV][ciphertext][16-byte GCM tag]`

### How Oura Decrypts (from PytorchModelFactory.java)

```java
// 1. Get key from EncryptionKeyHandler
String keyLabel = "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0";
byte[] key = Base64.decode(encryptionKeyHandler.getKey(keyLabel));

// 2. Read encrypted file
byte[] iv = readBytes(inputStream, 12);           // First 12 bytes = IV
byte[] encryptedData = readRemainingBytes();      // Rest = ciphertext + tag

// 3. Decrypt with AES-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(key, "AES"),
            new GCMParameterSpec(128, iv));        // 128-bit tag
byte[] decrypted = cipher.doFinal(encryptedData);

// 4. Load PyTorch model
Module model = Module.load(tempFile.getAbsolutePath());
```

---

## Python Decryption Script

```python
from Crypto.Cipher import AES
import base64
import os

# Keys from secrets.json (embedded in APK)
KEYS = {
    "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0": "kmElv6o7FUVdIB5/7+e1yrkIz27ojzfJ1CwZPTvTfpg=",
    "13e4f41f-5882-4dab-805f-f5c71022222a": "awpYSTsifG1F0PUBnx6hYPfgvuRjhNEsvY6EkwneiaU=",
}

# Current active key
CURRENT_KEY_LABEL = "2f1f19fb-f0f5-4cc3-9aeb-0591cb666ea0"
KEY = base64.b64decode(KEYS[CURRENT_KEY_LABEL])

def decrypt_oura_model(encrypted_path: str, output_path: str) -> bool:
    """
    Decrypt an Oura PyTorch model (.pt.enc -> .pt)

    Args:
        encrypted_path: Path to .pt.enc file
        output_path: Path for decrypted .pt file

    Returns:
        True if successful, False otherwise
    """
    with open(encrypted_path, 'rb') as f:
        data = f.read()

    # File format: [12-byte IV][ciphertext][16-byte tag]
    iv = data[:12]
    ciphertext_with_tag = data[12:]
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    # Decrypt using AES-GCM
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=iv)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_path, 'wb') as f:
        f.write(decrypted)

    return True

# Example usage:
# decrypt_oura_model("sleepstaging_2_6_0.pt.enc", "sleepstaging_2_6_0.pt")
```

**Dependencies:** `pip install pycryptodome`

---

## Encrypted Model Files

**Location:** `_large_files/models/assets/`

### Health & Sleep Models

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| `sleepstaging_2_6_0.pt.enc` | 2.6.0 | 114 KB | Sleep stage classification |
| `sleepnet_1_0_0.pt.enc` | 1.0.0 | 4.4 MB | Sleep analysis neural network |
| `sleepnet_moonstone_1_1_0.pt.enc` | 1.1.0 | 4.4 MB | Sleep analysis (Ring 4/Moonstone) |
| `sleepnet_bdi_0_2_2.pt.enc` | 0.2.2 | 1.4 MB | Sleep quality (BDI = ?) |

### Heart Rate & HRV Models

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| `whr_3_1_2.pt.enc` | 3.1.2 | 4.0 MB | Waking Heart Rate |
| `whr_2_6_0.pt.enc` | 2.6.0 | 4.0 MB | WHR (older version) |
| `awhr_imputation_1_1_0.pt.enc` | 1.1.0 | 889 KB | HR imputation |
| `awhr_profile_selector_0_0_1.pt.enc` | 0.0.1 | 117 KB | HR profile selection |
| `dhrv_imputation_1_0_3.pt.enc` | 1.0.3 | 41 KB | HRV imputation |
| `halite_1_1_0.pt.enc` | 1.1.0 | 3.9 MB | Unknown (HR-related?) |

### Cardiovascular Models

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| `cva_2_0_3.pt.enc` | 2.0.3 | 7.5 MB | Cardiovascular Age |
| `cva_1_2_2.pt.enc` | 1.2.2 | 1.4 MB | CVA (older version) |
| `cva_calibrator_1_2_3.pt.enc` | 1.2.3 | 16 KB | CVA calibration |

### Activity & Steps Models

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| `automatic_activity_detection_3_0_8.pt.enc` | 3.0.8 | 5.7 MB | Activity detection |
| `step_counter_1_2_0.pt.enc` | 1.2.0 | 128 KB | Step counting |
| `steps_motion_decoder_1_0_0.pt.enc` | 1.0.0 | 18 KB | Motion decoding |
| `energy_expenditure_0_0_10.pt.enc` | 0.0.10 | 1.4 MB | Calorie estimation |

### Stress Models

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| `stress_resilience_2_1_4.pt.enc` | 2.1.4 | 43 KB | Stress resilience score |
| `stress_daytime_sensing_1_0_4.pt.enc` | 1.0.4 | 12 KB | Daytime stress |
| `cumulative_stress_0_1_1.pt.enc` | 0.1.1 | 55 KB | Cumulative stress |

### Other Health Models

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| `illness_detection_0_4_1.pt.enc` | 0.4.1 | 707 KB | Sickness detection |
| `pregnancy_biometrics_0_4_0.pt.enc` | 0.4.0 | 43 KB | Pregnancy tracking |
| `meal_timing_0_0_5.pt.enc` | 0.0.5 | 14 KB | Meal detection |
| `popsicle_1_5_4.pt.enc` | 1.5.4 | 1.2 MB | Unknown |

### Baseline Models

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| `daily_medians_1_0_2.pt.enc` | 1.0.2 | 9 KB | Daily baseline medians |
| `daily_short_term_baselines_1_0_1.pt.enc` | 1.0.1 | 10 KB | Short-term baselines |

### Protected Models

| Model | Version | Size | Purpose |
|-------|---------|------|---------|
| `protected/insomnia_0_1_4.pt.enc` | 0.1.4 | 8.7 KB | Insomnia detection (restricted) |

---

## Model Format

Decrypted models are **PyTorch TorchScript** files (ZIP archives containing):

```
model_name/
├── data/           # Model weights (tensors)
│   ├── 0           # Parameter tensors
│   ├── 1
│   └── ...
├── data.pkl        # Pickle file with model state
└── code/           # TorchScript Python code
    ├── __torch__.py
    └── __torch__/
        └── *.py    # Sub-modules
```

### Inspecting Model Code

```bash
# List contents
unzip -l sleepstaging_2_6_0.pt

# Extract and view model code
unzip -p sleepstaging_2_6_0.pt "sleepstaging/code/__torch__.py"
```

### Loading with PyTorch

```python
import torch

model = torch.jit.load("sleepstaging_2_6_0.pt", map_location='cpu')
print(model)

# Run inference
output = model(acm_values, acm_timestamps, ibi_values, ibi_timestamps,
               temp_values, temp_timestamps, scalars_input, bedtime_input)
```

---

## Sleep Staging Model Architecture

The `sleepstaging_2_6_0.pt` model reveals Oura's sleep analysis pipeline:

```
Input Sensors:
├── Accelerometer (acm_values, acm_timestamps)
├── Heart Rate IBI (ibi_values, ibi_timestamps)
├── Temperature (temp_values, temp_timestamps)
├── Demographics (scalars_input)
└── Bedtime window (bedtime_input)

Processing Pipeline:
├── InputValidator          # Validate input data
├── ExtractMotionFeatures   # ACM → motion features
├── IBIRawToLowLevel        # IBI → low-level HRV
├── HrvLowToHighLevel       # Low → high-level HRV
├── TempLowToHighLevel      # Temperature features
├── ExtractTimeFeatures     # Time-of-day features
├── ExtractDemographicFeatures
├── FeatureCombiner         # Combine all features
├── SleepClassifier         # Neural network classifier
├── SleepPostprocessor      # Clean up predictions
└── Aggregate_30sec_to_5min # Aggregate to 5-min epochs

Output:
└── sleep_stages, combined_features, debug_metrics
```

---

## Key Delivery API

Models can also fetch keys from Oura's backend:

```
GET /api/v2/model-encryption-keys/{key_id}

Response: { "key": "<base64-encoded-key>" }
```

This is used for key rotation, but current keys are always bundled in the APK.

---

## Security Notes

- Keys are embedded in APK for offline functionality
- This is "security through obscurity" - protects against casual extraction
- Does NOT protect against determined reverse engineering
- GCM provides authenticity (tamper detection), not secrecy in this context

---

## Files

- **Encrypted models:** `_large_files/models/assets/*.pt.enc`
- **Encryption keys:** `_large_files/decompiled/resources/res/raw/secrets.json`
- **Key handling code:** `_large_files/decompiled/sources/com/ouraring/pytorch/PytorchModelFactory.java`
- **Model definitions:** `_large_files/decompiled/sources/com/ouraring/pytorch/PyTorchModelType.java`
- **Decrypted models:** `native_parser/decrypted_models/*.pt`

---

*Generated: 2026-01-12*
