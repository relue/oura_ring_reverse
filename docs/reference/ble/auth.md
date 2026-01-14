# BLE Authentication

Authentication flow between app and Oura Ring.

---

## Authentication Flow

```
1. App → Ring: GetAuthNonce request
   [47] [1] [43]

2. Ring → App: Nonce response
   [47] [16] [44] [nonce: 15 bytes]

3. App: Encrypt nonce with shared secret (AES/ECB/PKCS5Padding)
   encryptedNonce = encrypt(nonce, authKey)

4. App → Ring: Authenticate request
   [47] [17] [45] [encryptedNonce: 16 bytes]

5. Ring → App: Auth result
   [47] [length] [46] [0=SUCCESS / 1-3=FAILURE]
```

---

## GetAuthNonce

Request authentication challenge nonce from ring.

### Tags

| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 47 | 0x2F |
| EXTENDED_REQUEST_TAG | 43 | 0x2B |
| RESPONSE_TAG | 47 | 0x2F |
| EXTENDED_RESPONSE_TAG | 44 | 0x2C |

### Request Format (3 bytes)

```
[47] [1] [43]
 │    │   └── Extended tag: GetAuthNonce
 │    └────── Length: 1 byte follows
 └─────────── Request tag
```

### Response Format (18 bytes)

```
[47] [length] [44] [nonce: 15 bytes]
 │      │      │    └── Random 15-byte nonce
 │      │      └─────── Extended response tag
 │      └────────────── Length (typically 16)
 └───────────────────── Response tag
```

- Minimum response length: 18 bytes
- Nonce is at bytes 3-17

**Source:** `GetAuthNonce.java`

---

## Authenticate

Submit encrypted nonce to complete authentication.

### Tags

| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 47 | 0x2F |
| EXTENDED_REQUEST_TAG | 45 | 0x2D |
| RESPONSE_TAG | 47 | 0x2F |
| EXTENDED_RESPONSE_TAG | 46 | 0x2E |

### Request Format (19 bytes)

```
[47] [17] [45] [encryptedNonce: 16 bytes]
 │    │    │    └── AES-encrypted nonce
 │    │    └─────── Extended tag: Authenticate
 │    └──────────── Length: 17 bytes follow
 └───────────────── Request tag
```

### Response Format (4 bytes)

```
[47] [length] [46] [authResult: 1 byte]
 │      │      │    └── Status code (see below)
 │      │      └─────── Extended response tag
 │      └────────────── Length
 └───────────────────── Response tag
```

**Source:** `Authenticate.java`

---

## Encryption Algorithm

```
Algorithm: AES/ECB/PKCS5Padding
Input:     15-byte nonce
Key:       Auth key (16 bytes)
Output:    16 bytes (PKCS5 pads 15→16)
```

The auth key is obtained from cloud sync during ring onboarding. It appears to be AES-128 based on the 16-byte encrypted nonce output.

---

## Auth Response Values

| Value | Name | Description |
|-------|------|-------------|
| 0 | SUCCESS | Authentication successful |
| 1 | FAILURE_AUTHENTICATION_ERROR | Wrong key/encryption |
| 2 | FAILURE_IN_FACTORY_RESET | Ring is in factory reset |
| 3 | FAILURE_NOT_ORIGINAL_ONBOARDED_DEVICE | Wrong device |

**Source:** `AuthResponse.java`

---

## Auth Failure Indicator

If authentication fails, the response has special format:

```
If response[0] == 47 && response[2] == 47:
    Failure reason at response[3]
```

---

## Test Results (Verified)

```
Wrong nonce → Status 0x01 (FAILED) ✅ Confirmed
Correct nonce → Status 0x00 (SUCCESS) ✅ Expected
```

---

## Key Exchange

The shared secret (auth key) is established during ring onboarding:
1. Ring paired with app
2. Cloud API provides auth key
3. Key stored locally on phone
4. Used for all subsequent authentication

Example auth key format: `00426ed816dcece48dd9968c1f36c0b5` (16 bytes hex)

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ourakit.operations.GetAuthNonce`
- `com.ouraring.ourakit.operations.Authenticate`
- `com.ouraring.ourakit.domain.AuthResponse`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/
├── operations/
│   ├── GetAuthNonce.java
│   └── Authenticate.java
└── domain/
    └── AuthResponse.java
```

---

## See Also

- [Protocol](protocol.md) - Packet structure details
- [Data Sync](sync.md) - Post-auth data retrieval
