# Oura Ring APK: Encryption Keys Analysis

**Last Updated:** 2026-01-12

## 1. Executive Summary

Analysis of the Oura Ring Android APK revealed two encrypted third-party service keys stored in app resources. These keys are decrypted at runtime using an AES key retrieved from `libsecrets.so`.

**Keys Found:**
| Key | Type | Actual Capability |
|-----|------|-------------------|
| `segment_writeKey` | Segment CDP Write Key | Send events to Segment (write-only) |
| `braze_key` | Braze SDK Identifier (app_id) | Initialize SDK, track events (NOT a REST API key) |

**Critical Finding:** The `braze_key` is an **SDK identifier (app_id)**, NOT a REST API key. This dramatically limits what an attacker can do - they cannot send push notifications, export user data, or broadcast messages to users.

**Overall Risk Assessment:** Medium (business intelligence corruption risk, no direct user harm)

---

## 2. Keys Found in APK

### Source Location

**File:** `resources/res/values/strings.xml`

```xml
<string name="segment_writeKey">Y09Ds+pT+A46TKL9PLU0q3nFmZLH8XtIt8ofSKvOXo6x5WRexGcM7KsUXxkMt6VG</string>
<string name="braze_key">TE7Y3IZr1QLJ6ElqvHW8wA4w2yKrnQhOfPwGssj7vCXHGMKwbeoEbfEVSlUaLWGP</string>
<string name="braze_url">sdk.iad-06.braze.com</string>
```

These values are **AES-encrypted** (Base64-encoded ciphertext). The decryption key is retrieved from `libsecrets.so`.

### 2.1 Segment Write Key (`segment_writeKey`)

**Type:** Segment Customer Data Platform (CDP) Write Key

**Purpose:** Send tracking events from the mobile app to Oura's Segment workspace

**Authentication Model:**
```bash
curl https://api.segment.com/v1/track \
  -u "SEGMENT_WRITE_KEY:" \  # Key is username, password is empty
  -d '{ "userId": "...", "event": "...", "properties": {...} }'
```

### 2.2 Braze Key (`braze_key`)

**Type:** Braze SDK Identifier (app_id) - **NOT a REST API key**

**Purpose:** Initialize the Braze SDK for event tracking and receiving push notifications

**Code Evidence** (`BrazeManager.java:624`):
```kotlin
BrazeConfig.Builder().setApiKey(decryptedBrazeKey)
```

This is **SDK initialization**, not REST API authentication. The method name `setApiKey()` is misleading - it actually sets the app identifier used by the client SDK.

**Why This Distinction Matters:**
- SDK keys (app_id): Used for `BrazeConfig.Builder()` initialization in mobile apps
- REST API keys: Used for `Authorization: Bearer` headers in server-side API calls
- These are completely different keys with vastly different capabilities

---

## 3. Key Type Analysis

### Capability Comparison Table

| Capability | Segment Write Key | Braze SDK Key | Braze REST API Key |
|------------|-------------------|---------------|-------------------|
| Send tracking events | Yes | Yes | Yes |
| Create fake user profiles | Yes | Yes | Yes |
| Read existing user data | **No** | **No** | Yes |
| Export user data | **No** | **No** | Yes |
| Send push notifications | **No** | **No** | Yes |
| Broadcast messages | **No** | **No** | Yes |
| Trigger campaigns | **No** | **No** | Yes |
| Access dashboard | **No** | **No** | **No** (requires login) |

### What Each Key CAN Do

**Segment Write Key:**
- Send tracking events to Oura's Segment workspace
- Inject fake user data and analytics
- Create fake user identities
- Log fake events (purchases, signups, feature usage)

**Braze SDK Key:**
- Track events FROM a malicious app (send fake analytics)
- Create fake user profiles (impersonate or fabricate users)
- Update user attributes (subscription tier, preferences)
- Register fake devices for push (if engagement UIDs known)
- Log fake purchases (corrupt revenue tracking)

### What Each Key CANNOT Do

**Segment Write Key:**
- Cannot read existing data (write-only key)
- Cannot export user profiles
- Cannot access Segment dashboard
- Cannot send messages to users

**Braze SDK Key:**
- **Cannot send push notifications** (requires REST API key)
- **Cannot broadcast messages** (requires REST API key)
- **Cannot export user data** (requires REST API key)
- **Cannot trigger campaigns** (requires REST API key)
- Cannot access Braze dashboard

---

## 4. How Keys Are Used

### 4.1 libsecrets.so Decryption Flow

The API key from `libsecrets.so` is **NOT used for Oura's backend API calls**. It serves as an **AES encryption key** to decrypt embedded third-party service credentials.

**Native Key Retrieval:**

**Location:** `lib/arm64-v8a/libsecrets.so`

**JNI Functions:**
```c
jstring Java_com_ouraring_core_utils_Secrets_getapiKey(JNIEnv*, jobject, jstring packageName)
jstring Java_com_ouraring_core_utils_Secrets_getfallbackKey(JNIEnv*, jobject, jstring packageName)
```

**Keys Provided:**
- `apiKey`: Used as AES encryption key for decrypting resource strings
- `fallbackKey`: Used for OAuth 2.0 / HAAPI authentication client configuration

### 4.2 Key Retrieval Mechanism

**Step 1: Java Wrapper**

**File:** `sources/com/ouraring/core/utils/Secrets.java`

```java
public final class Secrets {
    static {
        System.loadLibrary("secrets");
    }
    public final native String getapiKey(String packageName);
    public final native String getfallbackKey(String packageName);
}
```

**Step 2: Crypto Utility**

**File:** `sources/com/ouraring/core/utils/l.java`

```java
// Algorithm: AES/ECB/PKCS5Padding
// Input: Base64-encoded encrypted strings

public static String a(String encryptedString) {
    byte[] decode = Base64.getDecoder().decode(str);
    synchronized (Cipher.class) {
        doFinal = ((Cipher) f21123b.getValue()).doFinal(decode);
    }
    return new String(doFinal, UTF_8);
}

public static String b(String encryptedString) {
    try {
        return a(encryptedString);
    } catch (Exception e5) {
        throw new ApiKeyDecryptionException("...", e5.getMessage());
    }
}
```

**Step 3: Segment Initialization**

**File:** `sources/com/ouraring/oura/analytics/segment/q.java:166-171`

```java
public final void b() {
    String string = context.getString(bj.n.segment_writeKey);  // Get encrypted key

    // Decrypt and initialize Segment
    com.segment.analytics.e eVar = new com.segment.analytics.e(
        context,
        com.ouraring.core.utils.l.b(string)  // <- Decryption happens here
    );
    // ...
}
```

**Step 4: Braze Initialization**

**File:** `sources/com/ouraring/oura/model/manager/BrazeManager.java:619-639`

```java
public final void setup(Application application) {
    String string = application.getString(bj.n.braze_key);  // Get encrypted key

    // Decrypt and configure Braze SDK
    BrazeConfig.Builder apiKey = new BrazeConfig.Builder()
        .setApiKey(com.ouraring.core.utils.l.b(string))  // <- Decryption
        .setCustomEndpoint(string2)  // sdk.iad-06.braze.com
        .setIsFirebaseCloudMessagingRegistrationEnabled(true)
        // ...

    Braze.INSTANCE.configure(application, apiKey.build());
}
```

### 4.3 Runtime Flow Diagram

```
App Launch
    |
    v
Application.onCreate()
    |
    +---> Secrets.getapiKey("com.ouraring.oura")
    |         |
    |         v
    |     libsecrets.so (returns AES key)
    |         |
    |         v
    +---> l.b(encrypted_segment_key) ---> Decrypted Segment Write Key
    |         |
    |         v
    |     Segment SDK initialized
    |
    +---> l.b(encrypted_braze_key) ---> Decrypted Braze SDK Key
              |
              v
          Braze SDK initialized
```

---

## 5. Security Assessment

### 5.1 Realistic Attack Scenarios

#### Attack 1: Analytics Poisoning (HIGH likelihood)

**Objective:** Corrupt business intelligence to mislead decision-making

```bash
# Create fake "Premium Subscription" events
for i in {1..10000}; do
  curl https://api.segment.com/v1/track \
    -u "SEGMENT_WRITE_KEY:" \
    -d '{
      "userId": "fake_user_'$i'",
      "event": "Subscription Started",
      "properties": { "plan": "premium_annual", "revenue": 299.99 }
    }'
done
```

**Impact:**
- KPI corruption: Inflates conversion rates, revenue, user growth
- Bad product decisions: Makes failing features appear successful
- Investor misrepresentation: Board decks show fake growth
- Financial reporting issues: If Segment feeds BI dashboards

#### Attack 2: Fake User Creation (MEDIUM likelihood)

**Objective:** Create thousands of fake users in Braze workspace

```kotlin
// Using extracted SDK key in malicious app
for (i in 1..10_000) {
    Braze.getInstance(context).changeUser("bot_user_$i")
    Braze.getInstance(context).getCurrentUser()?.apply {
        setEmail("bot$i@fakeemail.com")
        setCustomUserAttribute("subscription_tier", "premium")
    }
}
```

**Impact:**
- Billing impact: Braze charges per Monthly Active User (MAU)
- User count inflation: Fake growth metrics
- Database bloat: Storage costs increase

#### Attack 3: User Impersonation (LOW likelihood)

**Prerequisites:** Requires knowing victim's `engagement_uid`

```kotlin
// Impersonate victim if their engagement UID is known
Braze.getInstance(context).changeUser("victim_engagement_uid_12345")
Braze.getInstance(context).getCurrentUser()?.apply {
    setEmail("attacker@evil.com")  // Change victim's email
}
```

**Impact:**
- Could change victim's email/phone in Braze
- Could receive notifications meant for victim (if push token registered)
- **Requires additional information that is not easily obtainable**

### 5.2 Impossible Attack Scenarios

The following attacks are **NOT POSSIBLE** with the extracted SDK keys:

| Attack | Why It Fails |
|--------|--------------|
| Mass phishing push notifications | SDK key cannot call `/messages/send` REST endpoint |
| Broadcast messages to all users | Requires REST API key with `messages.send` permission |
| Export user data | SDK key has no export capabilities |
| Access Braze/Segment dashboards | Requires separate login credentials |
| Modify scheduled campaigns | Requires REST API key with campaign permissions |
| Access health data | Not stored in Segment/Braze; separate OAuth-protected backend |

### 5.3 Risk Matrix

| Risk Category | Severity | Likelihood | Feasibility |
|---------------|----------|------------|-------------|
| Analytics corruption (Segment) | **High** | Medium | Possible |
| Analytics corruption (Braze) | **Medium** | Medium | Possible |
| Fake user creation | **Low** | Medium | Possible |
| User impersonation | **Medium** | Very Low | Requires engagement UID |
| Push token theft | **Medium** | Very Low | Requires engagement UID |
| **Mass phishing** | ~~Critical~~ | - | **IMPOSSIBLE** |
| **User data export** | ~~High~~ | - | **IMPOSSIBLE** |
| **Broadcast messaging** | ~~Critical~~ | - | **IMPOSSIBLE** |

### 5.4 Financial Impact Estimates

**Segment Write Key Compromise:**
- Event overage charges: $1K-$50K/month (if attacker spams events)
- Analytics corruption: Indirect (bad decisions, wasted resources)
- Cleanup costs: Engineering time to filter fake events

**Braze SDK Key Compromise:**
- Fake MAU charges: ~$1-$5 per MAU x fake user count
- 10K fake users = $10K-$50K/month potential waste
- Cleanup costs: Database cleanup, anomaly detection

**Total Estimated Impact:** $10K-$100K in direct costs

**User Data Breach:** $0 - Health metrics are NOT in these platforms

---

## 6. Code References

### Key Files in Decompiled APK

| File | Purpose |
|------|---------|
| `lib/arm64-v8a/libsecrets.so` | Native JNI library providing obfuscated AES key |
| `com/ouraring/core/utils/Secrets.java` | JNI wrapper for key retrieval |
| `com/ouraring/core/utils/l.java` | AES/ECB decryption utility |
| `com/ouraring/oura/analytics/segment/q.java:166-171` | Segment SDK initialization |
| `com/ouraring/oura/model/manager/BrazeManager.java:619-639` | Braze SDK configuration |
| `com/ouraring/core/model/auth/moiv2/HaapiConfigProvider.java:65` | OAuth client setup (uses fallbackKey) |
| `resources/res/values/strings.xml` | Encrypted third-party API keys |

### Encryption Details

- **Algorithm:** AES/ECB/PKCS5Padding
- **Weakness:** ECB mode is cryptographically weak (no IV, deterministic)
- **Key Storage:** Native binary with custom obfuscation
- **Package Validation:** Keys only work with correct package name

---

## 7. Recommendations

### For Detection

```sql
-- Detect Segment event spikes
SELECT event_name, COUNT(*) as count, DATE(timestamp) as date
FROM segment_events
GROUP BY event_name, date
HAVING count > (SELECT AVG(count) + 3*STDDEV(count) FROM ...)
```

### For Mitigation

**Immediate:**
1. Implement IP allowlisting on Segment/Braze
2. Enable rate limiting per API key
3. Set up anomaly detection alerts

**Long-Term:**
1. Use authenticated proxy instead of embedding keys
2. Enable Braze SDK Authentication (JWT validation)
3. Server-side validation for high-value events

---

## 8. Conclusion

The compromised keys pose a **business risk**, not a **user security risk**. Oura's architecture correctly separates:
- Engagement platforms (Segment/Braze) - analytics and marketing
- Health data storage - OAuth 2.0 protected backend

The most severe attacks (mass phishing, data export, broadcast messaging) are **impossible** because the extracted Braze key is an SDK identifier, not a REST API key.

| Stakeholder | Risk Level | Reason |
|-------------|------------|--------|
| Oura Users | Low | No direct harm, health data unaffected |
| Oura Product Team | Medium | Analytics corruption could mislead decisions |
| Oura Finance | Medium | Potential billing fraud ($10K-$100K) |
| Oura Reputation | Low | No user-facing breach, no data leak |

---

*Merged from: attacker_model_keys_v2.md + api_key_usage_analysis.md*
