# Oura Ring API Key Usage Analysis

## Executive Summary

The "backend API key" retrieved from `libsecrets.so` is **NOT** used for Oura's backend API calls. Instead, it serves as an **AES encryption key** to decrypt embedded third-party service credentials stored in the app's resources.

## API Key Flow

### 1. Native Key Retrieval (`libsecrets.so`)

**Location**: `/home/picke/reverse_oura/analysis/native/lib/arm64-v8a/libsecrets.so`

**JNI Functions**:
```c
jstring Java_com_ouraring_core_utils_Secrets_getapiKey(JNIEnv*, jobject, jstring packageName)
jstring Java_com_ouraring_core_utils_Secrets_getfallbackKey(JNIEnv*, jobject, jstring packageName)
```

- Two keys are provided:
  - **`apiKey`**: Used as AES encryption key for decrypting resource strings
  - **`fallbackKey`**: Used for OAuth 2.0 / HAAPI authentication client configuration

### 2. Java Wrapper (`com.ouraring.core.utils.Secrets`)

**File**: `sources/com/ouraring/core/utils/Secrets.java:13-15`

```java
public final class Secrets {
    static {
        System.loadLibrary("secrets");
    }
    public final native String getapiKey(String packageName);
    public final native String getfallbackKey(String packageName);
}
```

### 3. Crypto Utility (`com.ouraring.core.utils.l`)

**File**: `sources/com/ouraring/core/utils/l.java`

**Purpose**: Provides AES decryption using the API key

**Key Components**:
- **Algorithm**: `AES/ECB/PKCS5Padding`
- **Input Format**: Base64-encoded encrypted strings
- **Initialization**: Lazy-loaded using Kotlin delegates

**Decrypt Functions**:
```java
// Line 41-51: Base64 decode + AES decrypt
public static String a(String encryptedString) {
    byte[] decode = Base64.getDecoder().decode(str);
    synchronized (Cipher.class) {
        doFinal = ((Cipher) f21123b.getValue()).doFinal(decode);
    }
    return new String(doFinal, UTF_8);
}

// Line 53-63: Decrypt with error handling
public static String b(String encryptedString) {
    try {
        return a(encryptedString);
    } catch (Exception e5) {
        throw new ApiKeyDecryptionException("...", e5.getMessage());
    }
}
```

## What is the API Key Used For?

### Primary Purpose: Third-Party Service Credential Decryption

The API key is used to decrypt **embedded third-party analytics and engagement service keys** that are stored as encrypted strings in the app's resources.

### Encrypted Resources Found

**File**: `resources/res/values/strings.xml`

1. **Segment Analytics Write Key** (encrypted):
   ```xml
   <string name="segment_writeKey">Y09Ds+pT+A46TKL9PLU0q3nFmZLH8XtIt8ofSKvOXo6x5WRexGcM7KsUXxkMt6VG</string>
   ```

2. **Braze API Key** (encrypted):
   ```xml
   <string name="braze_key">TE7Y3IZr1QLJ6ElqvHW8wA4w2yKrnQhOfPwGssj7vCXHGMKwbeoEbfEVSlUaLWGP</string>
   ```

3. **Braze Endpoint** (plaintext):
   ```xml
   <string name="braze_url">sdk.iad-06.braze.com</string>
   ```

4. **Other Plaintext Keys** (no decryption needed):
   - `google_api_key`: AIzaSyBoM4Iq2onE522CZc5dAoWDZC05hMZYas8
   - `intercom_api_key`: android_sdk-2a8f7942cda7511a47faa6446182ed6390608bf4
   - `hipaa_braze_api_key`: EX+4sVremxHKpxHHBuu3YZwEVR4/AvWel18xBKIOID4Gf7zMOLotm+tprMIJ4z3A (unused in code)

## Where is the API Key Used?

### Usage Site #1: Segment Analytics Initialization

**File**: `sources/com/ouraring/oura/analytics/segment/q.java:166-171`

**Class**: `SegmentAnalyticsManager`

**Method**: `public final void b()` (setup method)

```java
public final void b() {
    Context context = this.f22463a;
    zx.f fVar = com.ouraring.core.utils.l.f21122a;
    String string = context.getString(bj.n.segment_writeKey);  // Get encrypted key from resources
    kotlin.jvm.internal.f.h(string, "getString(...)");

    // DECRYPT SEGMENT KEY using l.b()
    com.segment.analytics.e eVar = new com.segment.analytics.e(
        context,
        com.ouraring.core.utils.l.b(string)  // <- API key decryption happens here
    );

    eVar.f46633j = true;  // Track lifecycle
    // ... register middleware and initialize Segment
    com.segment.analytics.f a11 = eVar.a();
    com.segment.analytics.f.B = a11;  // Set global Segment instance
}
```

**What it tracks**:
- User behavior analytics
- Screen views
- Custom events (e.g., onboarding steps, feature usage)
- User properties (ring type, subscription status, health metrics)

### Usage Site #2: Braze Push Notification & Engagement

**File**: `sources/com/ouraring/oura/model/manager/BrazeManager.java:619-639`

**Class**: `BrazeManager`

**Method**: `public final void setup(Application application)`

```java
public final void setup(Application application) {
    kotlin.jvm.internal.f.i(application, "application");
    f fVar = com.ouraring.core.utils.l.f21122a;

    String string = application.getString(bj.n.braze_key);  // Get encrypted key
    kotlin.jvm.internal.f.h(string, "getString(...)");

    // DECRYPT BRAZE API KEY using l.b()
    BrazeConfig.Builder apiKey = new BrazeConfig.Builder()
        .setApiKey(com.ouraring.core.utils.l.b(string));  // <- API key decryption

    String string2 = application.getString(bj.n.braze_url);
    kotlin.jvm.internal.f.h(string2, "getString(...)");

    BrazeConfig.Builder defaultNotificationChannelDescription = apiKey
        .setCustomEndpoint(string2)  // sdk.iad-06.braze.com
        .setIsFirebaseCloudMessagingRegistrationEnabled(true)
        .setFirebaseCloudMessagingSenderIdKey(this.gcmDefaultSenderId)
        .setHandlePushDeepLinksAutomatically(true)
        .setDefaultNotificationChannelName("Campaign")
        .setLargeNotificationIcon("ic_oura_symbol_boxed")
        .setSmallNotificationIcon("ic_oura_symbol_boxed")
        .setDefaultNotificationChannelDescription("Campaign related push");

    // Configure logging based on build flavor
    if (CoreConstants.Flavor.PRODUCTION.isCurrentFlavor()) {
        BrazeLogger.setLogLevel(6);  // ASSERT level (minimal logging)
    } else {
        BrazeLogger.setLogLevel(4);  // INFO level
        defaultNotificationChannelDescription.setInAppMessageTestPushEagerDisplayEnabled(true);
    }

    Braze.Companion companion = Braze.INSTANCE;
    companion.configure(application, defaultNotificationChannelDescription.build());

    // Register lifecycle callbacks (excludes login/onboarding screens from tracking)
    application.registerActivityLifecycleCallbacks(
        new BrazeActivityLifecycleCallbackListener(true, true,
            kotlin.collections.n.I0(new Class[]{
                LogInActivity.class,
                WelcomeOnBoardActivity.class,
                UserProfileActivity.class,
                AssaMigrationProgressActivity.class,
                ProfileQuestionsActivity.class,
                AllowNotificationsActivity.class,
                HealthConnectOnboardingActivity.class,
                TopWorkoutsActivity.class,
                RingOnboardingActivity.class,
                PermissionsActivity.class
            }), null, 8, null)
    );

    this.braze = companion.getInstance(application);
    setupUserAndAttributes(application, this.authModel.isUserLoggedIn());
}
```

**What it's used for**:
- Push notification campaigns
- In-app messaging
- User engagement tracking
- User attribute synchronization (sleep score, ring model, cycle insights, etc.)
- A/B testing and feature flags

### Usage Site #3: OAuth 2.0 Client Configuration

**File**: `sources/com/ouraring/core/model/auth/moiv2/HaapiConfigProvider.java:65`

**Class**: `HaapiConfigProvider`

**Method**: `public final e createFactory()`

```java
public final e createFactory() {
    // ... OAuth registration and token endpoints setup ...

    // Use FALLBACK KEY (not API key) for OAuth driver
    se.curity.identityserver.haapi.android.driver.b bVar2 =
        new se.curity.identityserver.haapi.android.driver.b(
            new Secrets().getfallbackKey("com.ouraring.core.utils")
        );

    // Configure HAAPI (Hypermedia Authentication API) for OAuth 2.0
    e eVar = new e(new se.curity.identityserver.haapi.android.sdk.f(
        keyStoreAliasName,  // "production_release_android_keystore"
        uri,                // Base OAuth endpoint
        resolve3,           // /oauth/v2/oauth-token
        resolve4,           // /oauth/v2/oauth-authorize
        // ... scopes, headers, revoke endpoint ...
    ));

    return eVar;
}
```

**Note**: This uses the **`fallbackKey`**, not the main `apiKey`.

## UI Flows That Trigger API Key Usage

### Flow 1: App Launch → Analytics Initialization

**Trigger**: Application.onCreate()

**Steps**:
1. **App starts** → `Application` class `onCreate()` called
2. **Dependency injection** initializes `SegmentAnalyticsManager` and `BrazeManager`
3. **SegmentAnalyticsManager.setup()** called:
   - Retrieves encrypted `segment_writeKey` from resources
   - Calls `Secrets.getapiKey()` from native library
   - Decrypts Segment write key using AES
   - Initializes Segment SDK with decrypted key
   - Sets up analytics event tracking
4. **BrazeManager.setup()** called:
   - Retrieves encrypted `braze_key` from resources
   - Calls `Secrets.getapiKey()` from native library
   - Decrypts Braze API key using AES
   - Configures Braze SDK with endpoint `sdk.iad-06.braze.com`
   - Registers activity lifecycle callbacks
   - Initializes push notification handlers

**When**: Once per app launch (before any UI is shown)

**User sees**: Splash screen or initial loading screen

### Flow 2: User Login → Braze User Identification

**Trigger**: User successfully logs in

**Steps**:
1. User enters credentials on **LoginActivity**
2. Authentication completes successfully
3. **BrazeManager.setupUserAndAttributes()** called:
   - Changes Braze user ID to `engagementUid`
   - Syncs user attributes:
     - Ring configuration (model, size, hardware type)
     - Subscription tier
     - User settings (country, units preference)
     - Health features enabled (cycle tracking, metabolic health, etc.)
     - Recent health metrics (readiness, sleep, activity scores)
4. **Segment tracks** "User Logged In" event

**When**: Every login

**User sees**: Dashboard loads with personalized content

### Flow 3: Throughout App Usage → Event Tracking

**Triggers**: User interactions with any feature

**Common tracked events** (examples):
- Screen views (Dashboard, Sleep Details, Activity, etc.)
- Onboarding steps completed
- Ring pairing events
- Health Connect integration enabled
- Feature discovery (Oura Labs, Cardiovascular Age, etc.)
- Settings changes
- Third-party app connections

**Processing**:
1. User action occurs (e.g., taps "Sleep" tab)
2. Activity/Fragment calls `SegmentAnalytics.track("Screen View", properties)`
3. Segment SDK (using decrypted write key) sends event to Segment backend
4. Braze SDK (using decrypted API key) may trigger in-app messages or record custom events

**When**: Continuously during app usage

**User sees**: Normal app interaction (tracking is invisible)

### Flow 4: Push Notification Campaigns

**Trigger**: Server-side campaign trigger or scheduled push

**Steps**:
1. Braze backend sends push notification via FCM
2. FCM delivers to device
3. **BrazeManager** (configured with decrypted API key) handles notification:
   - Displays notification with campaign content
   - Tracks notification received/opened
   - Deep links to specific app screen if clicked
4. Segment tracks "Push Notification Opened" event

**When**: Anytime (background or foreground)

**User sees**: System notification drawer

### Flow 5: OAuth Authentication (Cloud API Access)

**Trigger**: User connects third-party app or uses Oura Cloud API

**Steps**:
1. User taps "Connect" on third-party integration
2. **HaapiConfigProvider.createFactory()** called:
   - Uses `Secrets.getfallbackKey()` for OAuth client configuration
   - Initializes HAAPI authentication flow
3. OAuth authorization screen shown
4. User grants permissions
5. OAuth token issued by Oura backend

**When**: First-time integration setup or re-authentication

**User sees**: OAuth consent screen

## Summary of Findings

### API Key Purpose

The "API key" from `libsecrets.so` is **NOT a backend API key** for Oura's health data API. It is:

1. **An AES encryption key** for decrypting embedded third-party service credentials
2. **Security through obscurity**: Prevents casual extraction of Segment/Braze keys from APK resources
3. **Not used for Oura API calls**: The main Oura backend uses OAuth 2.0 tokens for authentication

### Security Assessment

**Current Protection**:
- Third-party keys are AES-encrypted in resources
- Decryption key stored in native library with custom obfuscation
- Package name validation prevents reuse in other apps

**Weaknesses**:
- AES/ECB mode is cryptographically weak (no IV, deterministic)
- Key can be extracted via Frida hooking (as demonstrated in libsecrets_analysis.md)
- Once API key is obtained, all encrypted resources can be decrypted
- Hardcoded keys in native binary are reversible with patience

**Impact if compromised**:
- Attacker gains Segment write key → Can send fake analytics to Oura's Segment workspace
- Attacker gains Braze API key → Can send unauthorized push campaigns (if other protections fail)
- Does NOT grant access to user health data or Oura backend API

### Architecture Insights

Oura uses a **multi-layer analytics stack**:

1. **Segment** - Unified analytics hub:
   - Collects all user events
   - Forwards to downstream destinations (likely Amplitude, Mixpanel, etc.)

2. **Braze** - User engagement platform:
   - Push notifications
   - In-app messages
   - Email campaigns
   - User attribute syncing

3. **Sentry** - Error tracking (also uses decrypted configuration)

4. **Firebase** - Crash reporting, FCM for push delivery

This architecture separates health data security (OAuth 2.0) from engagement platform credentials (AES-encrypted).

## Files Referenced

| File | Purpose |
|------|---------|
| `libsecrets.so` | Native JNI library providing obfuscated keys |
| `com.ouraring.core.utils.Secrets.java` | JNI wrapper for key retrieval |
| `com.ouraring.core.utils.l.java` | Crypto utility (AES decryption) |
| `com.ouraring.oura.analytics.segment.q.java` | Segment analytics initialization |
| `com.ouraring.oura.model.manager.BrazeManager.java` | Braze SDK configuration |
| `com.ouraring.core.model.auth.moiv2.HaapiConfigProvider.java` | OAuth client setup |
| `resources/res/values/strings.xml` | Encrypted third-party API keys |

## Conclusion

The API key retrieved from `libsecrets.so` serves as **an encryption key for protecting third-party service credentials**, not as a backend API key for Oura's health data services. It is used during app initialization to decrypt Segment and Braze API keys, which are then used for analytics tracking and user engagement throughout the app lifecycle. The actual Oura backend API authentication uses OAuth 2.0 with a separate `fallbackKey` for client identification.
