#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <cstring>
#include <cstdlib>
#include <string>

#define LOG_TAG "RingEventParserJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// Function pointer types for C++ methods (based on nm -D output)
// Constructor: _ZN15RingEventParserC1Ev
typedef void* (*RingEventParser_ctor)(void* this_ptr);

// parse_events: _ZN15RingEventParser12parse_eventsEPKhjPj
// Signature: RingEventParser::parse_events(const unsigned char*, unsigned int, unsigned int*)
typedef void* (*RingEventParser_parse_events)(void* this_ptr, const unsigned char* data, unsigned int len, unsigned int* events_received);

// Protobuf MessageLite interface
// From protobuf/message_lite.h
// We only need SerializeToString which has a stable mangled name across versions
namespace google {
namespace protobuf {
class MessageLite {
public:
    virtual ~MessageLite() = default;
    virtual bool SerializeToString(std::string* output) const = 0;
};
} // namespace protobuf
} // namespace google

/**
 * JNI bridge for Oura's native RingEventParser
 *
 * This function is called from Kotlin as:
 *   Java_com_example_reverseoura_RingEventParser_nativeParseEvents
 *
 * It uses dlsym to call the C++ methods from libringeventparser.so
 */
extern "C" JNIEXPORT jobject JNICALL
Java_com_example_reverseoura_RingEventParser_nativeParseEvents(
    JNIEnv* env,
    jobject thiz,
    jbyteArray events,
    jint ringTime,
    jlong utcTime,
    jboolean debugMode) {

    LOGI("=== JNI Bridge Called ===");
    LOGD("  Ring time: %d", ringTime);
    LOGD("  UTC time: %lld", (long long)utcTime);
    LOGD("  Debug mode: %d", debugMode);

    // Step 1: Load libringeventparser.so
    LOGI("Loading libringeventparser.so...");
    void* handle = dlopen("libringeventparser.so", RTLD_LAZY);
    if (!handle) {
        LOGE("Failed to dlopen libringeventparser.so: %s", dlerror());
        return nullptr;
    }
    LOGI("✓ Library loaded successfully");

    // Step 2: Get function pointers to C++ methods using mangled names
    LOGI("Looking up C++ methods...");

    // Constructor: RingEventParser::RingEventParser()
    auto ctor = (RingEventParser_ctor)dlsym(handle, "_ZN15RingEventParserC1Ev");
    if (!ctor) {
        LOGE("Failed to find constructor: %s", dlerror());
        dlclose(handle);
        return nullptr;
    }
    LOGD("✓ Found constructor");

    // parse_events method
    auto parse = (RingEventParser_parse_events)dlsym(handle, "_ZN15RingEventParser12parse_eventsEPKhjPj");
    if (!parse) {
        LOGE("Failed to find parse_events: %s", dlerror());
        dlclose(handle);
        return nullptr;
    }
    LOGD("✓ Found parse_events");

    // Step 3: Create RingEventParser instance
    // C++ objects need memory allocated for the 'this' pointer
    // We allocate 1024 bytes to be safe (actual object size likely smaller)
    void* parser = malloc(1024);
    if (!parser) {
        LOGE("Failed to allocate memory for parser object");
        dlclose(handle);
        return nullptr;
    }
    memset(parser, 0, 1024);

    LOGI("Creating RingEventParser instance...");
    ctor(parser);  // Call constructor on allocated memory
    LOGI("✓ RingEventParser created");

    // Step 4: Convert Java byte array to native bytes
    jsize len = env->GetArrayLength(events);
    jbyte* bytes = env->GetByteArrayElements(events, nullptr);

    LOGI("Calling parse_events with %d bytes...", len);
    LOGD("  First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
         (unsigned char)bytes[0], (unsigned char)bytes[1], (unsigned char)bytes[2], (unsigned char)bytes[3],
         (unsigned char)bytes[4], (unsigned char)bytes[5], (unsigned char)bytes[6], (unsigned char)bytes[7],
         (unsigned char)bytes[8], (unsigned char)bytes[9], (unsigned char)bytes[10], (unsigned char)bytes[11],
         (unsigned char)bytes[12], (unsigned char)bytes[13], (unsigned char)bytes[14], (unsigned char)bytes[15]);

    // Step 5: Call parse_events
    unsigned int eventsReceived = 0;
    void* result = parse(parser, (const unsigned char*)bytes, (unsigned int)len, &eventsReceived);

    LOGI("✓ parse_events returned");
    LOGI("  Events received: %u", eventsReceived);
    LOGI("  Result pointer: %p", result);

    // Release Java array
    env->ReleaseByteArrayElements(events, bytes, JNI_ABORT);

    // Step 6: Return raw result object bytes
    LOGI("=== ANALYZING C++ RESULT OBJECT ===");

    if (result == nullptr) {
        LOGI("Parse result is null - creating null return");
        free(parser);
        dlclose(handle);
        return nullptr;
    }

    LOGI("Result pointer: %p", result);
    LOGI("Events received: %u", eventsReceived);

    // The result is a C++ object - we'll return the raw bytes
    // so it can be analyzed with Frida or other tools
    unsigned char* resultBytes = (unsigned char*)result;

    LOGI("First 64 bytes of result object:");
    for (int i = 0; i < 64; i += 16) {
        LOGI("  [%02d-%02d]: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x",
            i, i+15,
            resultBytes[i], resultBytes[i+1], resultBytes[i+2], resultBytes[i+3],
            resultBytes[i+4], resultBytes[i+5], resultBytes[i+6], resultBytes[i+7],
            resultBytes[i+8], resultBytes[i+9], resultBytes[i+10], resultBytes[i+11],
            resultBytes[i+12], resultBytes[i+13], resultBytes[i+14], resultBytes[i+15]);
    }

    // Create HashMap with result data
    jclass hashMapClass = env->FindClass("java/util/HashMap");
    if (!hashMapClass) {
        LOGE("Failed to find HashMap class");
        free(parser);
        dlclose(handle);
        return nullptr;
    }

    jmethodID hashMapInit = env->GetMethodID(hashMapClass, "<init>", "()V");
    jmethodID hashMapPut = env->GetMethodID(hashMapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    jobject resultMap = env->NewObject(hashMapClass, hashMapInit);

    // Add metadata
    jclass integerClass = env->FindClass("java/lang/Integer");
    jmethodID integerInit = env->GetMethodID(integerClass, "<init>", "(I)V");

    // Events received
    jstring keyEventsReceived = env->NewStringUTF("eventsReceived");
    jobject valueEventsReceived = env->NewObject(integerClass, integerInit, eventsReceived);
    env->CallObjectMethod(resultMap, hashMapPut, keyEventsReceived, valueEventsReceived);

    // Result pointer as string
    jstring keyResultPtr = env->NewStringUTF("resultPointer");
    char ptrStr[32];
    snprintf(ptrStr, sizeof(ptrStr), "%p", result);
    jstring valueResultPtr = env->NewStringUTF(ptrStr);
    env->CallObjectMethod(resultMap, hashMapPut, keyResultPtr, valueResultPtr);

    // Add raw result object bytes (first 512 bytes)
    jstring keyResultBytes = env->NewStringUTF("resultObjectBytes");
    jbyteArray resultBytesArray = env->NewByteArray(512);
    env->SetByteArrayRegion(resultBytesArray, 0, 512, (jbyte*)resultBytes);
    env->CallObjectMethod(resultMap, hashMapPut, keyResultBytes, resultBytesArray);

    LOGI("=== JNI Bridge Completed Successfully ===");

    // Cleanup
    free(parser);
    dlclose(handle);

    return resultMap;
}

/**
 * Call EventParser::parse_api_sleep_period_info directly
 * Mangled name: _ZN11EventParser27parse_api_sleep_period_infoERK5Event
 */
extern "C" JNIEXPORT jfloatArray JNICALL
Java_com_example_reverseoura_RingEventParser_nativeParseSleepPeriodInfo(
    JNIEnv* env,
    jobject thiz,
    jbyteArray eventBytes) {

    LOGI("=== Calling parse_api_sleep_period_info ===");

    // Load library
    void* handle = dlopen("libringeventparser.so", RTLD_LAZY);
    if (!handle) {
        LOGE("Failed to dlopen: %s", dlerror());
        return nullptr;
    }

    // Get the function pointer
    // void EventParser::parse_api_sleep_period_info(Event const&)
    // Returns parsed data in a structure (array of 9 floats based on decompiled code)
    typedef void (*parse_func_t)(void* parser, const void* event, float* output);

    auto parse_sleep = (parse_func_t)dlsym(handle, "_ZN11EventParser27parse_api_sleep_period_infoERK5Event");
    if (!parse_sleep) {
        LOGE("Failed to find parse_api_sleep_period_info: %s", dlerror());
        dlclose(handle);
        return nullptr;
    }
    LOGI("✓ Found parse_api_sleep_period_info");

    // Get event data
    jsize len = env->GetArrayLength(eventBytes);
    jbyte* bytes = env->GetByteArrayElements(eventBytes, nullptr);

    LOGI("Event data: %d bytes", len);
    LOGD("  Hex: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
         (unsigned char)bytes[0], (unsigned char)bytes[1], (unsigned char)bytes[2], (unsigned char)bytes[3],
         (unsigned char)bytes[4], (unsigned char)bytes[5], (unsigned char)bytes[6], (unsigned char)bytes[7],
         (unsigned char)bytes[8], (unsigned char)bytes[9], (unsigned char)bytes[10], (unsigned char)bytes[11],
         (unsigned char)bytes[12], (unsigned char)bytes[13], (unsigned char)bytes[14], (unsigned char)bytes[15]);

    // The Event structure - based on decompiled code:
    // lVar9 = *(long *)param_11;  // Dereference Event* to get data pointer
    // bVar1 = *(byte *)(lVar9 + 0xc);  // Access byte at offset 0xc in data
    //
    // So Event is a struct containing a pointer to the actual data:
    // struct Event {
    //     unsigned char* data;
    // };
    struct Event {
        unsigned char* data;
    };
    Event event;
    event.data = (unsigned char*)bytes;

    // Output array for parsed data (9 floats based on decompiled code)
    float output[9] = {0};

    // Create EventParser instance
    void* parser = malloc(1024);
    memset(parser, 0, 1024);

    // Call parse function
    LOGI("Calling parse_api_sleep_period_info...");
    parse_sleep(parser, &event, output);
    LOGI("✓ Parsing completed");

    // Log results
    LOGI("Parsed values:");
    for (int i = 0; i < 9; i++) {
        LOGI("  [%d] = %.3f", i, output[i]);
    }

    // Create float array to return
    jfloatArray result = env->NewFloatArray(9);
    env->SetFloatArrayRegion(result, 0, 9, output);

    // Cleanup
    env->ReleaseByteArrayElements(eventBytes, bytes, JNI_ABORT);
    free(parser);
    dlclose(handle);

    return result;
}
