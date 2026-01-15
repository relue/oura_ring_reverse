/*
 * ibi_correction_bridge_v10.c - CORRECT JNI-matching parameter types
 *
 * JNI signature from EcoreWrapper.java:
 *   private final native void nativeIbiCorrection(int ibi, int amplitude, long timestamp);
 *
 * In JNI, Java int = jint = int32_t (32-bit signed)
 * Java long = jlong = int64_t (64-bit signed)
 *
 * The actual native function likely matches these types.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

// Global storage for corrected IBI data
#define MAX_IBIS 100000
static int32_t corrected_ibi[MAX_IBIS];
static int32_t corrected_amp[MAX_IBIS];
static int64_t corrected_ts[MAX_IBIS];
static int32_t corrected_validity[MAX_IBIS];
static int corrected_count = 0;

// Callback data structure - aligned with v9 but with proper types
typedef struct {
    int64_t timestamp;       // offset 0 (8 bytes)
    int32_t ibi;             // offset 8 (4 bytes) - JNI int
    int32_t amplitude;       // offset 12 (4 bytes) - JNI int
    int32_t validity;        // offset 16 (4 bytes)
    int32_t padding;         // alignment
} ibi_callback_data_t;

// Alternative struct for 16-bit values (original v9 guess)
typedef struct {
    uint64_t timestamp;      // offset 0
    uint16_t ibi;            // offset 8
    uint16_t amplitude;      // offset 10
    uint8_t validity;        // offset 12
    uint8_t padding[3];
} ibi_callback_data_v9_t;

static int callback_format = 0; // 0 = unknown, 1 = 32-bit, 2 = 16-bit

void our_ibi_callback(void* context, void* data) {
    if (corrected_count < MAX_IBIS && data) {
        // Try to detect format from first callback
        if (callback_format == 0) {
            // Examine raw bytes
            uint8_t* bytes = (uint8_t*)data;
            fprintf(stderr, "  [CALLBACK 0] Raw bytes: ");
            for (int i = 0; i < 20; i++) fprintf(stderr, "%02x ", bytes[i]);
            fprintf(stderr, "\n");

            // If bytes 8-9 look like IBI (300-2000) and bytes 10-11 look like amp, use 16-bit
            uint16_t ibi16 = *(uint16_t*)(bytes + 8);
            uint16_t amp16 = *(uint16_t*)(bytes + 10);
            int32_t ibi32 = *(int32_t*)(bytes + 8);
            int32_t amp32 = *(int32_t*)(bytes + 12);

            fprintf(stderr, "  As 16-bit: ibi=%u, amp=%u\n", ibi16, amp16);
            fprintf(stderr, "  As 32-bit: ibi=%d, amp=%d\n", ibi32, amp32);

            if (ibi16 >= 300 && ibi16 <= 2000 && amp16 < 65535) {
                callback_format = 2;  // 16-bit format
                fprintf(stderr, "  Detected 16-bit format\n");
            } else {
                callback_format = 1;  // 32-bit format
                fprintf(stderr, "  Detected 32-bit format\n");
            }
        }

        if (callback_format == 2) {
            // 16-bit format (v9 struct)
            ibi_callback_data_v9_t* d = (ibi_callback_data_v9_t*)data;
            corrected_ts[corrected_count] = d->timestamp;
            corrected_ibi[corrected_count] = d->ibi;
            corrected_amp[corrected_count] = d->amplitude;
            corrected_validity[corrected_count] = d->validity;
        } else {
            // 32-bit format
            ibi_callback_data_t* d = (ibi_callback_data_t*)data;
            corrected_ts[corrected_count] = d->timestamp;
            corrected_ibi[corrected_count] = d->ibi;
            corrected_amp[corrected_count] = d->amplitude;
            corrected_validity[corrected_count] = d->validity;
        }

        if (corrected_count < 10) {
            fprintf(stderr, "  [CALLBACK %d] ts=%ld ibi=%d amp=%d validity=%d\n",
                    corrected_count,
                    (long)corrected_ts[corrected_count],
                    corrected_ibi[corrected_count],
                    corrected_amp[corrected_count],
                    corrected_validity[corrected_count]);
        }

        corrected_count++;
    }
}

// Function signatures - use int32_t to match JNI int type
typedef void (*ibi_correction_init_t)(void);
typedef void* (*ibi_correction_alloc_state_t)(void* context, void* callback);
typedef void (*ibi_correction_free_state_t)(void* state);
typedef void (*ibi_correction_set_active_state_t)(void* state);

// CORRECTED: int32_t for ibi and amplitude to match JNI int
typedef void (*ibi_correction_t)(int32_t ibi, int32_t amplitude, int64_t timestamp);

int main(int argc, char* argv[]) {
    fprintf(stderr, "IBI Correction Bridge v10 (JNI-matching types)\n");
    fprintf(stderr, "================================================\n");

    // Load library
    fprintf(stderr, "\nLoading libappecore.so...\n");
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }
    fprintf(stderr, "  Loaded OK\n");

    // Get function pointers
    ibi_correction_init_t ibi_init = (ibi_correction_init_t)dlsym(handle, "ibi_correction_init");
    ibi_correction_alloc_state_t ibi_alloc = (ibi_correction_alloc_state_t)dlsym(handle, "ibi_correction_alloc_state");
    ibi_correction_free_state_t ibi_free = (ibi_correction_free_state_t)dlsym(handle, "ibi_correction_free_state");
    ibi_correction_t ibi_correct = (ibi_correction_t)dlsym(handle, "ibi_correction");
    ibi_correction_set_active_state_t ibi_set_state = (ibi_correction_set_active_state_t)dlsym(handle, "ibi_correction_set_active_state");

    fprintf(stderr, "\nFunction addresses:\n");
    fprintf(stderr, "  ibi_correction_init:        %p\n", (void*)ibi_init);
    fprintf(stderr, "  ibi_correction_alloc_state: %p\n", (void*)ibi_alloc);
    fprintf(stderr, "  ibi_correction:             %p\n", (void*)ibi_correct);
    fprintf(stderr, "  ibi_correction_free_state:  %p\n", (void*)ibi_free);

    if (!ibi_init || !ibi_alloc || !ibi_correct) {
        fprintf(stderr, "ERROR: Required functions not found\n");
        dlclose(handle);
        return 1;
    }

    // Initialize
    fprintf(stderr, "\nInitializing IBI correction...\n");
    ibi_init();
    fprintf(stderr, "  Init done\n");

    // Allocate state with callback
    fprintf(stderr, "\nAllocating state with callback...\n");
    void* state = ibi_alloc(NULL, (void*)our_ibi_callback);
    fprintf(stderr, "  State: %p\n", state);

    if (!state) {
        fprintf(stderr, "ERROR: Failed to allocate state\n");
        dlclose(handle);
        return 1;
    }

    // Set as active state
    if (ibi_set_state) {
        ibi_set_state(state);
        fprintf(stderr, "  Set as active state\n");
    }

    // Read IBI data from stdin
    fprintf(stderr, "\nReading IBI data from stdin...\n");

    int64_t* timestamps = malloc(MAX_IBIS * sizeof(int64_t));
    int32_t* ibis = malloc(MAX_IBIS * sizeof(int32_t));
    int32_t* amplitudes = malloc(MAX_IBIS * sizeof(int32_t));
    int count = 0;

    char line[256];
    while (fgets(line, sizeof(line), stdin) && count < MAX_IBIS) {
        long long ts;
        int ibi, amp;
        if (sscanf(line, "%lld,%d,%d", &ts, &ibi, &amp) == 3) {
            timestamps[count] = (int64_t)ts;
            ibis[count] = (int32_t)ibi;
            amplitudes[count] = (int32_t)amp;
            count++;
        }
    }

    fprintf(stderr, "Read %d IBI samples\n", count);

    if (count == 0) {
        fprintf(stderr, "No data to process\n");
        free(timestamps); free(ibis); free(amplitudes);
        if (ibi_free) ibi_free(state);
        dlclose(handle);
        return 1;
    }

    // Reset callback counter
    corrected_count = 0;

    // Process each IBI sample
    fprintf(stderr, "\nProcessing %d IBI samples...\n", count);
    for (int i = 0; i < count; i++) {
        if (i < 5 || i == count - 1) {
            fprintf(stderr, "  Input[%d]: ts=%ld ibi=%d amp=%d\n",
                    i, (long)timestamps[i], ibis[i], amplitudes[i]);
        } else if (i == 5) {
            fprintf(stderr, "  ... (processing %d more samples)...\n", count - 6);
        }
        // Call with int32_t types
        ibi_correct(ibis[i], amplitudes[i], timestamps[i]);
    }

    fprintf(stderr, "\nProcessing complete!\n");
    fprintf(stderr, "Received %d corrected samples via callback\n", corrected_count);

    // Output results
    printf("timestamp,ibi,amplitude,validity\n");
    if (corrected_count > 0) {
        for (int i = 0; i < corrected_count; i++) {
            printf("%ld,%d,%d,%d\n",
                   (long)corrected_ts[i],
                   corrected_ibi[i],
                   corrected_amp[i],
                   corrected_validity[i]);
        }
    } else {
        fprintf(stderr, "WARNING: No callbacks received - outputting original data\n");
        for (int i = 0; i < count; i++) {
            printf("%ld,%d,%d,0\n", (long)timestamps[i], ibis[i], amplitudes[i]);
        }
    }

    // Cleanup
    free(timestamps); free(ibis); free(amplitudes);
    if (ibi_free) ibi_free(state);
    dlclose(handle);

    fprintf(stderr, "\nDone.\n");
    return 0;
}
