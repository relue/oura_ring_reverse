/*
 * ibi_correction_bridge_v9.c - CORRECTED calling convention
 *
 * KEY DISCOVERY from JNI disassembly (nativeIbiCorrection at c0680):
 *   The ibi_correction function signature is:
 *     void ibi_correction(uint16_t ibi, uint16_t amplitude, uint64_t timestamp)
 *
 *   NOT: void ibi_correction(void* state, uint16_t ibi, uint16_t amplitude, uint64_t timestamp)
 *
 *   The state is managed GLOBALLY inside the library.
 *
 * alloc_state(context, callback):
 *   - Allocates a state structure
 *   - Stores callback at offset 4296, context at offset 4304
 *   - Sets this as the global state
 *
 * When corrected IBI data is ready:
 *   callback(context, &ibi_data)
 *   where ibi_data has:
 *     - offset 0:  timestamp (uint64_t)
 *     - offset 8:  ibi (uint16_t)
 *     - offset 10: amplitude (uint16_t)
 *     - offset 12: validity (uint8_t)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

// Global storage for corrected IBI data
#define MAX_IBIS 100000
static uint16_t corrected_ibi[MAX_IBIS];
static uint16_t corrected_amp[MAX_IBIS];
static uint64_t corrected_ts[MAX_IBIS];
static uint8_t corrected_validity[MAX_IBIS];
static int corrected_count = 0;

// Callback data structure
typedef struct {
    uint64_t timestamp;      // offset 0
    uint16_t ibi;            // offset 8
    uint16_t amplitude;      // offset 10
    uint8_t validity;        // offset 12
    uint8_t padding[3];      // alignment
} ibi_callback_data_t;

/*
 * OUR CALLBACK FUNCTION
 * Called when corrected IBI data is available.
 */
void our_ibi_callback(void* context, ibi_callback_data_t* data) {
    if (corrected_count < MAX_IBIS && data) {
        corrected_ts[corrected_count] = data->timestamp;
        corrected_ibi[corrected_count] = data->ibi;
        corrected_amp[corrected_count] = data->amplitude;
        corrected_validity[corrected_count] = data->validity;

        if (corrected_count < 10) {
            fprintf(stderr, "  [CALLBACK %d] ts=%lu ibi=%u amp=%u validity=%d\n",
                    corrected_count, data->timestamp, data->ibi, data->amplitude, data->validity);
        }

        corrected_count++;
    }
}

// Function signatures for libappecore.so - CORRECTED
typedef void (*ibi_correction_init_t)(void);
typedef void* (*ibi_correction_alloc_state_t)(void* context, void* callback);  // (context, callback)
typedef void (*ibi_correction_free_state_t)(void* state);
// CORRECTED: No state parameter! Just (ibi, amplitude, timestamp)
typedef void (*ibi_correction_t)(uint16_t ibi, uint16_t amplitude, uint64_t timestamp);
typedef void (*ibi_correction_set_active_state_t)(void* state);

int main(int argc, char* argv[]) {
    fprintf(stderr, "IBI Correction Bridge v9 (Corrected Calling Convention)\n");
    fprintf(stderr, "========================================================\n");

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
    fprintf(stderr, "  Our callback function:      %p\n", (void*)our_ibi_callback);

    if (!ibi_init || !ibi_alloc || !ibi_correct) {
        fprintf(stderr, "ERROR: Required functions not found\n");
        dlclose(handle);
        return 1;
    }

    // Initialize
    fprintf(stderr, "\nInitializing IBI correction...\n");
    ibi_init();
    fprintf(stderr, "  Init done\n");

    // Allocate state WITH OUR CALLBACK
    // Based on disassembly: alloc_state(context, callback)
    fprintf(stderr, "\nAllocating state with callback registration...\n");
    fprintf(stderr, "  Callback: %p, Context: NULL\n", (void*)our_ibi_callback);
    void* state = ibi_alloc(NULL, (void*)our_ibi_callback);  // (context=NULL, callback)
    fprintf(stderr, "  State: %p\n", state);

    if (!state) {
        fprintf(stderr, "ERROR: Failed to allocate state\n");
        dlclose(handle);
        return 1;
    }

    // Set as active state (important - makes this the global state)
    if (ibi_set_state) {
        ibi_set_state(state);
        fprintf(stderr, "  Set as active state\n");
    }

    // Read IBI data from stdin
    fprintf(stderr, "\nReading IBI data from stdin...\n");
    fprintf(stderr, "Format: timestamp,ibi_ms,amplitude\n");

    uint64_t* timestamps = malloc(MAX_IBIS * sizeof(uint64_t));
    uint16_t* ibis = malloc(MAX_IBIS * sizeof(uint16_t));
    uint16_t* amplitudes = malloc(MAX_IBIS * sizeof(uint16_t));
    int count = 0;

    char line[256];
    while (fgets(line, sizeof(line), stdin) && count < MAX_IBIS) {
        uint64_t ts;
        int ibi, amp;
        if (sscanf(line, "%lu,%d,%d", &ts, &ibi, &amp) == 3) {
            timestamps[count] = ts;
            ibis[count] = (uint16_t)ibi;
            amplitudes[count] = (uint16_t)amp;
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

    // Process each IBI sample - CORRECTED: just (ibi, amplitude, timestamp)
    fprintf(stderr, "\nProcessing %d IBI samples...\n", count);
    for (int i = 0; i < count; i++) {
        if (i < 5 || i == count - 1) {
            fprintf(stderr, "  Input[%d]: ts=%lu ibi=%u amp=%u\n",
                    i, timestamps[i], ibis[i], amplitudes[i]);
        } else if (i == 5) {
            fprintf(stderr, "  ... (processing %d more samples)...\n", count - 6);
        }
        // CORRECTED: No state parameter!
        ibi_correct(ibis[i], amplitudes[i], timestamps[i]);
    }

    fprintf(stderr, "\nProcessing complete!\n");
    fprintf(stderr, "Received %d corrected samples via callback\n", corrected_count);

    // Output results
    printf("timestamp,ibi,amplitude,validity\n");
    if (corrected_count > 0) {
        for (int i = 0; i < corrected_count; i++) {
            printf("%lu,%u,%u,%u\n", corrected_ts[i], corrected_ibi[i],
                   corrected_amp[i], corrected_validity[i]);
        }
    } else {
        fprintf(stderr, "WARNING: No callbacks received - outputting original data\n");
        for (int i = 0; i < count; i++) {
            printf("%lu,%u,%u,0\n", timestamps[i], ibis[i], amplitudes[i]);
        }
    }

    // Cleanup
    free(timestamps); free(ibis); free(amplitudes);
    if (ibi_free) ibi_free(state);
    dlclose(handle);

    fprintf(stderr, "\nDone.\n");
    return 0;
}
