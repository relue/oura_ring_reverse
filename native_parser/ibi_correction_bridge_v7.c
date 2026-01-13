/*
 * ibi_correction_bridge_v7.c - WORKING solution using callback registration
 *
 * KEY DISCOVERY: ibi_correction_alloc_state() takes TWO parameters:
 *   - x0: callback function pointer  (stored at state[4296])
 *   - x1: callback context/user data (stored at state[4304])
 *
 * When corrected IBI data is ready, the library calls:
 *   callback(context, &ibi_data)
 *
 * The ibi_data structure at the callback is:
 *   offset 0: timestamp (uint64_t)
 *   offset 8: ibi (uint16_t)
 *   offset 10: amplitude (uint16_t)
 *   offset 12: validity (uint8_t)
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

// Callback data structure (based on disassembly analysis)
// The callback receives x1 = pointer to sp+8, where:
//   stp x3, xzr, [sp, #8]    -> timestamp at sp+8 (offset 0)
//   strh w0, [sp, #16]       -> ibi at sp+16 (offset 8)
//   strh w1, [sp, #18]       -> amplitude at sp+18 (offset 10)
//   strb w2, [sp, #20]       -> validity at sp+20 (offset 12)
typedef struct {
    uint64_t timestamp;      // offset 0 (from sp+8)
    uint16_t ibi;            // offset 8 (from sp+16)
    uint16_t amplitude;      // offset 10 (from sp+18)
    uint8_t validity;        // offset 12 (from sp+20)
    uint8_t padding[3];      // alignment
} ibi_callback_data_t;

/*
 * OUR CALLBACK FUNCTION
 * This gets registered with ibi_correction_alloc_state() and called
 * when corrected IBI data is available.
 *
 * Parameters (from disassembly):
 *   context: user data passed to alloc_state (we pass NULL or a struct)
 *   data: pointer to ibi_callback_data_t
 */
void our_ibi_callback(void* context, ibi_callback_data_t* data) {
    if (corrected_count < MAX_IBIS && data) {
        corrected_ts[corrected_count] = data->timestamp;
        corrected_ibi[corrected_count] = data->ibi;
        corrected_amp[corrected_count] = data->amplitude;
        corrected_validity[corrected_count] = data->validity;

        fprintf(stderr, "  [CALLBACK] ts=%lu ibi=%u amp=%u validity=%d\n",
                data->timestamp, data->ibi, data->amplitude, data->validity);

        corrected_count++;
    }
}

// Function signatures for libappecore.so
typedef void (*ibi_correction_init_t)(void);
typedef void* (*ibi_correction_alloc_state_t)(void* callback, void* context);
typedef void (*ibi_correction_free_state_t)(void* state);
typedef void (*ibi_correction_t)(void* state, uint16_t ibi, uint16_t amplitude, uint64_t timestamp);
typedef void (*ibi_correction_set_active_state_t)(void* state);

int main(int argc, char* argv[]) {
    fprintf(stderr, "IBI Correction Bridge v7 (Callback Registration)\n");
    fprintf(stderr, "=================================================\n");

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
    // Based on disassembly:
    //   ibi_correction_alloc_state_cpp saves x0→x21 (offset 4304), x1→x20 (offset 4296)
    //   process_corrected_ibi loads callback from 4296, context from 4304
    // So: alloc_state(context, callback)
    fprintf(stderr, "\nAllocating state with callback registration...\n");
    fprintf(stderr, "  Callback: %p\n", (void*)our_ibi_callback);
    void* state = ibi_alloc(NULL, (void*)our_ibi_callback);  // (context, callback)
    fprintf(stderr, "  State: %p\n", state);

    if (!state) {
        fprintf(stderr, "ERROR: Failed to allocate state\n");
        dlclose(handle);
        return 1;
    }

    // Set as active state (if function exists)
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

    // Process each IBI sample
    fprintf(stderr, "\nProcessing %d IBI samples...\n", count);
    for (int i = 0; i < count; i++) {
        if (i < 5 || i == count - 1) {
            fprintf(stderr, "  Input[%d]: ts=%lu ibi=%u amp=%u\n",
                    i, timestamps[i], ibis[i], amplitudes[i]);
        } else if (i == 5) {
            fprintf(stderr, "  ... (processing %d more samples)\n", count - 6);
        }
        ibi_correct(state, ibis[i], amplitudes[i], timestamps[i]);
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
