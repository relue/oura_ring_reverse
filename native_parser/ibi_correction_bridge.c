/*
 * ibi_correction_bridge.c - Bridge to call Oura's libappecore.so IBI correction
 *
 * KEY INSIGHT: The library calls process_corrected_ibi() internally.
 * By defining this symbol with the exact mangled name in our executable,
 * the dynamic linker will resolve calls to OUR implementation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

// Validity indicator enum
typedef enum {
    RR_VALID = 0,
    RR_INVALID = 1,
    RR_INTERPOLATED = 2,
} rr_validity_indicator_t;

// Global storage for corrected IBI data
#define MAX_IBIS 100000
static uint16_t corrected_ibi[MAX_IBIS];
static uint16_t corrected_amp[MAX_IBIS];
static uint64_t corrected_ts[MAX_IBIS];
static uint8_t corrected_validity[MAX_IBIS];
static int corrected_count = 0;

/*
 * THIS IS THE KEY: Define process_corrected_ibi with the exact C++ mangled name.
 * When libappecore.so calls this function, it will resolve to OUR implementation.
 *
 * C++ signature: void process_corrected_ibi(unsigned short, unsigned short, rr_validity_indicator_t, unsigned long)
 * Mangled name: _Z21process_corrected_ibitt23rr_validity_indicator_tm
 */
void _Z21process_corrected_ibitt23rr_validity_indicator_tm(
    uint16_t ibi,
    uint16_t amplitude,
    rr_validity_indicator_t validity,
    uint64_t timestamp
) {
    if (corrected_count < MAX_IBIS) {
        corrected_ibi[corrected_count] = ibi;
        corrected_amp[corrected_count] = amplitude;
        corrected_validity[corrected_count] = (uint8_t)validity;
        corrected_ts[corrected_count] = timestamp;

        fprintf(stderr, "  [CALLBACK] ts=%lu ibi=%u amp=%u validity=%d\n",
                timestamp, ibi, amplitude, (int)validity);

        corrected_count++;
    }
}

// Also provide the amplitude variant
void _Z35process_corrected_ibi_and_amplitudett23rr_validity_indicator_tm(
    uint16_t ibi,
    uint16_t amplitude,
    rr_validity_indicator_t validity,
    uint64_t timestamp
) {
    _Z21process_corrected_ibitt23rr_validity_indicator_tm(ibi, amplitude, validity, timestamp);
}

// Function signatures for libappecore.so
typedef void (*ibi_correction_init_t)(void);
typedef void* (*ibi_correction_alloc_state_t)(void);
typedef void (*ibi_correction_free_state_t)(void* state);
typedef void (*ibi_correction_t)(void* state, uint16_t ibi, uint16_t amplitude, uint64_t timestamp);
typedef void (*ibi_correction_set_active_state_t)(void* state);

int main(int argc, char* argv[]) {
    fprintf(stderr, "IBI Correction Bridge v6 (Symbol Interposition)\n");
    fprintf(stderr, "================================================\n");

    // Verify our callback symbol is visible
    void* self = dlopen(NULL, RTLD_NOW);
    void* our_callback = dlsym(self, "_Z21process_corrected_ibitt23rr_validity_indicator_tm");
    fprintf(stderr, "Our process_corrected_ibi: %p\n", our_callback);

    // Load library - our symbol should take precedence for internal calls
    fprintf(stderr, "\nLoading libappecore.so...\n");
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }
    fprintf(stderr, "  Loaded OK\n");

    // Check which process_corrected_ibi is resolved
    void* lib_callback = dlsym(handle, "_Z21process_corrected_ibitt23rr_validity_indicator_tm");
    fprintf(stderr, "Library's process_corrected_ibi: %p\n", lib_callback);

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

    if (!ibi_init || !ibi_correct) {
        fprintf(stderr, "ERROR: Required functions not found\n");
        dlclose(handle);
        return 1;
    }

    // Initialize
    fprintf(stderr, "\nInitializing IBI correction...\n");
    ibi_init();
    fprintf(stderr, "  Init done\n");

    // Allocate and set state
    void* state = NULL;
    if (ibi_alloc) {
        state = ibi_alloc();
        fprintf(stderr, "  State: %p\n", state);
    }
    if (state && ibi_set_state) {
        ibi_set_state(state);
    }

    // Read IBI data from stdin
    fprintf(stderr, "\nReading IBI data from stdin...\n");

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
        if (state && ibi_free) ibi_free(state);
        dlclose(handle);
        return 1;
    }

    // Reset callback counter
    corrected_count = 0;

    // Process each IBI sample
    fprintf(stderr, "\nProcessing %d IBI samples...\n", count);
    for (int i = 0; i < count; i++) {
        if (i < 3) {
            fprintf(stderr, "  Input[%d]: ts=%lu ibi=%u amp=%u\n",
                    i, timestamps[i], ibis[i], amplitudes[i]);
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
    if (state && ibi_free) ibi_free(state);
    dlclose(handle);

    fprintf(stderr, "\nDone.\n");
    return 0;
}
