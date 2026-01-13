/*
 * ibi_correction_bridge_v8.c - Debug version to understand callback data layout
 *
 * Based on disassembly analysis of process_corrected_ibi:
 *   16ed58: stp x3, xzr, [sp, #8]    -> timestamp at sp+8
 *   16ed5c: strh w0, [sp, #16]       -> ibi at sp+16
 *   16ed64: strh w1, [sp, #18]       -> amplitude at sp+18
 *   16ed6c: strb w2, [sp, #20]       -> validity at sp+20
 *   16ed70: blr x9                   -> callback(context, sp+8)
 *
 * So data structure should be:
 *   offset 0:  timestamp (uint64_t)
 *   offset 8:  ibi (uint16_t)
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

/*
 * DEBUG CALLBACK - prints raw bytes to understand actual layout
 */
void our_ibi_callback(void* context, void* data) {
    if (corrected_count >= MAX_IBIS || !data) return;

    uint8_t* bytes = (uint8_t*)data;

    // Print first 24 raw bytes
    fprintf(stderr, "  [RAW %d] ", corrected_count);
    for (int i = 0; i < 24; i++) {
        fprintf(stderr, "%02x ", bytes[i]);
        if (i == 7 || i == 9 || i == 11 || i == 12) fprintf(stderr, "| ");
    }
    fprintf(stderr, "\n");

    // Try different interpretations
    uint64_t* ts_ptr = (uint64_t*)data;
    uint16_t* ibi_ptr = (uint16_t*)(bytes + 8);
    uint16_t* amp_ptr = (uint16_t*)(bytes + 10);
    uint8_t* val_ptr = (uint8_t*)(bytes + 12);

    fprintf(stderr, "        ts(off0)=%lu ibi(off8)=%u amp(off10)=%u val(off12)=%u\n",
            *ts_ptr, *ibi_ptr, *amp_ptr, *val_ptr);

    // Also try if callback receives registers directly (x0=context, x1=ibi, x2=amp, x3=validity, x4=ts)
    // In that case 'data' would actually be 'ibi' as uint64_t
    fprintf(stderr, "        alt: data_as_int=%lu ctx=%p\n", (uint64_t)(uintptr_t)data, context);

    // Store using standard interpretation
    corrected_ts[corrected_count] = *ts_ptr;
    corrected_ibi[corrected_count] = *ibi_ptr;
    corrected_amp[corrected_count] = *amp_ptr;
    corrected_validity[corrected_count] = *val_ptr;

    corrected_count++;
}

/*
 * Alternative callback - try different signature
 * Maybe: callback(ibi, amplitude, validity, timestamp)
 */
void our_ibi_callback_alt(uint16_t ibi, uint16_t amplitude, uint32_t validity, uint64_t timestamp) {
    if (corrected_count >= MAX_IBIS) return;

    fprintf(stderr, "  [ALT %d] ibi=%u amp=%u val=%u ts=%lu\n",
            corrected_count, ibi, amplitude, validity, timestamp);

    corrected_ts[corrected_count] = timestamp;
    corrected_ibi[corrected_count] = ibi;
    corrected_amp[corrected_count] = amplitude;
    corrected_validity[corrected_count] = (uint8_t)validity;

    corrected_count++;
}

// Function signatures for libappecore.so
typedef void (*ibi_correction_init_t)(void);
typedef void* (*ibi_correction_alloc_state_t)(void* callback, void* context);
typedef void (*ibi_correction_free_state_t)(void* state);
typedef void (*ibi_correction_t)(void* state, uint16_t ibi, uint16_t amplitude, uint64_t timestamp);
typedef void (*ibi_correction_set_active_state_t)(void* state);

int main(int argc, char* argv[]) {
    int use_alt = 0;
    if (argc > 1 && strcmp(argv[1], "-alt") == 0) {
        use_alt = 1;
        fprintf(stderr, "Using ALTERNATIVE callback signature\n");
    }

    fprintf(stderr, "IBI Correction Bridge v8 (Debug Raw Bytes)\n");
    fprintf(stderr, "==========================================\n");

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

    // Allocate state WITH OUR CALLBACK
    // Based on disassembly: alloc_state(context, callback)
    // - x0 (first param) stored at offset 4304 (context)
    // - x1 (second param) stored at offset 4296 (callback)
    void* callback = use_alt ? (void*)our_ibi_callback_alt : (void*)our_ibi_callback;
    fprintf(stderr, "\nAllocating state with callback: %p\n", callback);
    void* state = ibi_alloc(NULL, callback);  // (context=NULL, callback)
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
            fprintf(stderr, "  ... (processing %d more samples quietly)\n", count - 6);
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
