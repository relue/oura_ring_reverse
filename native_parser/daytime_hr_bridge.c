/*
 * daytime_hr_bridge.c - Daytime Heart Rate Processing via libappecore.so
 *
 * Following the pattern from ibi_correction_bridge_v9.c
 *
 * Daytime HR API Pattern:
 *   1. daytime_hr_init()                    - Initialize subsystem
 *   2. daytime_hr_set_handler(callback)     - Register output callback
 *   3. daytime_hr_process_event(...)        - Process each HR event
 *   4. daytime_hr_common_flush()            - Flush and trigger callbacks
 *   5. daytime_hr_get_corrected_ibi_count() - Get number of results
 *   6. daytime_hr_get_corrected_ibi()       - Get buffer pointer
 *
 * Input format (CSV from stdin):
 *   timestamp_ms,ibi_ms,amplitude
 *
 * Output format (CSV to stdout):
 *   timestamp_ms,ibi_ms,hr_bpm,quality
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

#define MAX_EVENTS 100000

// Output structure from daytime HR processing
// Format: packed IBI event data
typedef struct {
    uint64_t timestamp;        // offset 0
    uint16_t ibi;              // offset 8
    uint16_t amplitude;        // offset 10
    uint8_t validity;          // offset 12
    uint8_t padding[3];        // alignment to 16 bytes
} __attribute__((packed)) corrected_ibi_event_t;

// Alternative packed structure (12 bytes)
typedef struct {
    uint64_t timestamp;
    uint16_t ibi;
    uint8_t validity;
    uint8_t quality;
} __attribute__((packed)) corrected_ibi_event_12_t;

// Global storage for results received via callback
static corrected_ibi_event_t callback_results[MAX_EVENTS];
static int callback_count = 0;

/*
 * OUR CALLBACK FUNCTION
 * Called when processed HR data is available.
 */
void our_hr_callback(void* context, void* output_ptr) {
    fprintf(stderr, "[HR_CALLBACK] Called! context=%p output=%p\n", context, output_ptr);

    if (output_ptr) {
        // Dump raw bytes to understand structure
        uint8_t* bytes = (uint8_t*)output_ptr;
        fprintf(stderr, "  Raw bytes: ");
        for (int i = 0; i < 24; i++) {
            fprintf(stderr, "%02x ", bytes[i]);
        }
        fprintf(stderr, "\n");

        // Try to interpret
        uint64_t* ts_ptr = (uint64_t*)output_ptr;
        fprintf(stderr, "  As uint64 @0: %lu\n", *ts_ptr);

        if (callback_count < MAX_EVENTS) {
            memcpy(&callback_results[callback_count], output_ptr, sizeof(corrected_ibi_event_t));
            callback_count++;
        }
    }
}

// Function typedefs for libappecore.so daytime HR functions
typedef void (*daytime_hr_init_t)(void);
typedef void (*daytime_hr_set_handler_t)(void* callback);
typedef void (*daytime_hr_process_event_t)(uint64_t timestamp, uint16_t ibi, uint16_t amplitude);
typedef int (*daytime_hr_get_corrected_ibi_count_t)(void);
typedef void* (*daytime_hr_get_corrected_ibi_t)(void);  // Returns buffer pointer
typedef void (*daytime_hr_common_flush_t)(void);
typedef int (*daytime_hr_get_buffer_size_t)(void);

int main(int argc, char* argv[]) {
    fprintf(stderr, "Daytime HR Bridge v2 (with flush and getter analysis)\n");
    fprintf(stderr, "=====================================================\n");

    // Load library
    fprintf(stderr, "\nLoading libappecore.so...\n");
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }
    fprintf(stderr, "  Loaded OK\n");

    // Get function pointers
    daytime_hr_init_t hr_init = (daytime_hr_init_t)dlsym(handle, "daytime_hr_init");
    daytime_hr_set_handler_t hr_set_handler = (daytime_hr_set_handler_t)dlsym(handle, "daytime_hr_set_handler");
    daytime_hr_process_event_t hr_process = (daytime_hr_process_event_t)dlsym(handle, "daytime_hr_process_event");
    daytime_hr_get_corrected_ibi_count_t hr_get_count = (daytime_hr_get_corrected_ibi_count_t)dlsym(handle, "daytime_hr_get_corrected_ibi_count");
    daytime_hr_get_corrected_ibi_t hr_get_ibi = (daytime_hr_get_corrected_ibi_t)dlsym(handle, "daytime_hr_get_corrected_ibi");
    daytime_hr_common_flush_t hr_flush = (daytime_hr_common_flush_t)dlsym(handle, "daytime_hr_common_flush");
    daytime_hr_get_buffer_size_t hr_get_buffer_size = (daytime_hr_get_buffer_size_t)dlsym(handle, "daytime_hr_get_buffer_size");

    fprintf(stderr, "\nFunction addresses:\n");
    fprintf(stderr, "  daytime_hr_init:              %p\n", (void*)hr_init);
    fprintf(stderr, "  daytime_hr_set_handler:       %p\n", (void*)hr_set_handler);
    fprintf(stderr, "  daytime_hr_process_event:     %p\n", (void*)hr_process);
    fprintf(stderr, "  daytime_hr_get_corrected_ibi_count: %p\n", (void*)hr_get_count);
    fprintf(stderr, "  daytime_hr_get_corrected_ibi: %p\n", (void*)hr_get_ibi);
    fprintf(stderr, "  daytime_hr_common_flush:      %p\n", (void*)hr_flush);
    fprintf(stderr, "  daytime_hr_get_buffer_size:   %p\n", (void*)hr_get_buffer_size);

    if (!hr_init || !hr_process) {
        fprintf(stderr, "ERROR: Required functions not found\n");
        dlclose(handle);
        return 1;
    }

    // Initialize
    fprintf(stderr, "\nInitializing daytime HR processing...\n");
    hr_init();
    fprintf(stderr, "  Init done\n");

    // Set our callback handler
    if (hr_set_handler) {
        fprintf(stderr, "\nSetting HR output handler...\n");
        hr_set_handler((void*)our_hr_callback);
        fprintf(stderr, "  Handler set to: %p\n", (void*)our_hr_callback);
    }

    // Read HR data from stdin
    fprintf(stderr, "\nReading HR data from stdin...\n");
    fprintf(stderr, "Format: timestamp_ms,ibi_ms,amplitude\n");

    uint64_t* timestamps = malloc(MAX_EVENTS * sizeof(uint64_t));
    uint16_t* ibis = malloc(MAX_EVENTS * sizeof(uint16_t));
    uint16_t* amplitudes = malloc(MAX_EVENTS * sizeof(uint16_t));
    int count = 0;

    char line[256];
    while (fgets(line, sizeof(line), stdin) && count < MAX_EVENTS) {
        // Skip header line
        if (strncmp(line, "timestamp", 9) == 0) continue;

        uint64_t ts;
        int ibi, amp;
        if (sscanf(line, "%lu,%d,%d", &ts, &ibi, &amp) == 3) {
            timestamps[count] = ts;
            ibis[count] = (uint16_t)ibi;
            amplitudes[count] = (uint16_t)amp;
            count++;
        }
    }

    fprintf(stderr, "Read %d HR samples\n", count);

    if (count == 0) {
        fprintf(stderr, "No data to process\n");
        free(timestamps); free(ibis); free(amplitudes);
        dlclose(handle);
        return 1;
    }

    // Reset callback counter
    callback_count = 0;

    // Process each HR event
    fprintf(stderr, "\nProcessing %d HR events...\n", count);
    for (int i = 0; i < count; i++) {
        if (i < 5 || i == count - 1) {
            fprintf(stderr, "  Input[%d]: ts=%lu ibi=%u amp=%u\n",
                    i, timestamps[i], ibis[i], amplitudes[i]);
        } else if (i == 5) {
            fprintf(stderr, "  ... (processing %d more events)...\n", count - 6);
        }
        hr_process(timestamps[i], ibis[i], amplitudes[i]);
    }

    // Skip flush for now - it crashes without proper state
    // if (hr_flush) {
    //     fprintf(stderr, "\nCalling daytime_hr_common_flush()...\n");
    //     hr_flush();
    // }

    fprintf(stderr, "\nProcessing complete!\n");
    fprintf(stderr, "Received %d results via callback\n", callback_count);

    // Get buffer info
    if (hr_get_buffer_size) {
        int buf_size = hr_get_buffer_size();
        fprintf(stderr, "Buffer size: %d\n", buf_size);
    }

    // Get results via getter
    int getter_count = 0;
    if (hr_get_count) {
        getter_count = hr_get_count();
        fprintf(stderr, "Results from getter count: %d\n", getter_count);
    }

    // Skip getter for now - crashes without proper state/signature
    // The daytime_hr_get_corrected_ibi function likely needs state parameter
    void* buffer = NULL;
    fprintf(stderr, "Getter API skipped (needs further investigation)\n");

    // Output results
    printf("timestamp,ibi,hr_bpm,quality\n");

    if (callback_count > 0) {
        // Use callback results
        fprintf(stderr, "\nUsing callback results\n");
        for (int i = 0; i < callback_count; i++) {
            uint16_t hr_bpm = (callback_results[i].ibi > 0) ?
                              (uint16_t)(60000 / callback_results[i].ibi) : 0;
            printf("%lu,%u,%u,%u\n",
                   callback_results[i].timestamp, callback_results[i].ibi,
                   hr_bpm, callback_results[i].validity);
        }
    } else if (buffer && getter_count > 0) {
        // Try using getter buffer (16-byte structure)
        fprintf(stderr, "\nUsing getter buffer (16-byte events)\n");
        corrected_ibi_event_t* events = (corrected_ibi_event_t*)buffer;
        for (int i = 0; i < getter_count; i++) {
            uint16_t hr_bpm = (events[i].ibi > 0) ?
                              (uint16_t)(60000 / events[i].ibi) : 0;
            printf("%lu,%u,%u,%u\n",
                   events[i].timestamp, events[i].ibi,
                   hr_bpm, events[i].validity);
        }
    } else {
        // Fallback: output original data with HR calculated from IBI
        fprintf(stderr, "\nFallback: using original data with calculated HR\n");
        for (int i = 0; i < count; i++) {
            uint16_t hr_bpm = (ibis[i] > 0) ? (uint16_t)(60000 / ibis[i]) : 0;
            printf("%lu,%u,%u,0\n", timestamps[i], ibis[i], hr_bpm);
        }
    }

    // Cleanup
    free(timestamps); free(ibis); free(amplitudes);
    dlclose(handle);

    fprintf(stderr, "\nDone.\n");
    return 0;
}
