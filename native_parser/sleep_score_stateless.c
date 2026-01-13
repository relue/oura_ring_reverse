/*
 * sleep_score_stateless.c - Direct stateless call to sleep score calculation
 *
 * NO ecore_init() needed - calls the pure calculation function directly.
 *
 * Function signatures (from mangled C++ names):
 *
 * ecore_sleep_score_calculate_minutes(s_sleep_summary_4_t*, t, t, t, h, h, h, t, h, s, h, i)
 *   - P19s_sleep_summary_4_t* output
 *   - t = uint16 total_min
 *   - t = uint16 deep_min
 *   - t = uint16 rem_min
 *   - h = uint8 efficiency
 *   - h = uint8 latency_min
 *   - h = uint8 wakeup_count
 *   - t = uint16 awake_sec
 *   - h = uint8 restless
 *   - s = int16 temp_dev
 *   - h = uint8 unknown
 *   - i = int day_offset
 *
 * ecore_sleep_score_calculate(s_sleep_summary_4_t*, t, t, t, t, h, h, t, h, s, h, i)
 *   - P19s_sleep_summary_4_t* output
 *   - t = uint16 total_sec
 *   - t = uint16 deep_sec
 *   - t = uint16 rem_sec
 *   - t = uint16 awake_sec
 *   - h = uint8 efficiency
 *   - h = uint8 wakeup_count
 *   - t = uint16 latency_sec
 *   - h = uint8 restless
 *   - s = int16 temp_dev
 *   - h = uint8 unknown
 *   - i = int day_offset
 *
 * Input format (CSV from stdin):
 *   totalSleepSec,deepSec,remSec,efficiency,latencySec,wakeUpCount,awakeSec,restless,tempDev
 *
 * Output format (CSV to stdout):
 *   sleepScore,total,efficiency,restfulness,rem,deep,latency,timing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

/*
 * Output structure s_sleep_summary_4_t
 * Based on testing, the output appears to be sequential uint8 scores.
 */
// Use larger buffer to capture full output
typedef struct {
    uint8_t data[256];
} s_sleep_summary_4_t;

// Function pointer types - exact parameter types from mangled names
typedef void (*sleep_score_calc_minutes_t)(
    s_sleep_summary_4_t* output,
    uint16_t total_min,
    uint16_t deep_min,
    uint16_t rem_min,
    uint8_t efficiency,
    uint8_t latency_min,
    uint8_t wakeup_count,
    uint16_t awake_sec,
    uint8_t restless,
    int16_t temp_deviation,
    uint8_t unknown,
    int day_offset
);

// Try with int return type to capture return value
typedef int (*sleep_score_calc_t)(
    s_sleep_summary_4_t* output,
    uint16_t total_sec,
    uint16_t deep_sec,
    uint16_t rem_sec,
    uint16_t awake_sec,
    uint8_t efficiency,
    uint8_t wakeup_count,
    uint16_t latency_sec,
    uint8_t restless,
    int16_t temp_deviation,
    uint8_t unknown,
    int day_offset
);

typedef void (*sleep_score_init_limits_t)(uint8_t);

void dump_buffer(const char* label, void* buf, int size) {
    uint8_t* bytes = (uint8_t*)buf;
    fprintf(stderr, "%s:\n", label);
    for (int i = 0; i < size && i < 128; i++) {
        fprintf(stderr, "%02x ", bytes[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

int main(int argc, char* argv[]) {
    fprintf(stderr, "Sleep Score Stateless Bridge v2\n");
    fprintf(stderr, "================================\n");

    // Load library
    fprintf(stderr, "\nLoading libappecore.so...\n");
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }
    fprintf(stderr, "  Loaded OK\n");

    // Get function pointers - C++ mangled names
    sleep_score_calc_minutes_t calc_minutes =
        (sleep_score_calc_minutes_t)dlsym(handle,
            "_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi");

    sleep_score_calc_t calc_seconds =
        (sleep_score_calc_t)dlsym(handle,
            "_Z27ecore_sleep_score_calculateP19s_sleep_summary_4_ttttthhthshi");

    sleep_score_init_limits_t init_limits =
        (sleep_score_init_limits_t)dlsym(handle, "_Z29ecore_sleep_score_init_limitsh");

    fprintf(stderr, "\nFunction addresses:\n");
    fprintf(stderr, "  calc_minutes: %p\n", (void*)calc_minutes);
    fprintf(stderr, "  calc_seconds: %p\n", (void*)calc_seconds);
    fprintf(stderr, "  init_limits:  %p\n", (void*)init_limits);

    if (!calc_seconds) {
        fprintf(stderr, "ERROR: calc_seconds not found\n");
        dlclose(handle);
        return 1;
    }

    // Initialize score limits (sets up lookup tables)
    if (init_limits) {
        fprintf(stderr, "\nInitializing score limits...\n");
        init_limits(0);
    }

    // Read input from stdin
    // Function signature from mangled name: (output*, total, deep, rem, AWAKE, efficiency, wakeups, latency, restless, tempdev, unknown, dayoffset)
    fprintf(stderr, "\nReading input (CSV: totalSec,deepSec,remSec,awakeSec,efficiency,wakeups,latencySec,restless,tempDev)\n");

    // Default values (7h sleep)
    int total_sec = 25200;    // 7h = 420min
    int deep_sec = 5040;      // 84min
    int rem_sec = 6300;       // 105min
    int awake_sec = 300;      // 5min awake during sleep
    int efficiency = 88;      // 88%
    int wakeup_count = 2;
    int latency_sec = 600;    // 10min to fall asleep
    int restless = 4;
    int temp_dev = 0;

    char line[256];
    if (fgets(line, sizeof(line), stdin)) {
        int parsed = sscanf(line, "%d,%d,%d,%d,%d,%d,%d,%d,%d",
                   &total_sec, &deep_sec, &rem_sec,
                   &awake_sec, &efficiency, &wakeup_count,
                   &latency_sec, &restless, &temp_dev);
        if (parsed >= 6) {
            fprintf(stderr, "  Parsed %d values\n", parsed);
        }
    }

    fprintf(stderr, "\nInput:\n");
    fprintf(stderr, "  totalSec=%d deepSec=%d remSec=%d awakeSec=%d\n", total_sec, deep_sec, rem_sec, awake_sec);
    fprintf(stderr, "  efficiency=%d wakeups=%d latencySec=%d\n", efficiency, wakeup_count, latency_sec);
    fprintf(stderr, "  restless=%d tempDev=%d\n", restless, temp_dev);

    // Output buffer
    s_sleep_summary_4_t output;
    memset(&output, 0, sizeof(output));

    // Call the seconds version (preferred as input is in seconds)
    fprintf(stderr, "\nCalling ecore_sleep_score_calculate...\n");

    // Clamp values to uint16 range
    uint16_t ts = (total_sec > 65535) ? 65535 : total_sec;
    uint16_t ds = (deep_sec > 65535) ? 65535 : deep_sec;
    uint16_t rs = (rem_sec > 65535) ? 65535 : rem_sec;
    uint16_t as = (awake_sec > 65535) ? 65535 : awake_sec;
    uint16_t ls = (latency_sec > 65535) ? 65535 : latency_sec;

    int ret = calc_seconds(
        &output,
        ts,                     // total_sec
        ds,                     // deep_sec
        rs,                     // rem_sec
        as,                     // awake_sec
        (uint8_t)efficiency,    // efficiency
        (uint8_t)wakeup_count,  // wakeup_count
        ls,                     // latency_sec
        (uint8_t)restless,      // restless
        (int16_t)temp_dev,      // temp_deviation
        0,                      // unknown
        0                       // day_offset
    );

    fprintf(stderr, "  Done, return value: %d\n", ret);
    dump_buffer("  Raw output", &output, 64);

    // Find scores in the buffer - look for values 0-100
    fprintf(stderr, "\nLooking for score values (0-100):\n");
    for (int i = 0; i < 64; i++) {
        if (output.data[i] > 0 && output.data[i] <= 100) {
            fprintf(stderr, "  data[%d] = %d\n", i, output.data[i]);
        }
    }

    // Output results - use bytes as they are
    // Based on observation: bytes 0-7 seem to contain something
    fprintf(stderr, "\nFirst 8 bytes as scores:\n");
    for (int i = 0; i < 8; i++) {
        fprintf(stderr, "  [%d]: %d\n", i, output.data[i]);
    }

    // CSV output
    printf("sleepScore,total,efficiency,restfulness,rem,deep,latency,timing\n");
    printf("%d,%d,%d,%d,%d,%d,%d,%d\n",
           output.data[0], output.data[1], output.data[2], output.data[3],
           output.data[4], output.data[5], output.data[6], output.data[7]);

    dlclose(handle);
    fprintf(stderr, "\nDone.\n");
    return 0;
}
