/*
 * sleep_score_v3.c - Sleep score calculation with struct as input
 *
 * Testing hypothesis: The s_sleep_summary_4_t struct is the INPUT,
 * and the function parameters might be additional weights or config.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

// Possible struct layouts based on Java SleepPeriodInput fields

// Layout A: uint16 values for time measurements
typedef struct {
    uint16_t time_in_bed_sec;      // 0-1
    uint16_t total_sleep_sec;      // 2-3
    uint16_t deep_sleep_sec;       // 4-5
    uint16_t rem_sleep_sec;        // 6-7
    uint16_t light_sleep_sec;      // 8-9
    uint16_t awake_sec;            // 10-11
    uint16_t latency_sec;          // 12-13
    uint8_t efficiency;            // 14
    uint8_t wakeup_count;          // 15
    uint8_t restless_periods;      // 16
    uint8_t got_up_count;          // 17
    int16_t temp_centideg;         // 18-19
    uint16_t lowest_hr;            // 20-21
    uint16_t rmssd;                // 22-23
    uint8_t padding[8];            // 24-31
} __attribute__((packed)) sleep_input_v1_t;

// Layout B: 32-bit values for time
typedef struct {
    uint32_t time_in_bed_sec;
    uint32_t total_sleep_sec;
    uint32_t deep_sleep_sec;
    uint32_t rem_sleep_sec;
    uint32_t light_sleep_sec;
    uint32_t awake_sec;
    uint32_t latency_sec;
    uint8_t efficiency;
    uint8_t wakeup_count;
    uint8_t restless_periods;
    uint8_t got_up_count;
    int16_t temp_centideg;
    uint16_t lowest_hr;
    uint16_t rmssd;
    uint8_t padding[8];
} __attribute__((packed)) sleep_input_v2_t;

// Layout C: Match the "4" in s_sleep_summary_4_t (maybe version 4 format?)
// Perhaps starts with version or flags
typedef struct {
    uint32_t version;              // 0-3: version/flags
    uint16_t total_sleep_sec;      // 4-5
    uint16_t deep_sleep_sec;       // 6-7
    uint16_t rem_sleep_sec;        // 8-9
    uint16_t light_sleep_sec;      // 10-11
    uint8_t efficiency;            // 12
    uint8_t wakeup_count;          // 13
    uint8_t restless_periods;      // 14
    uint8_t latency_min;           // 15
    int8_t temp_deviation;         // 16
    uint8_t lowest_hr;             // 17
    uint8_t padding[14];           // 18-31
} __attribute__((packed)) sleep_input_v3_t;

// Large buffer for testing
typedef struct {
    uint8_t data[256];
} buffer_t;

// Function pointer - returns int (the sleep score)
typedef int (*sleep_score_calc_t)(
    void* summary,
    uint16_t p1, uint16_t p2, uint16_t p3, uint16_t p4,
    uint8_t p5, uint8_t p6,
    uint16_t p7,
    uint8_t p8,
    int16_t p9,
    uint8_t p10,
    int p11
);

typedef void (*sleep_score_init_limits_t)(uint8_t);

int main(int argc, char* argv[]) {
    fprintf(stderr, "Sleep Score v3 - Testing struct as input\n");
    fprintf(stderr, "=========================================\n");

    // Load library
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }

    sleep_score_calc_t calc = (sleep_score_calc_t)dlsym(handle,
        "_Z27ecore_sleep_score_calculateP19s_sleep_summary_4_ttttthhthshi");

    sleep_score_init_limits_t init_limits =
        (sleep_score_init_limits_t)dlsym(handle, "_Z29ecore_sleep_score_init_limitsh");

    if (!calc) {
        fprintf(stderr, "Function not found\n");
        dlclose(handle);
        return 1;
    }

    if (init_limits) {
        init_limits(0);
    }

    // Test values (7h good sleep)
    int total_sec = 25200;
    int deep_sec = 5040;
    int rem_sec = 6300;
    int light_sec = total_sec - deep_sec - rem_sec;
    int awake_sec = 300;
    int efficiency = 88;
    int latency_sec = 600;
    int wakeup_count = 2;
    int restless = 4;
    int temp_dev = 0;

    // Parse input if provided
    char line[256];
    if (fgets(line, sizeof(line), stdin)) {
        sscanf(line, "%d,%d,%d,%d,%d,%d,%d,%d,%d",
               &total_sec, &deep_sec, &rem_sec,
               &awake_sec, &efficiency, &wakeup_count,
               &latency_sec, &restless, &temp_dev);
        light_sec = total_sec - deep_sec - rem_sec;
    }

    fprintf(stderr, "\nInput: total=%d deep=%d rem=%d awake=%d eff=%d wakeups=%d latency=%d restless=%d\n",
            total_sec, deep_sec, rem_sec, awake_sec, efficiency, wakeup_count, latency_sec, restless);

    // Test 1: Empty struct, params contain all data (original approach)
    fprintf(stderr, "\n=== Test 1: Empty struct, data in params ===\n");
    buffer_t buf1 = {0};
    int score1 = calc(&buf1,
        total_sec > 65535 ? 65535 : total_sec,
        deep_sec,
        rem_sec,
        awake_sec,
        efficiency,
        wakeup_count,
        latency_sec,
        restless,
        temp_dev,
        0, 0);
    fprintf(stderr, "  Score: %d\n", score1);

    // Test 2: Fill struct with data, pass zeros to params
    fprintf(stderr, "\n=== Test 2: Filled struct, zero params ===\n");
    sleep_input_v1_t input2 = {0};
    input2.total_sleep_sec = total_sec > 65535 ? 65535 : total_sec;
    input2.deep_sleep_sec = deep_sec;
    input2.rem_sleep_sec = rem_sec;
    input2.light_sleep_sec = light_sec;
    input2.awake_sec = awake_sec;
    input2.latency_sec = latency_sec;
    input2.efficiency = efficiency;
    input2.wakeup_count = wakeup_count;
    input2.restless_periods = restless;
    input2.temp_centideg = temp_dev;

    int score2 = calc(&input2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    fprintf(stderr, "  Score: %d\n", score2);

    // Test 3: Struct has data, params have same data (redundant)
    fprintf(stderr, "\n=== Test 3: Both struct and params have data ===\n");
    int score3 = calc(&input2,
        total_sec > 65535 ? 65535 : total_sec,
        deep_sec,
        rem_sec,
        awake_sec,
        efficiency,
        wakeup_count,
        latency_sec,
        restless,
        temp_dev,
        0, 0);
    fprintf(stderr, "  Score: %d\n", score3);

    // Test 4: Try with larger struct values (32-bit)
    fprintf(stderr, "\n=== Test 4: 32-bit struct layout ===\n");
    sleep_input_v2_t input4 = {0};
    input4.total_sleep_sec = total_sec;
    input4.deep_sleep_sec = deep_sec;
    input4.rem_sleep_sec = rem_sec;
    input4.light_sleep_sec = light_sec;
    input4.awake_sec = awake_sec;
    input4.latency_sec = latency_sec;
    input4.efficiency = efficiency;
    input4.wakeup_count = wakeup_count;
    input4.restless_periods = restless;
    input4.temp_centideg = temp_dev;

    int score4 = calc(&input4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    fprintf(stderr, "  Score: %d\n", score4);

    // Test 5: Try params as minutes instead of seconds
    fprintf(stderr, "\n=== Test 5: Params in minutes ===\n");
    buffer_t buf5 = {0};
    int score5 = calc(&buf5,
        total_sec / 60,       // total minutes
        deep_sec / 60,        // deep minutes
        rem_sec / 60,         // rem minutes
        awake_sec / 60,       // awake minutes
        efficiency,           // efficiency (0-100)
        wakeup_count,         // wakeups
        latency_sec / 60,     // latency minutes
        restless,             // restless
        temp_dev,             // temp dev
        0, 0);
    fprintf(stderr, "  Score: %d\n", score5);

    // Output best result
    printf("sleepScore\n");
    printf("%d\n", score5);  // Using minutes seems most likely

    dlclose(handle);
    return 0;
}
