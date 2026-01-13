/*
 * daily_sleep_bridge.c - Call get_daily_sleep for sleep score calculation
 *
 * Uses the stateless get_daily_sleep function which takes:
 *   - s_ecore_daily_sleep_output_t* output
 *   - s_ecore_user_info_t* user
 *   - unsigned char (count?)
 *   - int (day_offset?)
 *   - unsigned int (timestamp?)
 *   - s_ecore_sleep_period_input_t* sleep_periods
 *
 * Based on SleepPeriodInput.java field analysis.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

/*
 * Input struct based on SleepPeriodInput.java fields:
 *   day, sleepPeriodId, isMainPeriod, bedtimeStartUtcTimeSeconds, timeZone,
 *   timeInBedSec, totalSleepSec, remSec, deepSec, efficiency, latencySec,
 *   wakeUpCount, restlessPeriods, gotUpCount, sleepMidPoint,
 *   highestTempCentideg, lowestHr, lowestHrTimeSec, rmssd, rawType
 */
typedef struct {
    int32_t day;                        // 0
    int32_t sleep_period_id;            // 4
    uint8_t is_main_period;             // 8
    uint8_t pad1[3];                    // 9-11 (alignment)
    int64_t bedtime_start_utc_seconds;  // 12 (but aligned to 16?)
    int32_t time_zone;                  // time zone offset
    uint32_t time_in_bed_sec;
    uint32_t total_sleep_sec;
    uint32_t rem_sec;
    uint32_t deep_sec;
    uint8_t efficiency;
    uint8_t pad2[3];
    uint32_t latency_sec;
    uint8_t wakeup_count;
    uint8_t restless_periods;
    uint8_t got_up_count;
    uint8_t pad3;
    uint32_t sleep_midpoint;
    int16_t highest_temp_centideg;
    uint16_t lowest_hr;
    uint32_t lowest_hr_time_sec;
    uint32_t rmssd;
    uint8_t raw_type;
    uint8_t pad4[3];
} __attribute__((packed)) s_ecore_sleep_period_input_v1_t;

/* Alternative layout with 16-bit time values */
typedef struct {
    uint16_t day;
    uint16_t sleep_period_id;
    uint8_t is_main_period;
    uint8_t raw_type;
    uint16_t time_zone;
    uint32_t bedtime_start_utc_seconds;
    uint16_t time_in_bed_min;
    uint16_t total_sleep_min;
    uint16_t rem_min;
    uint16_t deep_min;
    uint8_t efficiency;
    uint8_t latency_min;
    uint8_t wakeup_count;
    uint8_t restless_periods;
    uint8_t got_up_count;
    uint8_t pad1;
    uint16_t sleep_midpoint_min;
    int16_t highest_temp_centideg;
    uint8_t lowest_hr;
    uint8_t pad2;
    uint16_t lowest_hr_time_min;
    uint16_t rmssd;
} __attribute__((packed)) s_ecore_sleep_period_input_v2_t;

/* User info - minimal guess */
typedef struct {
    uint8_t data[64];
} s_ecore_user_info_t;

/* Output struct - contains sleep scores */
typedef struct {
    uint8_t data[256];
} s_ecore_daily_sleep_output_t;

/* Function pointer */
typedef void (*get_daily_sleep_t)(
    s_ecore_daily_sleep_output_t* output,
    s_ecore_user_info_t* user,
    uint8_t count_or_flag,
    int day_offset,
    uint32_t timestamp_or_count,
    void* sleep_periods
);

typedef void (*sleep_score_init_limits_t)(uint8_t);

void dump_buffer(const char* label, void* buf, int size) {
    uint8_t* bytes = (uint8_t*)buf;
    fprintf(stderr, "%s:\n", label);
    for (int i = 0; i < size && i < 128; i++) {
        fprintf(stderr, "%02x ", bytes[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
    }
    if (size % 16 != 0) fprintf(stderr, "\n");
}

int main(int argc, char* argv[]) {
    fprintf(stderr, "Daily Sleep Bridge\n");
    fprintf(stderr, "==================\n");

    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }
    fprintf(stderr, "Library loaded OK\n");

    /* Get functions */
    get_daily_sleep_t get_sleep = (get_daily_sleep_t)dlsym(handle,
        "_Z15get_daily_sleepP28s_ecore_daily_sleep_output_tP19s_ecore_user_info_thijP28s_ecore_sleep_period_input_t");

    sleep_score_init_limits_t init_limits =
        (sleep_score_init_limits_t)dlsym(handle, "_Z29ecore_sleep_score_init_limitsh");

    fprintf(stderr, "Function addresses:\n");
    fprintf(stderr, "  get_daily_sleep: %p\n", (void*)get_sleep);
    fprintf(stderr, "  init_limits:     %p\n", (void*)init_limits);

    if (!get_sleep) {
        fprintf(stderr, "ERROR: get_daily_sleep not found\n");
        dlclose(handle);
        return 1;
    }

    /* Initialize score limits */
    if (init_limits) {
        init_limits(0);
        fprintf(stderr, "Initialized score limits\n");
    }

    /* Read input */
    fprintf(stderr, "\nReading input (CSV: totalSec,deepSec,remSec,awakeSec,efficiency,wakeups,latencySec,restless,tempDev)\n");

    int total_sec = 25200;
    int deep_sec = 5040;
    int rem_sec = 6300;
    int awake_sec = 300;
    int efficiency = 88;
    int wakeup_count = 2;
    int latency_sec = 600;
    int restless = 4;
    int temp_dev = 0;

    char line[256];
    if (fgets(line, sizeof(line), stdin)) {
        sscanf(line, "%d,%d,%d,%d,%d,%d,%d,%d,%d",
               &total_sec, &deep_sec, &rem_sec,
               &awake_sec, &efficiency, &wakeup_count,
               &latency_sec, &restless, &temp_dev);
    }

    fprintf(stderr, "\nInput: total=%d deep=%d rem=%d awake=%d eff=%d wakeups=%d latency=%d\n",
            total_sec, deep_sec, rem_sec, awake_sec, efficiency, wakeup_count, latency_sec);

    /* Build input struct - try v2 layout with minutes */
    s_ecore_sleep_period_input_v2_t input = {0};
    input.day = 1;
    input.sleep_period_id = 1;
    input.is_main_period = 1;
    input.raw_type = 0;
    input.time_zone = 0;
    input.bedtime_start_utc_seconds = 0;  /* Would need real timestamp */
    input.time_in_bed_min = (total_sec + awake_sec + latency_sec) / 60;
    input.total_sleep_min = total_sec / 60;
    input.rem_min = rem_sec / 60;
    input.deep_min = deep_sec / 60;
    input.efficiency = efficiency;
    input.latency_min = latency_sec / 60;
    input.wakeup_count = wakeup_count;
    input.restless_periods = restless;
    input.got_up_count = wakeup_count;
    input.sleep_midpoint_min = (total_sec / 2) / 60;  /* Middle of sleep */
    input.highest_temp_centideg = temp_dev;
    input.lowest_hr = 50;  /* Typical resting HR */
    input.lowest_hr_time_min = 180;  /* 3h into sleep */
    input.rmssd = 40;  /* Typical RMSSD */

    fprintf(stderr, "\nInput struct (v2 layout, %zu bytes):\n", sizeof(input));
    dump_buffer("sleep_period_input", &input, sizeof(input));

    /* Prepare output and user info */
    s_ecore_daily_sleep_output_t output;
    s_ecore_user_info_t user;
    memset(&output, 0, sizeof(output));
    memset(&user, 0, sizeof(user));

    /* Call the function */
    fprintf(stderr, "\nCalling get_daily_sleep...\n");
    get_sleep(&output, &user, 1, 0, 1, &input);
    fprintf(stderr, "Function returned\n");

    /* Dump output */
    dump_buffer("Output buffer", &output, 64);

    /* Look for score-like values */
    fprintf(stderr, "\nPossible scores (values 1-100):\n");
    for (int i = 0; i < 64; i++) {
        if (output.data[i] >= 1 && output.data[i] <= 100) {
            fprintf(stderr, "  [%d] = %d\n", i, output.data[i]);
        }
    }

    /* Output CSV */
    printf("sleepScore,total,efficiency,restfulness,rem,deep,latency,timing\n");
    printf("%d,%d,%d,%d,%d,%d,%d,%d\n",
           output.data[0], output.data[1], output.data[2], output.data[3],
           output.data[4], output.data[5], output.data[6], output.data[7]);

    dlclose(handle);
    fprintf(stderr, "\nDone.\n");
    return 0;
}
