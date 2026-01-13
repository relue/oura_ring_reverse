/*
 * sleep_score_final.c - Sleep Score Calculation using Native Library
 *
 * Calls ecore_sleep_score_calculate directly without ecore_init().
 *
 * Function: ecore_sleep_score_calculate(s_sleep_summary_4_t*, t, t, t, t, h, h, t, h, s, h, i)
 * Returns: Sleep score (0-100)
 *
 * Parameters (from mangled C++ signature):
 *   - output: s_sleep_summary_4_t* (receives contributor scores)
 *   - total_sec: uint16 - total sleep time in seconds
 *   - deep_sec: uint16 - deep sleep time in seconds
 *   - rem_sec: uint16 - REM sleep time in seconds
 *   - awake_sec: uint16 - time awake during sleep in seconds
 *   - efficiency: uint8 - sleep efficiency percentage (0-100)
 *   - wakeup_count: uint8 - number of times woken up
 *   - latency_sec: uint16 - time to fall asleep in seconds
 *   - restless: uint8 - restless periods count
 *   - temp_dev: int16 - temperature deviation in centidegrees
 *   - unknown: uint8 - unknown parameter (use 0)
 *   - day_offset: int - day offset (use 0)
 *
 * Input CSV format (stdin):
 *   totalSleepSec,deepSleepSec,remSleepSec,awakeSec,efficiency,wakeups,latencySec,restless,tempDev
 *
 * Output CSV format (stdout):
 *   sleepScore
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

/* Output struct for contributor scores */
typedef struct {
    uint8_t data[64];
} s_sleep_summary_4_t;

/* Function pointer - returns the overall sleep score */
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
    int16_t temp_dev,
    uint8_t unknown,
    int day_offset
);

typedef void (*init_limits_t)(uint8_t);

int main(int argc, char* argv[]) {
    /* Load library */
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load libappecore.so: %s\n", dlerror());
        return 1;
    }

    /* Get function pointers */
    sleep_score_calc_t calc = (sleep_score_calc_t)dlsym(handle,
        "_Z27ecore_sleep_score_calculateP19s_sleep_summary_4_ttttthhthshi");

    init_limits_t init_limits = (init_limits_t)dlsym(handle,
        "_Z29ecore_sleep_score_init_limitsh");

    if (!calc) {
        fprintf(stderr, "Function not found\n");
        dlclose(handle);
        return 1;
    }

    /* Initialize score lookup tables */
    if (init_limits) {
        init_limits(0);
    }

    /* Parse input */
    int total_sec = 25200;  /* 7h default */
    int deep_sec = 5040;    /* 84min */
    int rem_sec = 6300;     /* 105min */
    int awake_sec = 300;    /* 5min awake */
    int efficiency = 88;    /* 88% */
    int wakeup_count = 2;
    int latency_sec = 600;  /* 10min */
    int restless = 4;
    int temp_dev = 0;

    char line[256];
    if (fgets(line, sizeof(line), stdin)) {
        sscanf(line, "%d,%d,%d,%d,%d,%d,%d,%d,%d",
               &total_sec, &deep_sec, &rem_sec,
               &awake_sec, &efficiency, &wakeup_count,
               &latency_sec, &restless, &temp_dev);
    }

    /* Prepare output buffer */
    s_sleep_summary_4_t output;
    memset(&output, 0, sizeof(output));

    /* Call the function */
    int score = calc(
        &output,
        (total_sec > 65535) ? 65535 : total_sec,
        (deep_sec > 65535) ? 65535 : deep_sec,
        (rem_sec > 65535) ? 65535 : rem_sec,
        (awake_sec > 65535) ? 65535 : awake_sec,
        (uint8_t)efficiency,
        (uint8_t)wakeup_count,
        (latency_sec > 65535) ? 65535 : latency_sec,
        (uint8_t)restless,
        (int16_t)temp_dev,
        0,
        0
    );

    /* Output the sleep score */
    printf("sleepScore\n");
    printf("%d\n", score);

    /* Also output to stderr for debugging */
    fprintf(stderr, "Input: total=%ds deep=%ds rem=%ds awake=%ds eff=%d%% wakeups=%d latency=%ds restless=%d temp=%d\n",
            total_sec, deep_sec, rem_sec, awake_sec, efficiency, wakeup_count, latency_sec, restless, temp_dev);
    fprintf(stderr, "Sleep Score: %d\n", score);

    dlclose(handle);
    return 0;
}
