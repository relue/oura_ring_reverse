/*
 * sleep_score_minutes.c - Sleep Score using minutes function
 *
 * Function signature from mangled name:
 * ecore_sleep_score_calculate_minutes(s_sleep_summary_4_t*, t, t, t, h, h, h, t, h, s, h, i)
 *
 * Parameters:
 *   - output: pointer to output struct
 *   - t: uint16 total_min
 *   - t: uint16 deep_min
 *   - t: uint16 rem_min
 *   - h: uint8 efficiency
 *   - h: uint8 latency_min
 *   - h: uint8 wakeup_count
 *   - t: uint16 awake_sec (or awake_min?)
 *   - h: uint8 restless
 *   - s: int16 temp_dev
 *   - h: uint8 unknown
 *   - i: int day_offset
 *
 * Input: totalMin,deepMin,remMin,efficiency,latencyMin,wakeups,awakeSec,restless,tempDev
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

typedef struct {
    uint8_t data[64];
} s_sleep_summary_4_t;

typedef int (*sleep_score_calc_minutes_t)(
    s_sleep_summary_4_t* output,
    uint16_t total_min,
    uint16_t deep_min,
    uint16_t rem_min,
    uint8_t efficiency,
    uint8_t latency_min,
    uint8_t wakeup_count,
    uint16_t awake_sec,
    uint8_t restless,
    int16_t temp_dev,
    uint8_t unknown,
    int day_offset
);

typedef void (*init_limits_t)(uint8_t);

int main(int argc, char* argv[]) {
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }

    sleep_score_calc_minutes_t calc = (sleep_score_calc_minutes_t)dlsym(handle,
        "_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi");

    init_limits_t init_limits = (init_limits_t)dlsym(handle,
        "_Z29ecore_sleep_score_init_limitsh");

    if (!calc) {
        fprintf(stderr, "Function not found\n");
        dlclose(handle);
        return 1;
    }

    if (init_limits) init_limits(0);

    /* Defaults for 7h sleep */
    int total_min = 420;
    int deep_min = 84;
    int rem_min = 105;
    int efficiency = 88;
    int latency_min = 10;
    int wakeup_count = 2;
    int awake_sec = 300;
    int restless = 4;
    int temp_dev = 0;

    char line[256];
    if (fgets(line, sizeof(line), stdin)) {
        sscanf(line, "%d,%d,%d,%d,%d,%d,%d,%d,%d",
               &total_min, &deep_min, &rem_min,
               &efficiency, &latency_min, &wakeup_count,
               &awake_sec, &restless, &temp_dev);
    }

    s_sleep_summary_4_t output;
    memset(&output, 0, sizeof(output));

    int score = calc(&output,
        (uint16_t)total_min,
        (uint16_t)deep_min,
        (uint16_t)rem_min,
        (uint8_t)efficiency,
        (uint8_t)latency_min,
        (uint8_t)wakeup_count,
        (uint16_t)awake_sec,
        (uint8_t)restless,
        (int16_t)temp_dev,
        0, 0);

    printf("sleepScore\n%d\n", score);

    fprintf(stderr, "Input: total=%dmin deep=%dmin rem=%dmin eff=%d%% latency=%dmin wakeups=%d awake=%ds restless=%d temp=%d\n",
            total_min, deep_min, rem_min, efficiency, latency_min, wakeup_count, awake_sec, restless, temp_dev);
    fprintf(stderr, "Score: %d\n", score);

    /* Also dump output struct to look for contributor scores */
    fprintf(stderr, "Output bytes: ");
    for (int i = 0; i < 16; i++) {
        fprintf(stderr, "%d ", output.data[i]);
    }
    fprintf(stderr, "\n");

    dlclose(handle);
    return 0;
}
