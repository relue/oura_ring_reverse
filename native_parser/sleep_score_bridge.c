/*
 * sleep_score_bridge.c - Sleep Score Calculation using Native Oura Library
 *
 * Calls ecore_sleep_score_calculate_minutes to compute sleep score.
 * NO ecore_init() required - this is a stateless calculation function.
 *
 * Input format (CSV from stdin):
 *   totalSleepMin,deepSleepMin,remSleepMin,efficiency,latencyMin,wakeUpCount,awakeSec,restlessPeriods,tempDeviation
 *
 * Output format (CSV to stdout):
 *   sleepScore,totalContrib,contrib2,efficiencyContrib,restfulnessContrib,timingContrib,deepContrib,latencyContrib
 *
 * Example:
 *   echo "420,84,105,88,10,2,300,4,0" | ./sleep_score_bridge
 *   sleepScore,totalContrib,contrib2,efficiencyContrib,restfulnessContrib,timingContrib,deepContrib,latencyContrib
 *   52,63,61,73,1,1,87,33
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

/* Output structure for contributor scores */
typedef struct {
    uint8_t data[64];
} s_sleep_summary_4_t;

/* Function pointer type for sleep score calculation */
typedef int (*sleep_score_calc_t)(
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
    /* Load library */
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to load libappecore.so: %s\n", dlerror());
        return 1;
    }

    /* Get function pointers */
    sleep_score_calc_t calc = (sleep_score_calc_t)dlsym(handle,
        "_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi");

    init_limits_t init_limits = (init_limits_t)dlsym(handle,
        "_Z29ecore_sleep_score_init_limitsh");

    if (!calc) {
        fprintf(stderr, "ERROR: Sleep score function not found\n");
        dlclose(handle);
        return 1;
    }

    /* Initialize score lookup tables */
    if (init_limits) {
        init_limits(0);
    }

    /* Default values for a typical 7-hour sleep */
    int total_min = 420;      /* 7 hours */
    int deep_min = 84;        /* ~20% of sleep */
    int rem_min = 105;        /* ~25% of sleep */
    int efficiency = 88;      /* 88% efficiency */
    int latency_min = 10;     /* 10 min to fall asleep */
    int wakeup_count = 2;     /* 2 wake-ups */
    int awake_sec = 300;      /* 5 min awake during night */
    int restless = 4;         /* 4 restless periods */
    int temp_dev = 0;         /* neutral temperature */

    /* Parse input from stdin */
    char line[256];
    if (fgets(line, sizeof(line), stdin)) {
        int parsed = sscanf(line, "%d,%d,%d,%d,%d,%d,%d,%d,%d",
                   &total_min, &deep_min, &rem_min,
                   &efficiency, &latency_min, &wakeup_count,
                   &awake_sec, &restless, &temp_dev);
        if (parsed < 4) {
            fprintf(stderr, "WARNING: Only parsed %d values, using defaults for rest\n", parsed);
        }
    }

    /* Prepare output buffer */
    s_sleep_summary_4_t output;
    memset(&output, 0, sizeof(output));

    /* Call the native function */
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
        0,  /* unknown parameter */
        0   /* day offset */
    );

    /* Output CSV header and data */
    printf("sleepScore,totalContrib,contrib2,efficiencyContrib,restfulnessContrib,timingContrib,deepContrib,latencyContrib\n");
    printf("%d,%d,%d,%d,%d,%d,%d,%d\n",
           score,
           output.data[0],  /* Total sleep contributor */
           output.data[1],  /* Unknown contributor */
           output.data[2],  /* Efficiency contributor */
           output.data[3],  /* Restfulness contributor (often low) */
           output.data[4],  /* Timing contributor (often low) */
           output.data[5],  /* Deep sleep contributor */
           output.data[6]   /* Latency contributor */
    );

    dlclose(handle);
    return 0;
}
