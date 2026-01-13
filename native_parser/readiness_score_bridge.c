/*
 * readiness_score_bridge.c - Readiness Score Calculation Bridge
 *
 * Calls readiness_calculate to compute readiness score with contributors.
 *
 * This is more complex than sleep score - requires struct inputs based on:
 * - ReadinessScoreSleepInput.java
 * - ReadinessScoreHistoryInput.java
 * - PreviousDayInput.java
 * - Baseline.java
 * - RestModeInput.java
 *
 * Input format (CSV from stdin):
 *   sleepDateUtcSec,dayNumber,sleepScore,timeInBedSec,totalSleepSec,remSleepSec,deepSleepSec,latencySec,wakeUpCount,highestTempCentideg,lowestHr,lowestHrTimeSec,rmssd
 *
 * Output format (CSV to stdout):
 *   score,activityBalance,lastDayActivity,lastNightSleep,restingHr,restingHrTime,sleepBalance,temperature,hrvBalance,sleepRegularity,tempDeviation,tempTrendDeviation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

/* Readiness output structure - 12 fields based on ReadinessScoreOutput.java */
typedef struct {
    int score;
    int activity_balance;
    int last_day_activity;
    int last_night_sleep;
    int resting_hr;
    int resting_hr_time;
    int sleep_balance;
    int temperature;
    int hrv_balance;          // May be -1 if not set
    int sleep_regularity;     // May be -1 if not set
    int temp_deviation;       // May be -1 if not set
    int temp_trend_deviation; // May be -1 if not set
} s_ecore_readiness_output_t;

/* Readiness input structure - based on ReadinessScoreSleepInput.java */
typedef struct {
    int64_t sleep_date_utc_seconds;
    int day_number;
    int sleep_score;
    int time_in_bed_seconds;
    int total_sleep_seconds;
    int rem_sleep_seconds;
    int deep_sleep_seconds;
    int latency_seconds;
    int wake_up_count;
    int highest_temp_centidegrees;
    int lowest_hr;
    int lowest_hr_time_seconds;
    int rmssd;
} s_readiness_sleep_input_t;

/* Simplified input - just sleep data for now */
typedef struct {
    s_readiness_sleep_input_t sleep_input;
    // TODO: Add other required inputs (previous day, baseline, history, rest mode)
} s_ecore_readiness_input_t;

/* Function pointer type */
typedef int (*readiness_calculate_t)(
    s_ecore_readiness_output_t* output,
    s_ecore_readiness_input_t* input
);

int main(int argc, char* argv[]) {
    /* Load library */
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to load libappecore.so: %s\n", dlerror());
        return 1;
    }

    /* Get function pointer - using mangled name */
    readiness_calculate_t calc = (readiness_calculate_t)dlsym(handle,
        "_Z19readiness_calculateP26s_ecore_readiness_output_tP25s_ecore_readiness_input_t");

    if (!calc) {
        fprintf(stderr, "ERROR: readiness_calculate function not found\n");
        dlclose(handle);
        return 1;
    }

    /* Parse input from stdin */
    char line[512];
    int64_t sleep_date_utc_sec = 0;
    int day_number = 1;
    int sleep_score = 75;
    int time_in_bed_sec = 28800;  // 8h
    int total_sleep_sec = 25200;  // 7h
    int rem_sleep_sec = 6300;     // 105min
    int deep_sleep_sec = 5040;    // 84min
    int latency_sec = 600;        // 10min
    int wake_up_count = 2;
    int highest_temp_centideg = 0;
    int lowest_hr = 55;
    int lowest_hr_time_sec = 3600;
    int rmssd = 50;

    if (fgets(line, sizeof(line), stdin)) {
        int parsed = sscanf(line, "%ld,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
                   &sleep_date_utc_sec, &day_number, &sleep_score,
                   &time_in_bed_sec, &total_sleep_sec, &rem_sleep_sec,
                   &deep_sleep_sec, &latency_sec, &wake_up_count,
                   &highest_temp_centideg, &lowest_hr, &lowest_hr_time_sec, &rmssd);

        if (parsed < 3) {
            fprintf(stderr, "WARNING: Only parsed %d values, using defaults\n", parsed);
        }
    }

    /* Prepare input */
    s_ecore_readiness_input_t input = {0};
    input.sleep_input.sleep_date_utc_seconds = sleep_date_utc_sec;
    input.sleep_input.day_number = day_number;
    input.sleep_input.sleep_score = sleep_score;
    input.sleep_input.time_in_bed_seconds = time_in_bed_sec;
    input.sleep_input.total_sleep_seconds = total_sleep_sec;
    input.sleep_input.rem_sleep_seconds = rem_sleep_sec;
    input.sleep_input.deep_sleep_seconds = deep_sleep_sec;
    input.sleep_input.latency_seconds = latency_sec;
    input.sleep_input.wake_up_count = wake_up_count;
    input.sleep_input.highest_temp_centidegrees = highest_temp_centideg;
    input.sleep_input.lowest_hr = lowest_hr;
    input.sleep_input.lowest_hr_time_seconds = lowest_hr_time_sec;
    input.sleep_input.rmssd = rmssd;

    /* Prepare output buffer */
    s_ecore_readiness_output_t output = {0};

    /* Call the native function */
    int result = calc(&output, &input);

    fprintf(stderr, "DEBUG: Function returned: %d\n", result);
    fprintf(stderr, "DEBUG: Output score: %d\n", output.score);

    /* Output CSV header and data */
    printf("score,activityBalance,lastDayActivity,lastNightSleep,restingHr,restingHrTime,sleepBalance,temperature,hrvBalance,sleepRegularity,tempDeviation,tempTrendDeviation\n");
    printf("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
           output.score,
           output.activity_balance,
           output.last_day_activity,
           output.last_night_sleep,
           output.resting_hr,
           output.resting_hr_time,
           output.sleep_balance,
           output.temperature,
           output.hrv_balance,
           output.sleep_regularity,
           output.temp_deviation,
           output.temp_trend_deviation
    );

    dlclose(handle);
    return 0;
}
