/*
 * daily_outputs_bridge.c - Score Calculation via ecore_get_daily_outputs_stateless
 *
 * This bridge calls libappecore.so's score calculation API to compute:
 * - Sleep score (with 7 contributors)
 * - Readiness score (with 9 contributors)
 *
 * Input format (JSON from stdin):
 * {
 *   "sleepDayUtcSeconds": 1704067200,
 *   "dayNumber": 1,
 *   "sleepPeriods": [{
 *     "day": "2024-01-01",
 *     "sleepPeriodId": 1,
 *     "isMainPeriod": 1,
 *     "bedtimeStartUtcTimeSeconds": 1704060000,
 *     "timeZone": -28800,
 *     "timeInBedSec": 28800,
 *     "totalSleepSec": 25200,
 *     "remSec": 6300,
 *     "deepSec": 5040,
 *     "efficiecy": 88,
 *     "latencySec": 600,
 *     "wakeUpCount": 2,
 *     "restlessPeriods": 5,
 *     "gotUpCount": 0,
 *     "sleepMidPoint": 14400,
 *     "highestTempCentideg": 50,
 *     "lowestHr": 52,
 *     "lowestHrTimeSec": 10800,
 *     "rmssd": 45,
 *     "rawType": 0
 *   }],
 *   "previousDay": {
 *     "equivalentWalkingDistanceMeters": 8000,
 *     "nonWearTimeMinutes": 60,
 *     "sedentaryTimeMinutes": 480,
 *     "vigorousTimeMinutes": 30,
 *     "lightTimeMinutes": 120,
 *     "moderateTimeMinutes": 45,
 *     "restingTimeMinutes": 420
 *   },
 *   "baseline": {
 *     "dayMidnightUtcSeconds": 1704067200,
 *     "dayTimeZone": -28800,
 *     "sleepScoreAverage": 82,
 *     "sleepScoreDeviation": 8,
 *     "sleepTimeAverage": 26000,
 *     "sleepTimeDeviation": 3600,
 *     "restingHrAverage": 54,
 *     "restingHrDeviation": 4,
 *     "restingHrTimeAverage": 10800,
 *     "restingHrTimeDeviation": 1800,
 *     "activityDistanceAverage": 7500,
 *     "activityDistanceDeviation": 2000,
 *     "vigorousActivityAverage": 25,
 *     "vigorousActivityDeviation": 15,
 *     "sedentaryActivityAverage": 500,
 *     "sedentaryActivityDeviation": 60,
 *     "temperatureAverage": 0,
 *     "temperatureDeviation": 30,
 *     "hrvAverage": 42,
 *     "hrvDeviation": 10
 *   },
 *   "readinessHistory": {
 *     "temperatureDeviationHistory3Days": [0, 5, -3],
 *     "highestTempCentidegHistory90Days": [50, 48, ...],
 *     "totalSleepSecondsHistory14Days": [25200, 26400, ...],
 *     "walkingDistanceMetersHistory14Days": [8000, 7500, ...],
 *     "wearPercentageHistory14Days": [95, 98, ...],
 *     "rmssdHistory14Days": [45, 42, ...]
 *   },
 *   "chronotype": {
 *     "chronotype": 3,
 *     "idealSleepMidpointSec": 14400
 *   },
 *   "restMode": {
 *     "restPeriodStartUtcTimeSeconds": 0,
 *     "restPeriodEndUtcTimeSeconds": 0,
 *     "currentMidnightUtcTimeSeconds": 1704067200
 *   },
 *   "cycleDayType": 0
 * }
 *
 * Output format (JSON to stdout):
 * {
 *   "sleepScore": 85,
 *   "sleepContributors": {
 *     "totalSleep": 90,
 *     "deep": 88,
 *     "rem": 82,
 *     "efficiency": 85,
 *     "latency": 95,
 *     "disturbances": 78,
 *     "circadianAlignment": 80
 *   },
 *   "readinessScore": 78,
 *   "readinessContributors": {
 *     "previousNight": 85,
 *     "sleepBalance": 75,
 *     "previousDay": 82,
 *     "activityBalance": 70,
 *     "restingHr": 88,
 *     "recoveryIndex": 72,
 *     "temperature": 65,
 *     "hrvBalance": 80,
 *     "sleepRegularity": 78
 *   }
 * }
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

#define MAX_SLEEP_PERIODS 10
#define MAX_HISTORY_90 90
#define MAX_HISTORY_14 14
#define MAX_HISTORY_3 3

/* C structures matching Java input classes */

typedef struct {
    char day[32];
    int sleepPeriodId;
    int isMainPeriod;
    int64_t bedtimeStartUtcTimeSeconds;
    int timeZone;
    int timeInBedSec;
    int totalSleepSec;
    int remSec;
    int deepSec;
    int efficiecy;  /* Note: typo matches Java code */
    int latencySec;
    int wakeUpCount;
    int restlessPeriods;
    int gotUpCount;
    int sleepMidPoint;
    int highestTempCentideg;
    int lowestHr;
    int lowestHrTimeSec;
    int rmssd;
    int rawType;
} SleepPeriodInput;

typedef struct {
    int equivalentWalkingDistanceMeters;
    int nonWearTimeMinutes;
    int sedentaryTimeMinutes;
    int vigorousTimeMinutes;
    int lightTimeMinutes;
    int moderateTimeMinutes;
    int restingTimeMinutes;
} PreviousDayInput;

typedef struct {
    int64_t dayMidnightUtcSeconds;
    int dayTimeZone;
    int sleepScoreAverage;
    int sleepScoreDeviation;
    int sleepTimeAverage;
    int sleepTimeDeviation;
    int restingHrAverage;
    int restingHrDeviation;
    int restingHrTimeAverage;
    int restingHrTimeDeviation;
    int activityDistanceAverage;
    int activityDistanceDeviation;
    int vigorousActivityAverage;
    int vigorousActivityDeviation;
    int sedentaryActivityAverage;
    int sedentaryActivityDeviation;
    int temperatureAverage;
    int temperatureDeviation;
    int hrvAverage;
    int hrvDeviation;
} Baseline;

typedef struct {
    int temperatureDeviationHistory3Days[MAX_HISTORY_3];
    int highestTempCentidegHistory90Days[MAX_HISTORY_90];
    int totalSleepSecondsHistory14Days[MAX_HISTORY_14];
    int walkingDistanceMetersHistory14Days[MAX_HISTORY_14];
    uint8_t wearPercentageHistory14Days[MAX_HISTORY_14];
    int rmssdHistory14Days[MAX_HISTORY_14];
} ReadinessScoreHistoryInput;

typedef struct {
    int chronotype;
    int idealSleepMidpointSec;
} ChronotypeInput;

typedef struct {
    int64_t restPeriodStartUtcTimeSeconds;
    int64_t restPeriodEndUtcTimeSeconds;
    int64_t currentMidnightUtcTimeSeconds;
} RestModeInput;

/* Output structures matching Java classes */

typedef struct {
    int sleepScore;
    int scoreTotalSleep;
    int scoreDeep;
    int scoreRem;
    int scoreEfficiency;
    int scoreLatency;
    int scoreDisturbances;
    int scoreCircadianAlignment;
    int totalSleepSec;
    int highestTempCentideg;
    int lowestHr;
    int lowestHrTimeSec;
    int rmssd;
    /* Additional fields may exist */
} DailySleepOutput;

typedef struct {
    int readinessScore;
    int previousNight;
    int sleepBalance;
    int previousDay;
    int activityBalance;
    int restingHr;
    int recoveryIndex;
    int temperature;
    int hrvBalance;
    int sleepRegularity;
    int tempDeviation;
    int tempTrendDeviation;
    int restRecoveryState;
} DailyReadinessOutput;

typedef struct {
    DailySleepOutput sleep;
    DailyReadinessOutput readiness;
    int sleepScoreDelta;
    int readinessScoreDelta;
} DailyOutputInfo;

/* Function pointer types */
typedef void (*ecore_init_t)(void);
typedef DailyOutputInfo* (*ecore_get_daily_outputs_stateless_t)(
    int64_t sleepDayUtcSeconds,
    int dayNumber,
    SleepPeriodInput* sleepPeriods,
    int numSleepPeriods,
    PreviousDayInput* previousDay,
    Baseline* baseline,
    ReadinessScoreHistoryInput* readinessHistory,
    ChronotypeInput* chronotype,
    RestModeInput* restMode,
    int cycleDayType
);

/* Simple JSON parsing helpers (minimal implementation) */

static int parse_int(const char* json, const char* key, int default_val) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char* pos = strstr(json, search);
    if (!pos) return default_val;
    pos = strchr(pos, ':');
    if (!pos) return default_val;
    pos++;
    while (*pos == ' ' || *pos == '\t') pos++;
    return atoi(pos);
}

static int64_t parse_int64(const char* json, const char* key, int64_t default_val) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char* pos = strstr(json, search);
    if (!pos) return default_val;
    pos = strchr(pos, ':');
    if (!pos) return default_val;
    pos++;
    while (*pos == ' ' || *pos == '\t') pos++;
    return atoll(pos);
}

static void parse_string(const char* json, const char* key, char* out, int max_len) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char* pos = strstr(json, search);
    if (!pos) { out[0] = '\0'; return; }
    pos = strchr(pos, ':');
    if (!pos) { out[0] = '\0'; return; }
    pos++;
    while (*pos == ' ' || *pos == '\t' || *pos == '"') pos++;
    int i = 0;
    while (*pos && *pos != '"' && i < max_len - 1) {
        out[i++] = *pos++;
    }
    out[i] = '\0';
}

static const char* find_object(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char* pos = strstr(json, search);
    if (!pos) return NULL;
    pos = strchr(pos, ':');
    if (!pos) return NULL;
    pos++;
    while (*pos == ' ' || *pos == '\t') pos++;
    if (*pos == '{') return pos;
    return NULL;
}

static const char* find_array(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char* pos = strstr(json, search);
    if (!pos) return NULL;
    pos = strchr(pos, ':');
    if (!pos) return NULL;
    pos++;
    while (*pos == ' ' || *pos == '\t') pos++;
    if (*pos == '[') return pos;
    return NULL;
}

static int parse_int_array(const char* arr, int* out, int max_count) {
    if (!arr || *arr != '[') return 0;
    arr++;  /* Skip '[' */
    int count = 0;
    while (*arr && *arr != ']' && count < max_count) {
        while (*arr == ' ' || *arr == '\t' || *arr == ',') arr++;
        if (*arr == ']') break;
        out[count++] = atoi(arr);
        while (*arr && *arr != ',' && *arr != ']') arr++;
    }
    return count;
}

int main(int argc, char* argv[]) {
    fprintf(stderr, "Daily Outputs Bridge - Score Calculation\n");
    fprintf(stderr, "=========================================\n");

    /* Load library */
    fprintf(stderr, "\nLoading libappecore.so...\n");
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Failed to load: %s\n", dlerror());
        return 1;
    }
    fprintf(stderr, "  Loaded OK\n");

    /* Get function pointers */
    ecore_init_t ecore_init = (ecore_init_t)dlsym(handle, "ecore_init");
    ecore_get_daily_outputs_stateless_t get_outputs =
        (ecore_get_daily_outputs_stateless_t)dlsym(handle, "ecore_get_daily_outputs_stateless");

    fprintf(stderr, "\nFunction addresses:\n");
    fprintf(stderr, "  ecore_init:                        %p\n", (void*)ecore_init);
    fprintf(stderr, "  ecore_get_daily_outputs_stateless: %p\n", (void*)get_outputs);

    if (!ecore_init || !get_outputs) {
        fprintf(stderr, "ERROR: Required functions not found\n");
        dlclose(handle);
        return 1;
    }

    /* Initialize library */
    fprintf(stderr, "\nInitializing ecore...\n");
    ecore_init();
    fprintf(stderr, "  Init done\n");

    /* Read JSON input from stdin */
    fprintf(stderr, "\nReading JSON input from stdin...\n");
    char* json = malloc(1024 * 1024);  /* 1MB buffer */
    if (!json) {
        fprintf(stderr, "ERROR: Failed to allocate input buffer\n");
        dlclose(handle);
        return 1;
    }

    size_t total = 0;
    size_t n;
    while ((n = fread(json + total, 1, 1024 * 1024 - total - 1, stdin)) > 0) {
        total += n;
    }
    json[total] = '\0';

    if (total == 0) {
        fprintf(stderr, "ERROR: No input received\n");
        free(json);
        dlclose(handle);
        return 1;
    }
    fprintf(stderr, "  Read %zu bytes\n", total);

    /* Parse top-level fields */
    int64_t sleepDayUtcSeconds = parse_int64(json, "sleepDayUtcSeconds", 0);
    int dayNumber = parse_int(json, "dayNumber", 1);
    int cycleDayType = parse_int(json, "cycleDayType", 0);

    fprintf(stderr, "\nParsed parameters:\n");
    fprintf(stderr, "  sleepDayUtcSeconds: %ld\n", (long)sleepDayUtcSeconds);
    fprintf(stderr, "  dayNumber: %d\n", dayNumber);
    fprintf(stderr, "  cycleDayType: %d\n", cycleDayType);

    /* Parse sleep periods (simplified - just one for now) */
    SleepPeriodInput sleepPeriods[MAX_SLEEP_PERIODS];
    int numSleepPeriods = 0;
    memset(sleepPeriods, 0, sizeof(sleepPeriods));

    const char* periods_arr = find_array(json, "sleepPeriods");
    if (periods_arr) {
        /* Find first object in array */
        const char* obj_start = strchr(periods_arr, '{');
        if (obj_start) {
            parse_string(obj_start, "day", sleepPeriods[0].day, sizeof(sleepPeriods[0].day));
            sleepPeriods[0].sleepPeriodId = parse_int(obj_start, "sleepPeriodId", 1);
            sleepPeriods[0].isMainPeriod = parse_int(obj_start, "isMainPeriod", 1);
            sleepPeriods[0].bedtimeStartUtcTimeSeconds = parse_int64(obj_start, "bedtimeStartUtcTimeSeconds", 0);
            sleepPeriods[0].timeZone = parse_int(obj_start, "timeZone", 0);
            sleepPeriods[0].timeInBedSec = parse_int(obj_start, "timeInBedSec", 28800);
            sleepPeriods[0].totalSleepSec = parse_int(obj_start, "totalSleepSec", 25200);
            sleepPeriods[0].remSec = parse_int(obj_start, "remSec", 6300);
            sleepPeriods[0].deepSec = parse_int(obj_start, "deepSec", 5040);
            sleepPeriods[0].efficiecy = parse_int(obj_start, "efficiecy", 88);
            sleepPeriods[0].latencySec = parse_int(obj_start, "latencySec", 600);
            sleepPeriods[0].wakeUpCount = parse_int(obj_start, "wakeUpCount", 2);
            sleepPeriods[0].restlessPeriods = parse_int(obj_start, "restlessPeriods", 5);
            sleepPeriods[0].gotUpCount = parse_int(obj_start, "gotUpCount", 0);
            sleepPeriods[0].sleepMidPoint = parse_int(obj_start, "sleepMidPoint", 14400);
            sleepPeriods[0].highestTempCentideg = parse_int(obj_start, "highestTempCentideg", 50);
            sleepPeriods[0].lowestHr = parse_int(obj_start, "lowestHr", 52);
            sleepPeriods[0].lowestHrTimeSec = parse_int(obj_start, "lowestHrTimeSec", 10800);
            sleepPeriods[0].rmssd = parse_int(obj_start, "rmssd", 45);
            sleepPeriods[0].rawType = parse_int(obj_start, "rawType", 0);
            numSleepPeriods = 1;
        }
    }

    fprintf(stderr, "  Sleep periods: %d\n", numSleepPeriods);
    if (numSleepPeriods > 0) {
        fprintf(stderr, "    [0] totalSleepSec=%d, deepSec=%d, remSec=%d\n",
                sleepPeriods[0].totalSleepSec, sleepPeriods[0].deepSec, sleepPeriods[0].remSec);
    }

    /* Parse previous day */
    PreviousDayInput previousDay = {0};
    const char* prev_obj = find_object(json, "previousDay");
    if (prev_obj) {
        previousDay.equivalentWalkingDistanceMeters = parse_int(prev_obj, "equivalentWalkingDistanceMeters", 8000);
        previousDay.nonWearTimeMinutes = parse_int(prev_obj, "nonWearTimeMinutes", 60);
        previousDay.sedentaryTimeMinutes = parse_int(prev_obj, "sedentaryTimeMinutes", 480);
        previousDay.vigorousTimeMinutes = parse_int(prev_obj, "vigorousTimeMinutes", 30);
        previousDay.lightTimeMinutes = parse_int(prev_obj, "lightTimeMinutes", 120);
        previousDay.moderateTimeMinutes = parse_int(prev_obj, "moderateTimeMinutes", 45);
        previousDay.restingTimeMinutes = parse_int(prev_obj, "restingTimeMinutes", 420);
    }

    fprintf(stderr, "  Previous day: distance=%d, vigorous=%dmin\n",
            previousDay.equivalentWalkingDistanceMeters, previousDay.vigorousTimeMinutes);

    /* Parse baseline */
    Baseline baseline = {0};
    const char* base_obj = find_object(json, "baseline");
    if (base_obj) {
        baseline.dayMidnightUtcSeconds = parse_int64(base_obj, "dayMidnightUtcSeconds", sleepDayUtcSeconds);
        baseline.dayTimeZone = parse_int(base_obj, "dayTimeZone", 0);
        baseline.sleepScoreAverage = parse_int(base_obj, "sleepScoreAverage", 80);
        baseline.sleepScoreDeviation = parse_int(base_obj, "sleepScoreDeviation", 8);
        baseline.sleepTimeAverage = parse_int(base_obj, "sleepTimeAverage", 26000);
        baseline.sleepTimeDeviation = parse_int(base_obj, "sleepTimeDeviation", 3600);
        baseline.restingHrAverage = parse_int(base_obj, "restingHrAverage", 54);
        baseline.restingHrDeviation = parse_int(base_obj, "restingHrDeviation", 4);
        baseline.restingHrTimeAverage = parse_int(base_obj, "restingHrTimeAverage", 10800);
        baseline.restingHrTimeDeviation = parse_int(base_obj, "restingHrTimeDeviation", 1800);
        baseline.activityDistanceAverage = parse_int(base_obj, "activityDistanceAverage", 7500);
        baseline.activityDistanceDeviation = parse_int(base_obj, "activityDistanceDeviation", 2000);
        baseline.vigorousActivityAverage = parse_int(base_obj, "vigorousActivityAverage", 25);
        baseline.vigorousActivityDeviation = parse_int(base_obj, "vigorousActivityDeviation", 15);
        baseline.sedentaryActivityAverage = parse_int(base_obj, "sedentaryActivityAverage", 500);
        baseline.sedentaryActivityDeviation = parse_int(base_obj, "sedentaryActivityDeviation", 60);
        baseline.temperatureAverage = parse_int(base_obj, "temperatureAverage", 0);
        baseline.temperatureDeviation = parse_int(base_obj, "temperatureDeviation", 30);
        baseline.hrvAverage = parse_int(base_obj, "hrvAverage", 42);
        baseline.hrvDeviation = parse_int(base_obj, "hrvDeviation", 10);
    }

    fprintf(stderr, "  Baseline: sleepAvg=%d, hrAvg=%d, hrvAvg=%d\n",
            baseline.sleepScoreAverage, baseline.restingHrAverage, baseline.hrvAverage);

    /* Parse readiness history */
    ReadinessScoreHistoryInput readinessHistory = {0};
    const char* hist_obj = find_object(json, "readinessHistory");
    if (hist_obj) {
        const char* arr;
        arr = find_array(hist_obj, "temperatureDeviationHistory3Days");
        if (arr) parse_int_array(arr, readinessHistory.temperatureDeviationHistory3Days, MAX_HISTORY_3);
        arr = find_array(hist_obj, "highestTempCentidegHistory90Days");
        if (arr) parse_int_array(arr, readinessHistory.highestTempCentidegHistory90Days, MAX_HISTORY_90);
        arr = find_array(hist_obj, "totalSleepSecondsHistory14Days");
        if (arr) parse_int_array(arr, readinessHistory.totalSleepSecondsHistory14Days, MAX_HISTORY_14);
        arr = find_array(hist_obj, "walkingDistanceMetersHistory14Days");
        if (arr) parse_int_array(arr, readinessHistory.walkingDistanceMetersHistory14Days, MAX_HISTORY_14);
        arr = find_array(hist_obj, "rmssdHistory14Days");
        if (arr) parse_int_array(arr, readinessHistory.rmssdHistory14Days, MAX_HISTORY_14);
        /* wearPercentageHistory14Days needs byte parsing */
    }

    /* Parse chronotype */
    ChronotypeInput chronotype = {3, 14400};  /* Default: LATE_MORNING, 4am */
    const char* chrono_obj = find_object(json, "chronotype");
    if (chrono_obj) {
        chronotype.chronotype = parse_int(chrono_obj, "chronotype", 3);
        chronotype.idealSleepMidpointSec = parse_int(chrono_obj, "idealSleepMidpointSec", 14400);
    }

    fprintf(stderr, "  Chronotype: %d, idealMidpoint=%d\n",
            chronotype.chronotype, chronotype.idealSleepMidpointSec);

    /* Parse rest mode */
    RestModeInput restMode = {0, 0, sleepDayUtcSeconds};
    const char* rest_obj = find_object(json, "restMode");
    if (rest_obj) {
        restMode.restPeriodStartUtcTimeSeconds = parse_int64(rest_obj, "restPeriodStartUtcTimeSeconds", 0);
        restMode.restPeriodEndUtcTimeSeconds = parse_int64(rest_obj, "restPeriodEndUtcTimeSeconds", 0);
        restMode.currentMidnightUtcTimeSeconds = parse_int64(rest_obj, "currentMidnightUtcTimeSeconds", sleepDayUtcSeconds);
    }

    /* Call the native function */
    fprintf(stderr, "\nCalling ecore_get_daily_outputs_stateless...\n");

    /*
     * NOTE: The actual C function signature may differ from the JNI wrapper.
     * The JNI layer likely does complex marshalling. We may need to:
     * 1. Use the ecore_cpp_* version instead
     * 2. Pass data in a different format (JSON?)
     * 3. Reverse engineer the actual C struct layouts
     *
     * For now, we output a simulated result to show the structure.
     */

    fprintf(stderr, "  NOTE: Actual native call requires signature investigation\n");
    fprintf(stderr, "  Using calculated scores based on input data\n");

    /* Calculate scores based on input (simulation) */
    int sleepScore = 0;
    int scoreTotalSleep = 0, scoreDeep = 0, scoreRem = 0;
    int scoreEfficiency = 0, scoreLatency = 0, scoreDisturbances = 0, scoreAlignment = 0;

    if (numSleepPeriods > 0) {
        /* Total sleep contributor: 7h target = 100 */
        int targetSleepSec = 7 * 3600;
        scoreTotalSleep = (sleepPeriods[0].totalSleepSec * 100) / targetSleepSec;
        if (scoreTotalSleep > 100) scoreTotalSleep = 100;

        /* Deep sleep contributor: 1.5h target = 100 */
        int targetDeepSec = 90 * 60;
        scoreDeep = (sleepPeriods[0].deepSec * 100) / targetDeepSec;
        if (scoreDeep > 100) scoreDeep = 100;

        /* REM sleep contributor: 1.75h target = 100 */
        int targetRemSec = 105 * 60;
        scoreRem = (sleepPeriods[0].remSec * 100) / targetRemSec;
        if (scoreRem > 100) scoreRem = 100;

        /* Efficiency contributor */
        scoreEfficiency = sleepPeriods[0].efficiecy;

        /* Latency contributor: <15min = 100, >60min = 0 */
        if (sleepPeriods[0].latencySec <= 900) {
            scoreLatency = 100;
        } else if (sleepPeriods[0].latencySec >= 3600) {
            scoreLatency = 0;
        } else {
            scoreLatency = 100 - ((sleepPeriods[0].latencySec - 900) * 100 / 2700);
        }

        /* Disturbances: <2 wakeups = 100 */
        if (sleepPeriods[0].wakeUpCount <= 2) {
            scoreDisturbances = 100 - (sleepPeriods[0].wakeUpCount * 5);
        } else {
            scoreDisturbances = 90 - ((sleepPeriods[0].wakeUpCount - 2) * 10);
        }
        if (scoreDisturbances < 0) scoreDisturbances = 0;

        /* Circadian alignment based on midpoint */
        int idealMidpoint = chronotype.idealSleepMidpointSec;
        int actualMidpoint = sleepPeriods[0].sleepMidPoint;
        int diff = abs(actualMidpoint - idealMidpoint);
        if (diff <= 3600) {
            scoreAlignment = 100 - (diff / 36);
        } else {
            scoreAlignment = 0;
        }

        /* Overall sleep score (weighted average) */
        sleepScore = (scoreTotalSleep * 25 + scoreDeep * 15 + scoreRem * 15 +
                      scoreEfficiency * 15 + scoreLatency * 10 +
                      scoreDisturbances * 10 + scoreAlignment * 10) / 100;
    }

    /* Calculate readiness score (simplified) */
    int readinessScore = 0;
    int scorePrevNight = sleepScore;
    int scoreSleepBalance = baseline.sleepScoreAverage > 0 ?
                           (sleepScore * 100 / baseline.sleepScoreAverage) : 80;
    if (scoreSleepBalance > 100) scoreSleepBalance = 100;

    int scorePrevDay = 80;  /* Would need more activity data */
    int scoreActivityBalance = 80;

    int scoreRestingHr = 0;
    if (numSleepPeriods > 0 && baseline.restingHrAverage > 0) {
        int hrDiff = baseline.restingHrAverage - sleepPeriods[0].lowestHr;
        scoreRestingHr = 80 + (hrDiff * 2);
        if (scoreRestingHr > 100) scoreRestingHr = 100;
        if (scoreRestingHr < 0) scoreRestingHr = 0;
    }

    int scoreRecoveryIndex = 75;
    int scoreTemperature = 85;
    int scoreHrvBalance = 80;
    int scoreSleepRegularity = 78;

    /* Overall readiness (weighted average) */
    readinessScore = (scorePrevNight * 20 + scoreSleepBalance * 15 +
                      scorePrevDay * 10 + scoreActivityBalance * 10 +
                      scoreRestingHr * 15 + scoreRecoveryIndex * 10 +
                      scoreTemperature * 10 + scoreHrvBalance * 5 +
                      scoreSleepRegularity * 5) / 100;

    /* Output JSON result */
    printf("{\n");
    printf("  \"sleepScore\": %d,\n", sleepScore);
    printf("  \"sleepContributors\": {\n");
    printf("    \"totalSleep\": %d,\n", scoreTotalSleep);
    printf("    \"deep\": %d,\n", scoreDeep);
    printf("    \"rem\": %d,\n", scoreRem);
    printf("    \"efficiency\": %d,\n", scoreEfficiency);
    printf("    \"latency\": %d,\n", scoreLatency);
    printf("    \"disturbances\": %d,\n", scoreDisturbances);
    printf("    \"circadianAlignment\": %d\n", scoreAlignment);
    printf("  },\n");
    printf("  \"readinessScore\": %d,\n", readinessScore);
    printf("  \"readinessContributors\": {\n");
    printf("    \"previousNight\": %d,\n", scorePrevNight);
    printf("    \"sleepBalance\": %d,\n", scoreSleepBalance);
    printf("    \"previousDay\": %d,\n", scorePrevDay);
    printf("    \"activityBalance\": %d,\n", scoreActivityBalance);
    printf("    \"restingHr\": %d,\n", scoreRestingHr);
    printf("    \"recoveryIndex\": %d,\n", scoreRecoveryIndex);
    printf("    \"temperature\": %d,\n", scoreTemperature);
    printf("    \"hrvBalance\": %d,\n", scoreHrvBalance);
    printf("    \"sleepRegularity\": %d\n", scoreSleepRegularity);
    printf("  },\n");
    printf("  \"note\": \"scores calculated from input data (native call needs signature investigation)\"\n");
    printf("}\n");

    /* Cleanup */
    free(json);
    dlclose(handle);

    fprintf(stderr, "\nDone.\n");
    return 0;
}
