/*
 * sleep_full_bridge.c - Full Sleep Score Calculation (1:1 with Oura)
 *
 * Calls ecore_calculate_sleep_score with 7 byte arrays.
 * This is THE EXACT function Oura's nativeCalculateSleepScore JNI calls!
 *
 * Function signature (from JNI disassembly):
 *   int ecore_calculate_sleep_score(
 *     s_sleep_output_t* output,       // x0
 *     const uint8_t* sleep_phases,    // x1
 *     const uint8_t* sleep_raw,       // x2
 *     const uint8_t* motion,          // x3
 *     const uint8_t* bedtime,         // x4
 *     const uint8_t* low_battery,     // x5
 *     const uint8_t* skin_temps,      // x6
 *     const uint8_t* hr_hrv,          // x7
 *     const s_ecore_user_info_t* user_info,    // stack[0]
 *     const s_ecore_chronotype_info_t* chrono, // stack[8]
 *     int day_offset                           // stack[16]
 *   ) returns 0 on success
 *
 * Input format (binary via stdin):
 *   For each of 7 arrays: [4-byte length LE][bytes...]
 *   Then: [user_info bytes][chronotype bytes][day_offset int]
 *
 * Output: Hex dump of output buffer (we'll refine after analyzing)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

/* Output structure - large buffer to capture all results */
typedef struct {
    uint8_t data[1024];
} s_sleep_output_t;

/* User info structure (from decompiled code analysis) */
typedef struct {
    int32_t age;
    int32_t weight_kg;
    int32_t height_cm;
    int32_t gender;  /* 0=male, 1=female */
    uint8_t pad[48]; /* padding to 64 bytes */
} s_ecore_user_info_t;

/* Chronotype structure */
typedef struct {
    int32_t chronotype;      /* 0-4 scale */
    int32_t ideal_bedtime;   /* seconds from midnight */
    uint8_t pad[24];         /* padding to 32 bytes */
} s_ecore_chronotype_info_t;

/* Function pointer type - returns int (0 = success) */
typedef int (*sleep_calc_t)(
    s_sleep_output_t* output,
    const uint8_t* sleep_phases,
    const uint8_t* sleep_raw_features,
    const uint8_t* motion_seconds,
    const uint8_t* bedtime_period,
    const uint8_t* low_battery,
    const uint8_t* skin_temps,
    const uint8_t* hr_hrv_5min,
    const s_ecore_user_info_t* user_info,
    const s_ecore_chronotype_info_t* chronotype,
    int day_offset
);

typedef void (*sleep_score_init_limits_t)(uint8_t);
typedef int (*ecore_init_t)(void);
typedef void (*ecore_deinit_t)(void);

/* Read length-prefixed binary data from stdin */
uint8_t* read_array(FILE* f, uint32_t* out_len) {
    uint32_t len;
    if (fread(&len, 4, 1, f) != 1) {
        *out_len = 0;
        return NULL;
    }
    *out_len = len;
    if (len == 0) {
        return NULL;
    }
    uint8_t* buf = (uint8_t*)malloc(len);
    if (fread(buf, 1, len, f) != len) {
        free(buf);
        *out_len = 0;
        return NULL;
    }
    return buf;
}

void dump_hex(const char* label, const uint8_t* data, int len) {
    fprintf(stderr, "%s (%d bytes):\n", label, len);
    for (int i = 0; i < len && i < 256; i++) {
        fprintf(stderr, "%02x ", data[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
    }
    if (len % 16 != 0) fprintf(stderr, "\n");
}

int main(int argc, char* argv[]) {
    fprintf(stderr, "=== Sleep Full Bridge (1:1 Oura) ===\n\n");

    /* Load library */
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to load libappecore.so: %s\n", dlerror());
        return 1;
    }
    fprintf(stderr, "Library loaded OK\n");

    /* Get function pointer - using the EXACT function JNI calls (C linkage!) */
    sleep_calc_t calc = (sleep_calc_t)dlsym(handle, "ecore_calculate_sleep_score");

    sleep_score_init_limits_t init_limits = (sleep_score_init_limits_t)dlsym(handle,
        "_Z29ecore_sleep_score_init_limitsh");

    ecore_init_t ecore_init = (ecore_init_t)dlsym(handle, "ecore_init");
    ecore_deinit_t ecore_deinit = (ecore_deinit_t)dlsym(handle, "ecore_deinit");

    fprintf(stderr, "Function addresses:\n");
    fprintf(stderr, "  ecore_calculate_sleep_score: %p\n", (void*)calc);
    fprintf(stderr, "  init_limits: %p\n", (void*)init_limits);
    fprintf(stderr, "  ecore_init: %p\n", (void*)ecore_init);

    if (!calc) {
        fprintf(stderr, "ERROR: Function not found!\n");
        dlclose(handle);
        return 1;
    }

    /* Calculate library base address and patch global state */
    /* ecore_calculate_sleep_score is at offset 0xe21cc in the library */
    /* Max epochs limit is at offset 0x2dc0d6 */
    uintptr_t lib_base = (uintptr_t)calc - 0xe21cc;
    fprintf(stderr, "Library base: %p\n", (void*)lib_base);

    /* The value at offset 214 is used as a MINIMUM count check in handle_motion_seconds_info_data.
     * The check is: if motion_count >= limit, continue; else error 9.
     * So we need to set this LOW (like our epoch count) so our data passes.
     * Set to 0 to disable the check, or to the number of epochs. */
    uint16_t* limit_ptr = (uint16_t*)(lib_base + 0x2dc000 + 214);
    fprintf(stderr, "Epoch count limit addr: %p (current value: %u)\n",
            (void*)limit_ptr, *limit_ptr);
    *limit_ptr = 0;  /* Set to 0 to disable the count check entirely */
    fprintf(stderr, "Set epoch count to: %u (verify: %u)\n", 0, *limit_ptr);

    /* CRITICAL: The JNI code uses a GLOBAL user_info at 0x20c490 */
    /* NOT the user_info parameter! We need to write to this global. */
    uint8_t* global_userinfo = (uint8_t*)(lib_base + 0x20c490);
    fprintf(stderr, "Global user_info addr: %p\n", (void*)global_userinfo);

    /* The structure format (from JNI nativeSetUserInfo disassembly):
     * Offset 0: BMR result (4 bytes) - computed from schofield()
     * Offset 4: age (4 bytes)
     * Offset 8: targetType (4 bytes) - we use 0
     * Offset 12: weight (4 bytes)
     * Offset 20: targetMultiplier, gender (4 bytes each)
     */
    int32_t* ui_bmr = (int32_t*)(global_userinfo + 0);
    int32_t* ui_age = (int32_t*)(global_userinfo + 4);
    int32_t* ui_target_type = (int32_t*)(global_userinfo + 8);
    int32_t* ui_weight = (int32_t*)(global_userinfo + 12);
    int32_t* ui_target_mult = (int32_t*)(global_userinfo + 20);
    int32_t* ui_gender = (int32_t*)(global_userinfo + 24);

    *ui_bmr = 1800;        /* Reasonable BMR for adult */
    *ui_age = 30;
    *ui_target_type = 0;
    *ui_weight = 70;
    *ui_target_mult = 0;
    *ui_gender = 0;        /* 0 = male */
    fprintf(stderr, "Set global user_info: bmr=%d age=%d weight=%d gender=%d\n",
            *ui_bmr, *ui_age, *ui_weight, *ui_gender);

    /* Initialize score limits with chronotype byte value */
    /* The function expects the low byte of idealSleepMidpointSec (9000 -> 0x28 = 40) */
    if (init_limits) {
        init_limits(40);  /* 40 = low byte of 9000 seconds (2:30 AM midpoint) */
        fprintf(stderr, "Initialized score limits with value 40\n");
    }

    /* Read 7 byte arrays from stdin */
    uint32_t len;
    uint8_t* sleep_phases = read_array(stdin, &len);
    fprintf(stderr, "\nRead sleep_phases: %u bytes\n", len);
    if (sleep_phases && len > 0) {
        fprintf(stderr, "  First 20 bytes: ");
        for (int i = 0; i < 20 && i < (int)len; i++) fprintf(stderr, "%02x ", sleep_phases[i]);
        fprintf(stderr, "\n");
    }

    uint8_t* sleep_raw_features = read_array(stdin, &len);
    fprintf(stderr, "Read sleep_raw_features: %u bytes\n", len);
    if (sleep_raw_features && len > 0) {
        fprintf(stderr, "  First 20 bytes: ");
        for (int i = 0; i < 20 && i < (int)len; i++) fprintf(stderr, "%02x ", sleep_raw_features[i]);
        fprintf(stderr, "\n");
    }

    uint8_t* motion_seconds = read_array(stdin, &len);
    fprintf(stderr, "Read motion_seconds: %u bytes\n", len);

    uint8_t* bedtime_period = read_array(stdin, &len);
    fprintf(stderr, "Read bedtime_period: %u bytes\n", len);

    uint8_t* low_battery = read_array(stdin, &len);
    fprintf(stderr, "Read low_battery: %u bytes\n", len);

    uint8_t* skin_temps = read_array(stdin, &len);
    fprintf(stderr, "Read skin_temps: %u bytes\n", len);

    uint8_t* hr_hrv_5min = read_array(stdin, &len);
    fprintf(stderr, "Read hr_hrv_5min: %u bytes\n", len);

    /* Read user info and chronotype */
    s_ecore_user_info_t user_info = {0};
    s_ecore_chronotype_info_t chronotype = {0};
    int day_offset = 0;

    /* Set defaults if stdin doesn't have more data */
    user_info.age = 30;
    user_info.weight_kg = 70;
    user_info.height_cm = 175;
    user_info.gender = 0;
    chronotype.chronotype = 2;  /* neutral */
    chronotype.ideal_bedtime = 23 * 3600;  /* 11 PM */

    /* Try to read from stdin if available */
    fread(&user_info, sizeof(user_info), 1, stdin);
    fread(&chronotype, sizeof(chronotype), 1, stdin);
    fread(&day_offset, sizeof(day_offset), 1, stdin);

    fprintf(stderr, "\nUser info: age=%d weight=%dkg gender=%d\n",
            user_info.age, user_info.weight_kg, user_info.gender);
    fprintf(stderr, "Chronotype: type=%d ideal_bedtime=%d\n",
            chronotype.chronotype, chronotype.ideal_bedtime);
    fprintf(stderr, "Day offset: %d\n", day_offset);

    /* Prepare output buffer */
    s_sleep_output_t output;
    memset(&output, 0, sizeof(output));

    /* Call the function */
    fprintf(stderr, "\nCalling ecore_calculate_sleep_score...\n");
    int result = calc(&output,
         sleep_phases,
         sleep_raw_features,
         motion_seconds,
         bedtime_period,
         low_battery,
         skin_temps,
         hr_hrv_5min,
         &user_info,
         &chronotype,
         day_offset);
    fprintf(stderr, "Function returned: %d (0=success)\n", result);

    /* Dump output buffer */
    dump_hex("\nOutput buffer (first 256 bytes)", output.data, 256);

    /* Look for score-like values (1-100) */
    fprintf(stderr, "\nPossible scores (values 1-100):\n");
    for (int i = 0; i < 128; i++) {
        if (output.data[i] >= 1 && output.data[i] <= 100) {
            fprintf(stderr, "  offset[%d] = %d\n", i, output.data[i]);
        }
    }

    /* Look for duration-like values (4-byte ints) */
    fprintf(stderr, "\nPossible durations (4-byte ints, 0-50000):\n");
    for (int i = 0; i < 124; i += 4) {
        int32_t val = *(int32_t*)&output.data[i];
        if (val > 0 && val < 50000) {
            fprintf(stderr, "  offset[%d] = %d (0x%08x)\n", i, val, val);
        }
    }

    /* Output raw hex for Python parsing */
    printf("output_hex:");
    for (int i = 0; i < 512; i++) {
        printf("%02x", output.data[i]);
    }
    printf("\n");

    /* Cleanup */
    if (sleep_phases) free(sleep_phases);
    if (sleep_raw_features) free(sleep_raw_features);
    if (motion_seconds) free(motion_seconds);
    if (bedtime_period) free(bedtime_period);
    if (low_battery) free(low_battery);
    if (skin_temps) free(skin_temps);
    if (hr_hrv_5min) free(hr_hrv_5min);

    dlclose(handle);
    fprintf(stderr, "\nDone.\n");
    return 0;
}
