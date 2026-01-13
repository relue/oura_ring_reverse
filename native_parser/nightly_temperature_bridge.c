/*
 * nightly_temperature_bridge.c - Nightly Temperature Calculation
 *
 * Calculates nightly average temperature from temperature readings.
 *
 * Input format (CSV from stdin):
 *   temp1,temp2,temp3,...  (temperatures in centidegrees Celsius)
 *
 * Output format (CSV to stdout):
 *   nightlyTemperature
 *
 * Example:
 *   echo "3650,3652,3648,3651,3649" | ./nightly_temperature_bridge
 *   3650
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

/* Function pointer type - takes int array, returns int */
typedef int (*nightly_temp_calc_t)(int32_t* temperatures);

#define MAX_TEMPS 1024

int main(int argc, char* argv[]) {
    /* Load library */
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to load libappecore.so: %s\n", dlerror());
        return 1;
    }

    /* Get function pointer - try direct symbol first */
    nightly_temp_calc_t calc = (nightly_temp_calc_t)dlsym(handle,
        "ecore_calculate_nightly_temperature");

    if (!calc) {
        /* Try the JNI wrapper version */
        calc = (nightly_temp_calc_t)dlsym(handle,
            "Java_com_ouraring_ecorelibrary_EcoreWrapper_nativeCalculateNightlyTemperature");
    }

    if (!calc) {
        fprintf(stderr, "ERROR: nightly temperature function not found\n");
        dlclose(handle);
        return 1;
    }

    /* Parse CSV input */
    char line[8192];
    int32_t temps[MAX_TEMPS];
    int count = 0;

    if (fgets(line, sizeof(line), stdin)) {
        char* token = strtok(line, ",\n");
        while (token && count < MAX_TEMPS) {
            temps[count++] = atoi(token);
            token = strtok(NULL, ",\n");
        }
    }

    if (count == 0) {
        fprintf(stderr, "ERROR: No temperature values provided\n");
        dlclose(handle);
        return 1;
    }

    fprintf(stderr, "DEBUG: Processing %d temperature values\n", count);

    /* Call the native function */
    int result = calc(temps);

    fprintf(stderr, "DEBUG: Function returned: %d\n", result);

    /* Output CSV */
    printf("nightlyTemperature\n");
    printf("%d\n", result);

    dlclose(handle);
    return 0;
}
