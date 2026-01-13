/*
 * nightly_temp_bridge_v2.c - Nightly Temperature Calculation (v2)
 *
 * Uses the actual C function: nightly_temperature_calculate(uint16_t*, uint16_t)
 * Not the JNI wrapper that requires Java VM.
 *
 * Input format (CSV from stdin):
 *   temp1,temp2,temp3,...  (temperatures in centidegrees Celsius)
 *
 * Output format (CSV to stdout):
 *   nightlyTemperature
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

/* Function pointer type - real C function */
typedef int (*nightly_temp_calc_t)(uint16_t* temperatures, uint16_t count);

#define MAX_TEMPS 1024

int main(int argc, char* argv[]) {
    /* Load library */
    void* handle = dlopen("libappecore.so", RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to load libappecore.so: %s\n", dlerror());
        return 1;
    }

    /* Get function pointer - use mangled C++ name */
    nightly_temp_calc_t calc = (nightly_temp_calc_t)dlsym(handle,
        "_Z29nightly_temperature_calculatePtt");

    if (!calc) {
        fprintf(stderr, "ERROR: nightly_temperature_calculate function not found\n");
        dlclose(handle);
        return 1;
    }

    /* Parse CSV input */
    char line[8192];
    uint16_t temps[MAX_TEMPS];
    int count = 0;

    if (fgets(line, sizeof(line), stdin)) {
        char* token = strtok(line, ",\n");
        while (token && count < MAX_TEMPS) {
            temps[count++] = (uint16_t)atoi(token);
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
    int result = calc(temps, (uint16_t)count);

    fprintf(stderr, "DEBUG: Function returned: %d\n", result);

    /* Output CSV */
    printf("nightlyTemperature\n");
    printf("%d\n", result);

    dlclose(handle);
    return 0;
}
