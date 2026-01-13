/*
 * ibi_callback.c - Callback implementation for IBI correction
 *
 * This provides the process_corrected_ibi function that libappecore.so calls
 * when it has corrected IBI data.
 *
 * Compile: aarch64-linux-android35-clang -shared -fPIC -o libibi_callback.so ibi_callback.c
 */

#include <stdio.h>
#include <stdint.h>

// Validity indicator enum (matching rr_validity_indicator_t)
typedef enum {
    RR_VALID = 0,
    RR_INVALID = 1,
    RR_INTERPOLATED = 2,
    // Add more values as discovered
} rr_validity_indicator_t;

// Global storage for corrected IBI data
#define MAX_CORRECTED_IBI 100000
static uint16_t corrected_ibi[MAX_CORRECTED_IBI];
static uint16_t corrected_amp[MAX_CORRECTED_IBI];
static uint64_t corrected_ts[MAX_CORRECTED_IBI];
static uint8_t corrected_validity[MAX_CORRECTED_IBI];
static int corrected_count = 0;

// This function is called by libappecore.so when it has corrected IBI data
// Signature from symbol: process_corrected_ibi(unsigned short, unsigned short, rr_validity_indicator_t, unsigned long)
void process_corrected_ibi(uint16_t ibi, uint16_t amplitude, rr_validity_indicator_t validity, uint64_t timestamp) {
    if (corrected_count < MAX_CORRECTED_IBI) {
        corrected_ibi[corrected_count] = ibi;
        corrected_amp[corrected_count] = amplitude;
        corrected_validity[corrected_count] = (uint8_t)validity;
        corrected_ts[corrected_count] = timestamp;
        corrected_count++;

        // Debug output
        fprintf(stderr, "  [callback] IBI=%u, amp=%u, validity=%d, ts=%lu\n",
                ibi, amplitude, validity, timestamp);
    }
}

// Also provide process_corrected_ibi_and_amplitude which might be called
void process_corrected_ibi_and_amplitude(uint16_t ibi, uint16_t amplitude, rr_validity_indicator_t validity, uint64_t timestamp) {
    process_corrected_ibi(ibi, amplitude, validity, timestamp);
}

// Function to get the corrected data (called by our bridge)
int get_corrected_count(void) {
    return corrected_count;
}

void reset_corrected_data(void) {
    corrected_count = 0;
}

void get_corrected_data(int index, uint16_t* ibi, uint16_t* amp, uint64_t* ts, uint8_t* validity) {
    if (index < corrected_count) {
        *ibi = corrected_ibi[index];
        *amp = corrected_amp[index];
        *ts = corrected_ts[index];
        *validity = corrected_validity[index];
    }
}
