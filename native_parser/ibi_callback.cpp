/*
 * ibi_callback.cpp - Callback implementation for IBI correction
 *
 * This provides the process_corrected_ibi function that libappecore.so calls
 * when it has corrected IBI data. Uses C++ to get proper name mangling.
 *
 * Compile: aarch64-linux-android35-clang++ -shared -fPIC -o libibi_callback.so ibi_callback.cpp
 */

#include <cstdio>
#include <cstdint>

// Validity indicator enum (matching rr_validity_indicator_t)
enum rr_validity_indicator_t : uint32_t {
    RR_VALID = 0,
    RR_INVALID = 1,
    RR_INTERPOLATED = 2,
    // Add more values as discovered
};

// Global storage for corrected IBI data
#define MAX_CORRECTED_IBI 100000
static uint16_t corrected_ibi[MAX_CORRECTED_IBI];
static uint16_t corrected_amp[MAX_CORRECTED_IBI];
static uint64_t corrected_ts[MAX_CORRECTED_IBI];
static uint8_t corrected_validity[MAX_CORRECTED_IBI];
static int corrected_count = 0;

// This function is called by libappecore.so when it has corrected IBI data
// C++ signature to match mangled name: _Z21process_corrected_ibitt23rr_validity_indicator_tm
// process_corrected_ibi(unsigned short, unsigned short, rr_validity_indicator_t, unsigned long)
extern "C" void _Z21process_corrected_ibitt23rr_validity_indicator_tm(
    uint16_t ibi, uint16_t amplitude, rr_validity_indicator_t validity, uint64_t timestamp
) {
    if (corrected_count < MAX_CORRECTED_IBI) {
        corrected_ibi[corrected_count] = ibi;
        corrected_amp[corrected_count] = amplitude;
        corrected_validity[corrected_count] = static_cast<uint8_t>(validity);
        corrected_ts[corrected_count] = timestamp;
        corrected_count++;

        // Debug output
        fprintf(stderr, "  [callback] IBI=%u, amp=%u, validity=%d, ts=%lu\n",
                ibi, amplitude, static_cast<int>(validity), timestamp);
    }
}


// Also provide process_corrected_ibi_and_amplitude
// C++ mangled: _Z35process_corrected_ibi_and_amplitudett23rr_validity_indicator_tm
extern "C" void _Z35process_corrected_ibi_and_amplitudett23rr_validity_indicator_tm(
    uint16_t ibi, uint16_t amplitude, rr_validity_indicator_t validity, uint64_t timestamp
) {
    _Z21process_corrected_ibitt23rr_validity_indicator_tm(ibi, amplitude, validity, timestamp);
}


// C interface for the bridge
extern "C" {
    int get_corrected_count() {
        return corrected_count;
    }

    void reset_corrected_data() {
        corrected_count = 0;
    }

    void get_corrected_data(int index, uint16_t* ibi, uint16_t* amp, uint64_t* ts, uint8_t* validity) {
        if (index >= 0 && index < corrected_count) {
            *ibi = corrected_ibi[index];
            *amp = corrected_amp[index];
            *ts = corrected_ts[index];
            *validity = corrected_validity[index];
        }
    }
}
