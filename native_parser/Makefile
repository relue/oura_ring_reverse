# Makefile for native parser bridge
#
# This builds an ARM64 binary that can call Oura's libringeventparser.so
# Run with QEMU on x86 Linux

CC = aarch64-linux-gnu-gcc
CFLAGS = -Wall -g -O2
LDFLAGS = -ldl

# Path to Oura's native libraries
OURA_LIBS = ../android_app/app/src/main/jniLibs/arm64-v8a
APPECORE_LIBS = ../_large_files/native/lib/arm64-v8a

# Test data file
TEST_DATA = ../analysis_scripts/ring_events_20260112_092318.txt

.PHONY: all clean test test-load check-deps ibi-test

all: parser_bridge ibi_correction_bridge sleep_full_bridge liblog.so libc_stub.so

# Build sleep full bridge (for calling ecore_sleep_final_calculate_sleep)
sleep_full_bridge: sleep_full_bridge.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

# Build liblog.so stub (provides __android_log_* functions)
liblog.so: bionic_stub.c
	$(CC) -shared -fPIC -o $@ $<

# Build libc stub for android_set_abort_message
libc_stub.so: libc_stub.c
	$(CC) -shared -fPIC -o $@ $<

# Build the parser bridge (glibc version - for testing only)
parser_bridge: parser_bridge.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Android NDK settings
NDK_PATH ?= $(HOME)/Android/Sdk/ndk/29.0.14206865
NDK_CLANG = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang

# Build parser_bridge_android with Android NDK (required for QEMU + android_root)
# This links against Android bionic libc, not glibc
parser_bridge_android: parser_bridge.c
	@if [ ! -f "$(NDK_CLANG)" ]; then \
		echo "ERROR: Android NDK not found at $(NDK_PATH)"; \
		echo "Install NDK or set NDK_PATH=<path>"; \
		exit 1; \
	fi
	$(NDK_CLANG) -Wall -O2 $< -o $@ -ldl
	@echo "Built $@ with Android NDK"

# Build IBI correction bridge (uses libappecore.so)
ibi_correction_bridge: ibi_correction_bridge.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Test IBI correction
ibi-test: ibi_correction_bridge liblog.so libc_stub.so
	@echo ""
	@echo "=== Testing IBI correction bridge ==="
	LD_LIBRARY_PATH=.:$(APPECORE_LIBS):/usr/aarch64-linux-gnu/lib \
	qemu-aarch64 -L /usr/aarch64-linux-gnu ./ibi_correction_bridge

# Check if required tools are installed
check-deps:
	@echo "Checking dependencies..."
	@which aarch64-linux-gnu-gcc > /dev/null || (echo "ERROR: Install aarch64-linux-gnu-gcc" && exit 1)
	@which qemu-aarch64 > /dev/null || (echo "ERROR: Install qemu-user or qemu-user-static" && exit 1)
	@test -f $(OURA_LIBS)/libringeventparser.so || (echo "ERROR: Oura libraries not found in $(OURA_LIBS)" && exit 1)
	@echo "All dependencies OK"

# Test just loading the libraries (no parsing)
test-load: all check-deps
	@echo ""
	@echo "=== Testing library load under QEMU ==="
	@echo "LD_LIBRARY_PATH=.:$(OURA_LIBS)"
	@echo ""
	LD_LIBRARY_PATH=.:$(OURA_LIBS) \
	LD_PRELOAD=./libc_stub.so \
	qemu-aarch64 -L /usr/aarch64-linux-gnu ./parser_bridge --help 2>&1 || true

# Full test with actual data
test: all check-deps
	@echo ""
	@echo "=== Testing parser with ring events ==="
	@test -f $(TEST_DATA) || (echo "ERROR: Test data not found: $(TEST_DATA)" && exit 1)
	LD_LIBRARY_PATH=.:$(OURA_LIBS) \
	LD_PRELOAD=./libc_stub.so \
	qemu-aarch64 -L /usr/aarch64-linux-gnu ./parser_bridge $(TEST_DATA)

# Run and save protobuf output
run: all
	@test -f $(INPUT) || (echo "Usage: make run INPUT=<events_file>" && exit 1)
	LD_LIBRARY_PATH=.:$(OURA_LIBS) \
	LD_PRELOAD=./libc_stub.so \
	qemu-aarch64 -L /usr/aarch64-linux-gnu ./parser_bridge $(INPUT)

# Run and save protobuf to file
save-proto: all
	@test -f $(TEST_DATA) || (echo "ERROR: Test data not found" && exit 1)
	LD_LIBRARY_PATH=.:$(OURA_LIBS) \
	LD_PRELOAD=./libc_stub.so \
	qemu-aarch64 -L /usr/aarch64-linux-gnu ./parser_bridge $(TEST_DATA) > ring_data.pb 2>parse.log
	@echo "Protobuf saved to ring_data.pb"
	@echo "Log saved to parse.log"
	@ls -la ring_data.pb

clean:
	rm -f parser_bridge ibi_correction_bridge liblog.so libc_stub.so ring_data.pb parse.log

# Debug: show what symbols the libraries need
show-symbols:
	@echo "=== Undefined symbols in libringeventparser.so ==="
	nm -Du $(OURA_LIBS)/libringeventparser.so 2>/dev/null | head -50
	@echo ""
	@echo "=== Bionic-specific symbols (need stubs) ==="
	nm -Du $(OURA_LIBS)/libringeventparser.so 2>/dev/null | grep -E "android|__android" || echo "(none found)"

# Debug: show library dependencies
show-deps:
	@echo "=== Library dependencies ==="
	readelf -d $(OURA_LIBS)/libringeventparser.so | grep NEEDED
	@echo ""
	readelf -d $(OURA_LIBS)/libprotobuf-lite.so | grep NEEDED
