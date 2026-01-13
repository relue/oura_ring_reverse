#!/bin/bash
#
# setup_android_root.sh - Helper script to set up Android sysroot for QEMU
#
# This script helps create the android_root/ directory needed to run
# ARM64 Android libraries via QEMU on x86 Linux.
#
# Usage:
#   ./setup_android_root.sh [--from-device | --from-emulator | --check]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_ROOT="$SCRIPT_DIR/android_root"

# Required libraries
REQUIRED_LIBS=(
    "libc.so"
    "libm.so"
    "libdl.so"
    "libc++.so"
    "liblog.so"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_qemu() {
    if ! command -v qemu-aarch64 &> /dev/null; then
        error "qemu-aarch64 not found!"
        echo ""
        echo "Install QEMU user-mode emulation:"
        echo "  Debian/Ubuntu: sudo apt install qemu-user qemu-user-binfmt"
        echo "  Arch Linux:    sudo pacman -S qemu-user"
        echo "  Fedora:        sudo dnf install qemu-user"
        return 1
    fi
    info "qemu-aarch64 found: $(which qemu-aarch64)"
    return 0
}

check_adb() {
    if ! command -v adb &> /dev/null; then
        error "adb not found!"
        echo "Install Android SDK platform-tools or use another method."
        return 1
    fi
    info "adb found: $(which adb)"
    return 0
}

create_directories() {
    info "Creating directory structure..."
    mkdir -p "$ANDROID_ROOT/system/bin"
    mkdir -p "$ANDROID_ROOT/system/lib64"
    info "Created $ANDROID_ROOT/system/{bin,lib64}"
}

pull_from_device() {
    info "Pulling libraries from connected Android device..."

    # Check device connection
    if ! adb devices | grep -q "device$"; then
        error "No Android device connected!"
        echo "Connect a device and enable USB debugging, then try again."
        return 1
    fi

    # Pull linker64
    info "Pulling linker64..."
    adb pull /system/bin/linker64 "$ANDROID_ROOT/system/bin/" || {
        warn "Failed to pull linker64, trying with root..."
        adb root && sleep 2
        adb pull /system/bin/linker64 "$ANDROID_ROOT/system/bin/"
    }

    # Pull libraries
    for lib in "${REQUIRED_LIBS[@]}"; do
        info "Pulling $lib..."
        adb pull "/system/lib64/$lib" "$ANDROID_ROOT/system/lib64/" || {
            warn "Failed to pull $lib"
        }
    done

    # Create symlink
    info "Creating ld-android.so symlink..."
    cd "$ANDROID_ROOT/system/lib64"
    ln -sf ../bin/linker64 ld-android.so
    cd "$SCRIPT_DIR"

    info "Done pulling from device!"
}

check_setup() {
    echo ""
    echo "=== Checking android_root setup ==="
    echo ""

    local all_ok=true

    # Check linker64
    if [ -f "$ANDROID_ROOT/system/bin/linker64" ]; then
        info "linker64: OK ($(du -h "$ANDROID_ROOT/system/bin/linker64" | cut -f1))"
    else
        error "linker64: MISSING"
        all_ok=false
    fi

    # Check libraries
    for lib in "${REQUIRED_LIBS[@]}"; do
        if [ -f "$ANDROID_ROOT/system/lib64/$lib" ]; then
            info "$lib: OK ($(du -h "$ANDROID_ROOT/system/lib64/$lib" | cut -f1))"
        else
            error "$lib: MISSING"
            all_ok=false
        fi
    done

    # Check symlink
    if [ -L "$ANDROID_ROOT/system/lib64/ld-android.so" ]; then
        info "ld-android.so symlink: OK"
    else
        error "ld-android.so symlink: MISSING"
        echo "  Create with: cd $ANDROID_ROOT/system/lib64 && ln -sf ../bin/linker64 ld-android.so"
        all_ok=false
    fi

    # Check libappecore.so
    echo ""
    if [ -f "$ANDROID_ROOT/system/lib64/libappecore.so" ]; then
        info "libappecore.so: OK ($(du -h "$ANDROID_ROOT/system/lib64/libappecore.so" | cut -f1))"
    else
        warn "libappecore.so: MISSING"
        echo "  Extract from Oura APK: unzip oura.apk -d oura && cp oura/lib/arm64-v8a/libappecore.so $ANDROID_ROOT/system/lib64/"
    fi

    # Check bridge binary
    echo ""
    if [ -f "$SCRIPT_DIR/ibi_correction_bridge_v9" ]; then
        info "ibi_correction_bridge_v9: OK"
    else
        warn "ibi_correction_bridge_v9: MISSING (needs compilation)"
    fi

    # Summary
    echo ""
    if $all_ok; then
        echo "=== Setup looks good! ==="
        echo ""
        echo "Test with:"
        echo "  cd $SCRIPT_DIR"
        echo "  echo '1000000,1000,13000' | bash run_ibi_correction.sh 2>&1"
    else
        echo "=== Setup incomplete ==="
        echo ""
        echo "See docs/LIBAPPECORE_QEMU_INTEGRATION.md for setup instructions."
    fi
}

show_help() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Set up android_root/ directory for QEMU ARM64 emulation."
    echo ""
    echo "Options:"
    echo "  --from-device    Pull libraries from connected Android device via ADB"
    echo "  --from-emulator  Same as --from-device (works with emulator too)"
    echo "  --check          Check if setup is complete"
    echo "  --help           Show this help"
    echo ""
    echo "Manual setup:"
    echo "  1. Create directories: mkdir -p android_root/system/{bin,lib64}"
    echo "  2. Copy linker64 to android_root/system/bin/"
    echo "  3. Copy libc.so, libm.so, libdl.so, libc++.so, liblog.so to android_root/system/lib64/"
    echo "  4. Create symlink: cd android_root/system/lib64 && ln -sf ../bin/linker64 ld-android.so"
    echo "  5. Copy libappecore.so from Oura APK to android_root/system/lib64/"
    echo ""
    echo "See docs/LIBAPPECORE_QEMU_INTEGRATION.md for detailed instructions."
}

# Main
case "${1:-}" in
    --from-device|--from-emulator)
        check_qemu || exit 1
        check_adb || exit 1
        create_directories
        pull_from_device
        check_setup
        ;;
    --check)
        check_qemu
        check_setup
        ;;
    --help|-h)
        show_help
        ;;
    "")
        show_help
        echo ""
        check_setup
        ;;
    *)
        error "Unknown option: $1"
        show_help
        exit 1
        ;;
esac
