# Transfer Guide: Moving to Another PC

This guide explains how to move the complete Oura Ring reverse engineering project to another computer.

## Two-Part Structure

This project is organized into:
1. **Git-tracked files** (~32MB) - Code, docs, scripts
2. **Large local files** (5.6GB) - APKs, decompiled code, tools

---

## Quick Transfer (Git Only)

If you only need the working code and documentation:

```bash
# On new PC
git clone https://github.com/relue/oura_ring_reverse.git
cd oura_ring_reverse

# Open Android app
cd android_app
# Open in Android Studio

# Run Python client
cd ../python_client
python oura_ble_client.py
```

**This gives you:**
- ✅ Working Android app
- ✅ Python BLE client
- ✅ Complete protocol documentation
- ✅ Frida scripts

---

## Complete Transfer (Everything)

To transfer ALL files including decompiled sources and build tools:

### Method 1: Separate Archive for Large Files

**On current PC:**

```bash
# 1. Clone/pull git repo (or push to GitHub first)
cd ~/oura_ring_reverse
git push origin master

# 2. Create archive of large files only
tar -czf oura_large_files.tar.gz _large_files/
# Creates ~1.5GB compressed file
```

**Transfer both:**
- Git repository (clone from GitHub)
- `oura_large_files.tar.gz` (USB drive, cloud, etc.)

**On new PC:**

```bash
# 1. Clone git repo
git clone https://github.com/relue/oura_ring_reverse.git
cd oura_ring_reverse

# 2. Extract large files
tar -xzf /path/to/oura_large_files.tar.gz
# Extracts to _large_files/ folder
```

### Method 2: Complete Archive

**On current PC:**

```bash
# Archive everything (git + large files)
cd ~
tar -czf oura_ring_complete.tar.gz oura_ring_reverse/
# Creates ~1.5GB file
```

**Transfer via:**
- External USB drive
- Cloud storage (Dropbox, Google Drive, etc.)
- Network transfer

**On new PC:**

```bash
# Extract
tar -xzf oura_ring_complete.tar.gz
cd oura_ring_reverse

# Verify git status
git status
```

---

## What's in Each Part

### Git Repository (~32MB)
```
oura_ring_reverse/
├── docs/                      # All documentation
├── python_client/             # Working Python client
├── android_app/               # Android Studio project
├── frida_scripts/             # Instrumentation scripts
├── README.md
└── .gitignore
```

### _large_files/ Folder (5.6GB - NOT in git)
```
_large_files/
├── apks/
│   ├── Oura_6.14.0_APKPure.xapk    # Original app (252MB)
│   └── extracted/                   # Extracted APK (368MB)
├── decompiled/                      # Decompiled Java sources (843MB)
├── native/                          # Native .so libraries
├── models/                          # ML model files
├── tools/                           # Build tools (4.4GB)
└── patched/                         # Modified APKs
```

---

## Opening Android App on New PC

### Requirements
- Android Studio (Koala or newer)
- Java 17+

### Steps

1. **Open in Android Studio:**
   ```
   File → Open → Navigate to: oura_ring_reverse/android_app/
   ```

2. **Wait for Gradle sync** (first time takes 5-10 minutes)

3. **Build project:**
   ```
   Build → Make Project
   ```

4. **Run on device:**
   - Connect Android device (Android 12+)
   - Click Run ▶️

---

## Python Client on New PC

### Requirements
- Python 3.8+
- pip

### Setup

```bash
cd oura_ring_reverse/python_client

# Install dependencies
pip install bleak

# Run client
python oura_ble_client.py
```

---

## File Sizes

| Component | Size | Transfer Method |
|-----------|------|-----------------|
| Git repo | 32MB | GitHub clone |
| APKs | 252MB | Archive |
| Decompiled code | 843MB | Archive |
| Tools | 4.4GB | Archive (optional) |
| **Total** | **5.6GB** | |

**Compressed:** ~1.5GB with tar.gz

---

## Recommendations

### For Active Development
Transfer both git repo + large files. You'll need decompiled sources for reference.

### For Running Apps Only
Git clone is sufficient. Android app and Python client work standalone.

### Storage Limited
- Git clone only (32MB)
- Skip `tools/` folder (saves 4.4GB)
- Download APK separately if needed later

---

## Verification After Transfer

### Check Git Status
```bash
cd oura_ring_reverse
git status  # Should show "nothing to commit, working tree clean"
git remote -v  # Should show GitHub remote
```

### Check Android App
```bash
cd android_app
./gradlew assembleDebug  # Should build successfully
```

### Check Python Client
```bash
cd python_client
python -c "import bleak; print('OK')"
```

### Verify Large Files (if transferred)
```bash
ls -lh _large_files/apks/Oura_6.14.0_APKPure.xapk
# Should show 252MB file
```

---

## Common Issues

### Git Repo Missing Remote
```bash
git remote add origin https://github.com/relue/oura_ring_reverse.git
```

### Android Studio Can't Find Project
- Ensure you open the `android_app/` folder, not the root
- Check `android_app/build.gradle.kts` exists

### Python Dependencies Missing
```bash
pip install -r python_client/requirements.txt
# Or: pip install bleak
```

---

## Notes

- **_large_files/** is gitignored - never pushed to GitHub
- Original folder locations: `~/reverse_oura/` and `~/AndroidStudioProjects/reverseoura/`
- Git remote: `https://github.com/relue/oura_ring_reverse`
- All commits include your authorship

---

Ready to transfer! Choose the method that fits your needs.
