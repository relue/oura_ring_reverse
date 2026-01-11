# Bluetooth Troubleshooting Guide

## Current Issue
`BleakError: Failed to start scanner. Is Bluetooth turned on?`

Even though:
- ✓ Bluetooth is enabled in Windows
- ✓ AirPods can connect (proving Bluetooth works)
- ✓ Bleak is installed correctly

## Solutions to Try (In Order)

### Solution 1: Windows 11 Manual Scan Workaround ⭐ MOST LIKELY

**Problem:** Windows 11 sometimes blocks BLE scanning unless a manual scan is active.

**Steps:**
1. Open **Windows Settings** → **Bluetooth & devices**
2. Click **"Add device"** → **"Bluetooth"**
3. **KEEP THIS WINDOW OPEN** (it's now scanning)
4. In a **separate** window/terminal, run:
   ```bash
   cd /home/picke/reverse_oura
   cmd.exe /c "C:\Users\picke\AppData\Local\Python\bin\python.exe $(wslpath -w scan_ble.py)"
   ```
5. The Python scan should work now!

---

### Solution 2: Privacy Settings

**Problem:** Windows privacy settings blocking app access to Bluetooth.

**Steps:**
1. **Windows Settings** → **Privacy & security** → **Bluetooth**
2. Enable:
   - ✓ "Let apps access Bluetooth"
   - ✓ "Let desktop apps access Bluetooth"
3. Restart Python script

---

### Solution 3: Run as Administrator

**Problem:** Python lacks permissions to access Bluetooth APIs.

**Steps:**
1. Right-click on **PowerShell** or **Command Prompt**
2. Select **"Run as administrator"**
3. Navigate to `C:\Users\picke\reverse_oura\` (or `\\wsl.localhost\Ubuntu\home\picke\reverse_oura\`)
4. Run:
   ```
   python scan_ble.py
   ```

---

### Solution 4: Restart Bluetooth Service

**Problem:** Bluetooth service in inconsistent state.

**Steps:**
1. Press **Win+R** → type `services.msc` → OK
2. Find **"Bluetooth Support Service"**
3. Right-click → **Restart**
4. Try Python script again

---

### Solution 5: Disable Power Management

**Problem:** Windows turning off Bluetooth adapter to save power.

**Steps:**
1. **Device Manager** (Win+X → Device Manager)
2. Expand **Bluetooth**
3. Right-click your Bluetooth adapter → **Properties**
4. **Power Management** tab
5. **Uncheck** "Allow the computer to turn off this device to save power"
6. OK → Try script again

---

### Solution 6: USB Dongle Specific

**If using USB Bluetooth dongle:**

1. **Check Device Manager:**
   - Win+X → Device Manager
   - Look under **Bluetooth** - Is your dongle listed?
   - Look under **Universal Serial Bus controllers** - Do you see it?

2. **Try different USB port:**
   - Unplug dongle
   - Plug into different USB port (preferably USB 2.0 if available)
   - Wait for Windows to recognize it

3. **Update drivers:**
   - Device Manager → Bluetooth → Right-click adapter → Update driver
   - Select "Search automatically for drivers"

---

## Quick Test After Each Fix

Run this to test if Bluetooth is now accessible:

```bash
cd /home/picke/reverse_oura
cmd.exe /c "C:\Users\picke\AppData\Local\Python\bin\python.exe $(wslpath -w test_bluetooth.py)"
```

Should show:
```
[OK] Bleak imported successfully
[OK] WinRT backend available
[OK] Scanner object created
[OK] Scanner started successfully - Bluetooth IS working!
```

---

## Still Not Working?

If none of the above work, the issue might be:

1. **Windows 11 S Mode** - Blocks some app functionality
   - Check: Settings → System → About → Check if S mode is enabled
   - Solution: Switch out of S mode

2. **Corporate/Managed PC** - Group policies blocking Bluetooth
   - Check with IT if this is a work computer

3. **Virtual Machine** - Bluetooth passthrough issues
   - WSL2 is technically a VM
   - Try running Python directly from Windows (not through WSL)

4. **Incompatible Bluetooth adapter**
   - Some very old Bluetooth 2.0 adapters don't support BLE
   - Need Bluetooth 4.0+ for BLE

---

## Alternative: Run Directly from Windows

Instead of running through WSL, try running Python directly in Windows:

1. Open **PowerShell** or **Command Prompt**
2. Navigate:
   ```
   cd \\wsl.localhost\Ubuntu\home\picke\reverse_oura
   ```
3. Run:
   ```
   C:\Users\picke\AppData\Local\Python\bin\python.exe scan_ble.py
   ```

This eliminates WSL as a potential complication.
