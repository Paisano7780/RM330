# Frida Scripts for DJI RM330 Research

This directory contains Frida scripts for dynamic instrumentation and analysis of the DJI Fly application on the DJI RM330 remote controller.

⚠️ **DISCLAIMER: These scripts are for educational and security research purposes only. Use at your own risk.**

## Prerequisites

1. **Rooted Android Device** (DJI RM330 controller)
2. **Frida Server** installed on the device
3. **Frida Tools** installed on your computer:
   ```bash
   pip install frida-tools
   ```

## Available Scripts

### 1. frida_hook.py
**Python-based hook script for basic feature unlocking**

Demonstrates runtime hooking of the DJI Fly app to bypass feature restrictions.

**Usage:**
```bash
python frida_hook.py
```

**What it does:**
- Hooks `FeatureManager.isFeatureEnabled()` to enable all features
- Spoofs product type to unlock Pro features
- Bypasses license validation

### 2. advanced_hook.js
**Advanced JavaScript hook for class discovery**

Enumerates loaded classes and discovers feature-related functionality.

**Usage:**
```bash
frida -U -f dji.go.v5 -l advanced_hook.js --no-pause
```

**Features:**
- Automatic class enumeration
- Method discovery
- Multi-target hooking
- Detailed logging

### 3. feature_enum.js
**Simple feature enumeration script**

Logs all feature checks made by the DJI Fly app to help identify available features.

**Usage:**
```bash
frida -U -f dji.go.v5 -l feature_enum.js --no-pause
```

**Output:**
Lists all unique features checked by the app during use.

## Setup Instructions

### Step 1: Install Frida Server on RM330

```bash
# Download Frida server for your device architecture
# Usually arm64 for modern Android devices
wget https://github.com/frida/frida/releases/download/16.0.0/frida-server-16.0.0-android-arm64.xz
unxz frida-server-16.0.0-android-arm64.xz

# Push to device
adb push frida-server-16.0.0-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start server (requires root)
adb shell
su
/data/local/tmp/frida-server &
```

### Step 2: Install Frida Tools on Computer

```bash
pip install -r requirements.txt
```

### Step 3: Verify Setup

```bash
# Check if device is detected
frida-ps -U

# Should list running processes on the device
```

### Step 4: Run Scripts

```bash
# Option 1: Use Python script
python frida-scripts/frida_hook.py

# Option 2: Use JavaScript directly
frida -U -f dji.go.v5 -l frida-scripts/advanced_hook.js --no-pause

# Option 3: Enumerate features
frida -U -f dji.go.v5 -l frida-scripts/feature_enum.js --no-pause
```

## Understanding the Output

### Hook Success Indicators
- `[✓]` - Hook installed successfully
- `[+]` - Feature/method intercepted
- `[!]` - Warning or error (expected if class doesn't exist)

### Common Messages
```
[+] Feature check intercepted: ActiveTrack
[+] Original result: false
[+] Forcing feature to enabled
```

This indicates that a feature check was intercepted and the result was modified.

## Troubleshooting

### "frida-server not running"
**Solution:** Start frida-server on the device as root

### "Process not found: dji.go.v5"
**Solution:** Ensure DJI Fly app is installed. Check package name with:
```bash
adb shell pm list packages | grep dji
```

### Hooks not working
**Possible causes:**
1. Class names may have changed (DJI updates the app)
2. Code is obfuscated differently
3. Different app version

**Solution:** Use the advanced_hook.js script to discover actual class names, then update the hooks.

## Safety Warnings

⚠️ **DO NOT:**
- Disable safety features (RTH, battery warnings, altitude limits)
- Use modified app for actual flights without thorough testing
- Fly in restricted areas or violate regulations
- Share modified APKs publicly

✅ **DO:**
- Test in safe, controlled environments
- Keep backups of original app
- Understand what each hook does
- Use for research and learning
- Respect aviation laws

## Legal Notice

These scripts are provided for educational and security research purposes only. 

- Modifying the DJI Fly app may void your warranty
- May violate DJI's Terms of Service
- User assumes all responsibility for consequences
- Ensure compliance with local drone regulations

## Further Reading

- See [PRACTICAL_GUIDE.md](../PRACTICAL_GUIDE.md) for comprehensive research methodology
- See [SECURITY_ANALYSIS.md](../SECURITY_ANALYSIS.md) for security architecture details
- Official Frida documentation: https://frida.re/docs/

## Contributing

If you discover new hooks or improvements:
1. Test thoroughly
2. Document the changes
3. Ensure safety features remain functional
4. Submit a pull request

---

**Last Updated:** November 18, 2025  
**Frida Version:** 16.0.0+  
**DJI Fly Package:** dji.go.v5
