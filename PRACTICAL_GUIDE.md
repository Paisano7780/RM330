# Practical Guide: DJI RM330 Feature Research

**⚠️ DISCLAIMER:** This guide is for educational and research purposes only. Proceed at your own risk.

---

## Prerequisites

### Required Tools

1. **Android Debug Bridge (ADB)**
   ```bash
   # Linux/Mac
   sudo apt-get install android-tools-adb
   # or download Android Platform Tools
   ```

2. **APK Analysis Tools**
   ```bash
   # apktool (for decompiling APK)
   sudo apt-get install apktool
   
   # jadx (for viewing Java code)
   wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip
   unzip jadx-1.4.7.zip -d jadx
   ```

3. **Optional: Frida (for runtime hooking)**
   ```bash
   pip install frida-tools
   ```

### Required Knowledge

- Basic understanding of Android
- Command line proficiency
- Patience and willingness to learn

---

## Phase 1: Information Gathering

### Step 1: Enable Developer Mode on RM330

1. Access Settings on the RM330 controller
2. Find "About" section
3. Tap "Build Number" 7 times to enable Developer Options
4. Enable "USB Debugging" in Developer Options

### Step 2: Connect to Computer

```bash
# Connect RM330 via USB
adb devices
# Should show your device
```

### Step 3: Extract DJI Fly APK

```bash
# List installed packages
adb shell pm list packages | grep dji

# Find the full path to the APK
adb shell pm path dji.go.v5

# Example output:
# package:/data/app/dji.go.v5-XXXXX/base.apk

# Pull the APK
adb pull /data/app/dji.go.v5-XXXXX/base.apk dji_fly.apk
```

### Step 4: Extract App Data (Optional)

```bash
# Pull app data (if accessible without root)
adb pull /sdcard/Android/data/dji.go.v5 ./dji_app_data/

# Pull shared preferences if accessible
adb shell run-as dji.go.v5 ls /data/data/dji.go.v5/shared_prefs/
adb shell run-as dji.go.v5 cat /data/data/dji.go.v5/shared_prefs/preferences.xml
```

---

## Phase 2: Static Analysis

### Step 1: Decompile APK

```bash
# Decompile to get resources and smali code
apktool d dji_fly.apk -o dji_decompiled

# View structure
cd dji_decompiled
ls -la
```

### Step 2: Analyze AndroidManifest.xml

```bash
cd dji_decompiled
cat AndroidManifest.xml

# Look for:
# - Permissions
# - Activities
# - Services
# - Receivers
# - Feature flags
```

### Step 3: Search for Feature Strings

```bash
cd dji_decompiled

# Search for common feature strings
grep -r "activetrack" .
grep -r "waypoint" .
grep -r "hyperlapse" .
grep -r "mini.*3" .
grep -r "pro.*model" .
grep -r "feature.*unlock" .
grep -r "enable.*" res/values/strings.xml

# Search for model detection
grep -r "device.*type" .
grep -r "product.*type" .
grep -r "aircraft.*type" .
```

### Step 4: Decompile to Java

```bash
# Use jadx for easier code reading
./jadx/bin/jadx dji_fly.apk -d dji_java

# Navigate the code
cd dji_java
find . -name "*Feature*"
find . -name "*Product*"
find . -name "*Aircraft*"
find . -name "*Permission*"
```

### Step 5: Analyze Key Classes

Look for classes related to:
- Product identification
- Feature management
- Permission checking
- License validation

```bash
cd dji_java/sources

# Common DJI package structures
ls dji/
ls com/dji/

# Example areas to check
find . -path "*/feature/*"
find . -path "*/product/*"
find . -path "*/permission/*"
find . -path "*/config/*"
```

---

## Phase 3: Network Analysis

### Step 1: Set Up Proxy

1. Install Charles Proxy or mitmproxy
2. Configure RM330 to use proxy:
   ```bash
   adb shell settings put global http_proxy <your_ip>:8888
   ```

3. Install SSL certificate on device (for HTTPS)

### Step 2: Capture Traffic

```bash
# Start mitmproxy
mitmproxy -p 8888

# Use the DJI Fly app
# Watch for:
# - Feature check requests
# - License validation
# - Product identification
# - Server responses
```

### Step 3: Analyze API Calls

Look for endpoints like:
- `api.dji.com/*/feature/check`
- `api.dji.com/*/product/info`
- `api.dji.com/*/license/verify`

Document:
- Request parameters
- Response format
- Authentication method

---

## Phase 4: Database Analysis

### Step 1: Locate Databases (requires root or backup)

```bash
# With root
adb shell
su
cd /data/data/dji.go.v5/databases/
ls -la

# Without root (via backup)
adb backup -f dji_backup.ab dji.go.v5
# Convert .ab to tar and extract
```

### Step 2: Analyze SQLite Databases

```bash
# Pull database
adb pull /data/data/dji.go.v5/databases/app.db

# Analyze with sqlite3
sqlite3 app.db
.tables
.schema

# Look for feature-related tables
SELECT * FROM features;
SELECT * FROM settings;
SELECT * FROM config;
```

---

## Phase 5: Runtime Analysis (Requires Root)

### Step 1: Root the RM330 (Research Required)

⚠️ **Warning:** Rooting may void warranty and risk bricking the device.

Search for:
- "RM330 root"
- "DJI controller root"
- Generic Android rooting methods for your device's chipset (Qualcomm)

### Step 2: Install Frida Server

```bash
# Download Frida server for Android
# https://github.com/frida/frida/releases

# Push to device
adb push frida-server-*-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Run as root
adb shell
su
/data/local/tmp/frida-server &
```

### Step 3: Hook DJI Fly App

```python
# frida_hook.py
import frida
import sys

# JavaScript hook
js_code = """
Java.perform(function() {
    // Hook feature check
    var FeatureManager = Java.use('com.dji.feature.FeatureManager');
    FeatureManager.isFeatureEnabled.implementation = function(feature) {
        console.log('[+] Feature check: ' + feature);
        var result = this.isFeatureEnabled(feature);
        console.log('[+] Original result: ' + result);
        // Force enable all features
        return true;
    };
    
    // Hook product type detection
    var ProductManager = Java.use('com.dji.product.ProductManager');
    ProductManager.getProductType.implementation = function() {
        console.log('[+] Product type check');
        var original = this.getProductType();
        console.log('[+] Original product: ' + original);
        // Spoof as Pro model
        return 'Mini3Pro';  // Example
    };
});
"""

# Attach to DJI Fly
device = frida.get_usb_device()
pid = device.spawn(['dji.go.v5'])
session = device.attach(pid)
script = session.create_script(js_code)
script.load()
device.resume(pid)
sys.stdin.read()
```

### Step 4: Test and Refine

```bash
# Run the hook
python frida_hook.py

# Launch DJI Fly
# Observe console output
# Identify successful hooks
# Refine as needed
```

---

## Phase 6: Modification Strategies

### Strategy A: APK Patching (No Root Required)

1. **Decompile APK**
   ```bash
   apktool d dji_fly.apk -o dji_mod
   ```

2. **Modify smali code**
   ```bash
   cd dji_mod
   # Find feature check methods
   find . -name "*.smali" | xargs grep -l "isFeatureEnabled"
   
   # Edit the smali file
   nano ./smali/com/dji/feature/FeatureManager.smali
   
   # Change return value from false to true
   # Before:
   # const/4 v0, 0x0  # false
   # return v0
   
   # After:
   # const/4 v0, 0x1  # true
   # return v0
   ```

3. **Rebuild APK**
   ```bash
   apktool b dji_mod -o dji_modded.apk
   ```

4. **Sign APK**
   ```bash
   # Generate keystore (first time only)
   keytool -genkey -v -keystore my-release-key.jks \
     -keyalg RSA -keysize 2048 -validity 10000 \
     -alias my-key-alias
   
   # Sign APK
   jarsigner -verbose -sigalg SHA256withRSA \
     -digestalg SHA-256 -keystore my-release-key.jks \
     dji_modded.apk my-key-alias
   
   # Align APK
   zipalign -v 4 dji_modded.apk dji_modded_aligned.apk
   ```

5. **Install Modified APK**
   ```bash
   # Uninstall original
   adb uninstall dji.go.v5
   
   # Install modified
   adb install dji_modded_aligned.apk
   ```

⚠️ **Limitations:**
- Loses access to DJI cloud services
- May have integrity checks
- Updates will overwrite modifications

### Strategy B: Xposed Module (Requires Root)

1. **Install Xposed Framework**
   - Flash via custom recovery or use Magisk + LSPosed

2. **Create Xposed Module**
   ```java
   // DJIUnlocker.java
   package com.example.djiunlocker;
   
   import de.robv.android.xposed.*;
   
   public class DJIUnlocker implements IXposedHookLoadPackage {
       public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
           if (!lpparam.packageName.equals("dji.go.v5"))
               return;
           
           // Hook feature checks
           XposedHelpers.findAndHookMethod(
               "com.dji.feature.FeatureManager",
               lpparam.classLoader,
               "isFeatureEnabled",
               String.class,
               new XC_MethodHook() {
                   @Override
                   protected void afterHookedMethod(MethodHookParam param) {
                       // Force all features to be enabled
                       param.setResult(true);
                   }
               }
           );
       }
   }
   ```

3. **Install and enable module**
4. **Reboot device**

### Strategy C: Runtime Hooking with Frida (Most Flexible)

See Phase 5, Step 3 for basic hook.

**Advanced Hooks:**

```javascript
// Advanced Frida script
Java.perform(function() {
    console.log('[*] DJI Feature Unlocker Loaded');
    
    // List all loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.toLowerCase().indexOf('feature') >= 0) {
                console.log('[*] Found class: ' + className);
            }
        },
        onComplete: function() {
            console.log('[*] Class enumeration complete');
        }
    });
    
    // Hook multiple methods
    var targets = [
        'com.dji.feature.FeatureManager',
        'com.dji.product.ProductVerifier',
        'com.dji.license.LicenseValidator'
    ];
    
    targets.forEach(function(target) {
        try {
            var clazz = Java.use(target);
            var methods = clazz.class.getDeclaredMethods();
            methods.forEach(function(method) {
                console.log('[*] Found method: ' + method);
            });
        } catch(e) {
            console.log('[!] Class not found: ' + target);
        }
    });
});
```

---

## Phase 7: Testing & Validation

### Safety Testing Checklist

Before any real flight:

- [ ] Test basic connection (controller to drone)
- [ ] Verify camera feed works
- [ ] Check manual controls respond correctly
- [ ] Test Return-to-Home functionality
- [ ] Verify battery monitoring works
- [ ] Check GPS lock and accuracy
- [ ] Test in safe, open area first
- [ ] Have original firmware ready to restore

### Feature Testing

For each unlocked feature:

1. **Document current state**
   - Take screenshots
   - Record settings
   - Note any warnings

2. **Test incrementally**
   - Test one feature at a time
   - Start with low-risk features
   - Monitor for errors or warnings

3. **Verify safety**
   - Ensure no impact on flight safety systems
   - Check that failsafes still work
   - Confirm Return-to-Home works

---

## Common Issues & Solutions

### Issue 1: App Signature Verification Failed

**Solution:**
- Disable signature verification in OS (requires root)
- Use Lucky Patcher to remove signature checks
- Accept that cloud features won't work

### Issue 2: App Detects Modifications

**Solution:**
- Clear app data and cache
- Use anti-detection modules (Hide My Applist)
- Use virtual environment (VMOS)

### Issue 3: Device Detection Fails

**Solution:**
- Check USB connections
- Enable USB debugging
- Try different USB cable
- Restart ADB server: `adb kill-server && adb start-server`

### Issue 4: Features Still Locked After Modification

**Possible Causes:**
- Server-side validation (can't bypass locally)
- Wrong method hooked
- Code obfuscated differently
- Feature requires firmware update

**Solution:**
- Review network traffic
- Find correct classes/methods
- Use deobfuscation tools
- Research firmware requirements

---

## Responsible Research Guidelines

### Do's ✅

- ✅ Research and understand before modifying
- ✅ Keep backups of everything
- ✅ Test in safe environments
- ✅ Document your findings
- ✅ Share knowledge with community
- ✅ Respect aviation regulations
- ✅ Maintain safety features

### Don'ts ❌

- ❌ Don't disable safety systems
- ❌ Don't fly in restricted areas
- ❌ Don't share personal flight data
- ❌ Don't distribute modified APKs
- ❌ Don't encourage unsafe practices
- ❌ Don't violate local laws
- ❌ Don't fly over people or property

---

## Additional Resources

### Communities

- **DJI Hacking Forum:** https://dji-rev.slack.com/
- **RCGroups DJI Section:** https://www.rcgroups.com/aircraft-electric-drones-471/
- **Reddit r/djihacks:** Research and discussion
- **XDA Forums:** Android modifications

### Tools

- **APKTool:** https://ibotpeaches.github.io/Apktool/
- **JADX:** https://github.com/skylot/jadx
- **Frida:** https://frida.re/
- **Ghidra:** https://ghidra-sre.org/
- **LSPosed:** https://github.com/LSPosed/LSPosed

### Learning Resources

- **Android App Reverse Engineering 101**
- **Frida Handbook**
- **Smali/Baksmali Documentation**
- **Android Security Internals**

---

## Legal & Safety Reminder

**⚠️ IMPORTANT:**

1. **Warranty:** Any modifications will void your warranty
2. **Regulations:** Ensure compliance with local drone laws
3. **Safety:** Never compromise flight safety features
4. **Liability:** You are responsible for any consequences
5. **Privacy:** Don't expose personal flight data
6. **Terms of Service:** May violate DJI's ToS

**When in doubt, don't do it.**

---

## Conclusion

This guide provides a structured approach to researching and potentially modifying the DJI RM330 controller and Fly app. Start with information gathering, progress through static and dynamic analysis, and only attempt modifications if you understand the risks and have the necessary skills.

**Remember:** The goal is education and understanding, not reckless modification.

**Good luck, and fly safely! 🚁**

---

**Guide Version:** 1.0  
**Last Updated:** November 18, 2025  
