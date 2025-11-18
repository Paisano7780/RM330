# RM330 Firmware Configuration Reference

## Overview

This document provides a detailed reference for the RM330 firmware configuration found in `upgrade_center/qcom/unsigned_package/temp_0000.xml`.

---

## Firmware Package Information

| Property | Value | Description |
|----------|-------|-------------|
| **Device ID** | rm330 | DJI RM330 Remote Controller |
| **Firmware Version** | 01.03.2200 | Current firmware release |
| **Anti-Rollback Level** | 4 | Minimum allowed firmware version |
| **Anti-Rollback (CN)** | 4 | China-specific anti-rollback level |
| **Enforce** | 0 | Enforcement flag (0 = not enforced?) |
| **Enforce (CN)** | 0 | China-specific enforcement |
| **Release Date** | 2025-07-22 | Firmware release date |
| **Expiration Date** | 2026-07-22 | Firmware expiration date |
| **Enforce Time** | 2025-07-22T03:50:54+00:00 | Enforcement timestamp |

---

## Module 1: sys_app (System/Application)

**Primary system partition containing OS and DJI Fly app**

### Basic Information
| Property | Value |
|----------|-------|
| **Module ID** | 0205 |
| **Version** | 00.15.00.16 |
| **Name** | sys_app |
| **Type** | (empty) |
| **Group** | rc (remote controller) |
| **File** | rm330_0205_v00.15.00.16_20250721.pro.fw.sig |

### Size & Checksums
| Property | Value |
|----------|-------|
| **Size** | 1,017,078,560 bytes (~970 MB) |
| **MD5 (unsigned)** | 31f7b51fd7563d0fb3bba274e89638e7 |
| **MD5 (signed)** | e901174b6bb67253a2cf1a3416026067 |

### Upgrade Configuration
| Property | Value | Description |
|----------|-------|-------------|
| **Upgrade Order** | 1 | First module to upgrade |
| **Is Upgrade Center** | true | This module is the upgrade center |
| **Operation Library** | librecovery_md_up.so | Library handling upgrade |
| **Communication Method** | V1 | Protocol version |
| **Communication Param 1** | 0x0205 | Module ID in hex |
| **Communication Param 2** | null | Not used |
| **Security Type** | **secure** | Highest security level |

### Upgrade Behavior
| Property | Value | Meaning |
|----------|-------|---------|
| **only_check_ver** | false | Not version-check only |
| **loader_needed** | false | No separate loader required |
| **post_reset** | false | No reset after upgrade |
| **post_check_ver** | true | Verify version after upgrade |
| **reboot_after_fail** | false | Don't reboot on failure |
| **reboot_notify** | true | Notify before reboot |
| **resp_get_ver** | true | Responds to version queries |
| **support_multi_hw** | false | Single hardware variant |
| **allow_skip** | false | Cannot skip this module |
| **fail_repeat** | 0 | Don't retry on failure |

### Timing Configuration
| Property | Value |
|----------|-------|
| **Order** | 0 |
| **Wait** | 0 |
| **delay_after_1_pkg_us** | 0 |
| **delay_after_a_cmd_s** | 0 |

---

## Module 2: RC_MCU (Remote Controller MCU)

**Microcontroller firmware for hardware control**

### Basic Information
| Property | Value |
|----------|-------|
| **Module ID** | 0600 |
| **Version** | 01.00.03.14 |
| **Name** | RC_MCU |
| **Type** | (empty) |
| **Group** | rc (remote controller) |
| **File** | rm330_0600_v01.00.03.14_20230404.pro.fw.sig |

### Size & Checksums
| Property | Value |
|----------|-------|
| **Size** | 43,840 bytes (~43 KB) |
| **MD5 (unsigned)** | 7f7a9caa72a8228f8d7e27f09b7061e3 |
| **MD5 (signed)** | 94fd3b3e882df3b55065472d37864c02 |

### Upgrade Configuration
| Property | Value | Description |
|----------|-------|-------------|
| **Upgrade Order** | 2 | Second module to upgrade |
| **Is Upgrade Center** | false | Not the upgrade center |
| **Operation Library** | libstandard_md_up.so | Standard upgrade library |
| **Communication Method** | V1 | Protocol version |
| **Communication Param 1** | 0x0600 | Module ID in hex |
| **Communication Param 2** | null | Not used |
| **Security Type** | normal | Standard security |

### Upgrade Behavior
| Property | Value | Meaning |
|----------|-------|---------|
| **only_check_ver** | false | Not version-check only |
| **loader_needed** | **true** | Requires bootloader |
| **post_reset** | **true** | Reset after upgrade |
| **post_check_ver** | **true** | Verify version after upgrade |
| **reboot_after_fail** | **true** | Reboot on failure |
| **reboot_notify** | false | No reboot notification |
| **resp_get_ver** | true | Responds to version queries |
| **support_multi_hw** | false | Single hardware variant |
| **allow_skip** | false | Cannot skip this module |
| **fail_repeat** | 2 | Retry twice on failure |

---

## Module 3: SPARROW_GND (Ground Station)

**Communication module for drone-controller link**

### Basic Information
| Property | Value |
|----------|-------|
| **Module ID** | 1400 |
| **Version** | 10.00.06.10 |
| **Name** | SPARROW_GND |
| **Type** | (empty) |
| **Group** | rc (remote controller) |
| **File** | rm330_1400_v10.00.06.10_20231110.pro.fw.sig |

### Size & Checksums
| Property | Value |
|----------|-------|
| **Size** | 2,692,896 bytes (~2.6 MB) |
| **MD5 (unsigned)** | df3e9b0e4c47139af2d52123275b54be |
| **MD5 (signed)** | 74fc19d5fe63290b875a58caa4f82896 |

### Upgrade Configuration
| Property | Value | Description |
|----------|-------|-------------|
| **Upgrade Order** | 3 | Third module to upgrade |
| **Is Upgrade Center** | false | Not the upgrade center |
| **Operation Library** | libsparrow_noemmc_md_up.so | SPARROW-specific library |
| **Communication Method** | V1 | Protocol version |
| **Communication Param 1** | 0x0e00 | Communication channel ID |
| **Communication Param 2** | null | Not used |
| **Security Type** | normal | Standard security |

### Upgrade Behavior
| Property | Value | Meaning |
|----------|-------|---------|
| **only_check_ver** | false | Not version-check only |
| **loader_needed** | false | No separate loader required |
| **post_reset** | false | No reset after upgrade |
| **post_check_ver** | false | No version verification after |
| **reboot_after_fail** | false | Don't reboot on failure |
| **reboot_notify** | false | No reboot notification |
| **resp_get_ver** | true | Responds to version queries |
| **support_multi_hw** | false | Single hardware variant |
| **allow_skip** | false | Cannot skip this module |
| **fail_repeat** | 2 | Retry twice on failure |

---

## Upgrade Sequence

Based on the `upgrade_order` attribute, the firmware upgrade sequence is:

```
1. sys_app (0205) - System/Application partition
   ↓
2. RC_MCU (0600) - Microcontroller firmware
   ↓
3. SPARROW_GND (1400) - Ground station module
```

### Why This Order?

1. **sys_app first:** The upgrade center itself must be updated first to ensure it can handle newer firmware formats
2. **RC_MCU second:** Core hardware control must be updated before communication protocols
3. **SPARROW_GND last:** Communication module updated last to ensure compatibility

---

## Security Analysis

### Security Levels

| Module | Security Type | Significance |
|--------|---------------|--------------|
| sys_app | **secure** | Hardware-backed verification, likely uses TrustZone |
| RC_MCU | normal | Standard signature verification |
| SPARROW_GND | normal | Standard signature verification |

### Signature Format

All firmware files use the naming convention:
```
{device}_{module_id}_v{version}_{date}.pro.fw.sig

Example: rm330_0205_v00.15.00.16_20250721.pro.fw.sig
         └─────┘ └──┘   └──────────┘  └──────┘ └─────────┘
         device  mod id   version      date     pro+signed
```

- `.pro` = Production (not debug)
- `.fw` = Firmware
- `.sig` = Signed with DJI's private key

---

## Anti-Rollback Protection

### How It Works

```
Current Anti-Rollback Level: 4

Firmware Version History:
├── v01.01.xxxx - Anti-Rollback: 1 ❌ Cannot install
├── v01.02.xxxx - Anti-Rollback: 2 ❌ Cannot install
├── v01.02.xxxx - Anti-Rollback: 3 ❌ Cannot install
├── v01.03.2200 - Anti-Rollback: 4 ✅ Current version
└── v01.04.xxxx - Anti-Rollback: 5 ✅ Can upgrade to this
```

### Protection Mechanism

1. **Hardware Counter:** Non-volatile storage stores the highest anti-rollback level ever installed
2. **Upgrade Check:** During upgrade, new firmware's anti-rollback level must be ≥ stored level
3. **Irreversible:** Once upgraded to level 4, cannot downgrade to levels 1-3
4. **Security Purpose:** Prevents attackers from exploiting patched vulnerabilities in older firmware

---

## XML Attribute Reference

### Common Attributes

| Attribute | Type | Purpose |
|-----------|------|---------|
| `id` | hex | Unique module identifier |
| `version` | string | Module version (format varies) |
| `type` | string | Module type (usually empty) |
| `group` | string | Module group (e.g., "rc") |
| `order` | int | Processing order |
| `wait` | int | Wait time (purpose unknown) |
| `size` | int | File size in bytes |
| `name` | string | Human-readable module name |
| `upgrade_order` | int | Order in upgrade sequence |

### Upgrade Library Attributes

| Attribute | Type | Purpose |
|-----------|------|---------|
| `op_lib_name` | string | Shared library handling the upgrade |
| `com_method` | string | Communication protocol version |
| `com_prama1` | string | Protocol parameter 1 (usually module ID) |
| `com_prama2` | string | Protocol parameter 2 |
| `sec_type` | string | Security level: "secure" or "normal" |

### Behavior Flags (Boolean)

All boolean attributes use "true" or "false" strings.

| Attribute | When True |
|-----------|-----------|
| `is_upgrade_center` | Module contains the upgrade system itself |
| `only_check_ver` | Only check version, don't upgrade |
| `loader_needed` | Requires bootloader to apply update |
| `post_reset` | Reset/reboot after upgrade |
| `post_check_ver` | Verify version after upgrade |
| `reboot_after_fail` | Reboot if upgrade fails |
| `reboot_notify` | Notify user before rebooting |
| `resp_get_ver` | Responds to version query commands |
| `support_multi_hw` | Supports multiple hardware variants |
| `allow_skip` | Can skip this module in upgrade |

### Retry Configuration

| Attribute | Type | Purpose |
|-----------|------|---------|
| `fail_repeat` | int | Number of retry attempts on failure |
| `delay_after_1_pkg_us` | int | Delay after each package (microseconds) |
| `delay_after_a_cmd_s` | int | Delay after each command (seconds) |

### Timeout Attributes

Most timeout attributes are set to "null" in this configuration:

- `get_version_to` / `get_version_dt`
- `request_upgrade_to` / `request_upgrade_dt`
- `check_status_to` / `check_status_dt`
- `request_accept_data_to` / `request_accept_data_dt`
- `transfer_data_to` / `transfer_data_dt`
- `transfer_complete_to` / `transfer_complete_dt`
- `reboot_to` / `reboot_dt`
- `wait_status_report_time`
- `wait_status_report_time_total`

### Checksum Attributes

| Attribute | Purpose |
|-----------|---------|
| `md5_unsign` | MD5 hash of firmware before signing |
| `md5` | MD5 hash of signed firmware file |

---

## Modification Considerations

### ⚠️ What NOT to Change

**DO NOT modify:**
- `md5` or `md5_unsign` (will cause verification failure)
- File names in module elements (must match actual files)
- `sec_type="secure"` (hardware will reject changes)
- Module IDs (must match hardware expectations)

### ⚠️ What MIGHT Be Changeable (Research Only)

**Potentially modifiable for research:**
- `antirollback` value (unlikely to have effect due to hardware counter)
- `enforce` flags (may affect enforcement behavior)
- Timeout values (if not null)
- Retry counts

**Expected Result:** Most changes will be ignored or cause upgrade failure

### Why Changes Won't Work

1. **MD5 Verification:** Any file modification changes the MD5 hash
2. **Signature Verification:** Signed firmware (.sig) includes cryptographic signature
3. **Hardware Enforcement:** Anti-rollback counter is in secure hardware
4. **Upgrade Library Validation:** Libraries validate parameters

---

## Practical Use Cases

### Use Case 1: Understanding Your Firmware

Check what you're running:
```bash
adb shell getprop | grep dji
# or
adb shell dumpsys | grep -i version
```

### Use Case 2: Identifying Update Files

If you obtain firmware update packages, verify them:
```bash
md5sum rm330_0205_v00.15.00.16_20250721.pro.fw.sig
# Should match: e901174b6bb67253a2cf1a3416026067
```

### Use Case 3: Research Data Point

This XML provides insight into:
- DJI's upgrade architecture
- Security implementation levels
- Module interdependencies
- Version history

---

## Related Files

Based on the XML, these firmware files should exist (or have existed):

```
upgrade_center/qcom/upgrade_package/
├── rm330_0205_v00.15.00.16_20250721.pro.fw.sig (970 MB)
├── rm330_0600_v01.00.03.14_20230404.pro.fw.sig (43 KB)
└── rm330_1400_v10.00.06.10_20231110.pro.fw.sig (2.6 MB)
```

**Note:** These files are not present in the current repository, only the XML manifest.

---

## Questions & Research Directions

### Unanswered Questions

1. **What is the actual enforcement mechanism?** (`enforce="0"` suggests it's not strictly enforced?)
2. **Can anti-rollback be bypassed?** (Unlikely, but worth understanding)
3. **What happens after expiration date?** (2026-07-22)
4. **Are there debug/development firmware variants?** (`.dev.fw.sig` instead of `.pro.fw.sig`?)

### Research Directions

1. **Firmware Extraction:** Can we dump current firmware from device?
2. **Signature Analysis:** What signature algorithm is used?
3. **Bootloader Investigation:** Can bootloader be analyzed or modified?
4. **Library Reverse Engineering:** What do the `.so` libraries do?

---

## Conclusion

This XML file is a **manifest** for the RM330 firmware package. It describes what should be upgraded but doesn't contain the actual firmware or the ability to modify it.

**Key Takeaway:** Understanding this file helps us know what we're up against, but doesn't provide a way to bypass the security measures.

---

**Document Version:** 1.0  
**Last Updated:** November 18, 2025  
**Source File:** `upgrade_center/qcom/unsigned_package/temp_0000.xml`
