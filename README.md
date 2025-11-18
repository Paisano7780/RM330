# DJI RM330 Remote Controller - Research Repository

[![Frida Test Environment](https://github.com/Paisano7780/RM330/actions/workflows/frida-test.yml/badge.svg)](https://github.com/Paisano7780/RM330/actions/workflows/frida-test.yml)

This repository contains data from a DJI RM330 remote controller used with a DJI Mini 3 (Non-Pro) drone, along with comprehensive security analysis and research documentation.

## ⚠️ IMPORTANT DISCLAIMER

**This repository is for educational and security research purposes only.**

- The analysis and guides provided are for learning about embedded systems security
- Modifying firmware or bypassing protections may void warranties and violate regulations
- The user assumes all responsibility for any actions taken based on this information
- Always comply with local aviation laws and DJI's Terms of Service
- Flying safely is more important than unlocking features

**USE AT YOUR OWN RISK**

---

## Repository Contents

### Device Data

This repository contains actual data extracted from a DJI RM330 controller:

- **Firmware Configuration:** XML manifest for firmware v01.03.2200
- **Flight Records:** GPS logs and flight telemetry (sanitize before sharing!)
- **App Data:** DJI Fly app cache, logs, and configuration
- **System Logs:** Diagnostic logs from various subsystems

### Documentation

Comprehensive analysis and research guides:

1. **[SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md)** - Complete security assessment
   - Firmware architecture analysis
   - Anti-rollback protection breakdown
   - Signature verification mechanisms
   - Vulnerability assessment
   - Modification strategies (feasibility analysis)

2. **[PRACTICAL_GUIDE.md](PRACTICAL_GUIDE.md)** - Step-by-step research guide
   - Tools and prerequisites
   - APK extraction and analysis
   - Network traffic analysis
   - Runtime hooking with Frida
   - APK modification techniques
   - Safety and testing procedures

3. **[FIRMWARE_REFERENCE.md](FIRMWARE_REFERENCE.md)** - Technical reference
   - Detailed XML configuration breakdown
   - Module specifications
   - Upgrade sequence explanation
   - Attribute reference guide

---

## Quick Start

### For Researchers

**Want to understand the system?**

1. Read [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for an overview
2. Review [FIRMWARE_REFERENCE.md](FIRMWARE_REFERENCE.md) for technical details
3. Follow [PRACTICAL_GUIDE.md](PRACTICAL_GUIDE.md) for hands-on research

### For Developers

**Want to experiment with modifications?**

1. Ensure you have Android development tools installed (ADB, apktool, etc.)
2. Follow the "Phase 1: Information Gathering" section in [PRACTICAL_GUIDE.md](PRACTICAL_GUIDE.md)
3. Start with static analysis before attempting any modifications
4. Test everything on a non-critical device first

---

## Key Findings Summary

### Firmware Security

✅ **Strong Protection:**
- All firmware modules are cryptographically signed
- Hardware-enforced anti-rollback protection (level 4)
- Secure boot chain with TrustZone implementation
- Multiple layers of signature verification

❌ **Direct Firmware Modification:** Not feasible without DJI's private signing key

### Potential Research Avenues

🟢 **Most Promising:**
- App-level modifications (APK patching)
- Runtime hooking with Frida
- Configuration file analysis
- Feature flag manipulation

🟡 **Moderate Success Potential:**
- Xposed/LSPosed modules
- Network traffic analysis
- Database modifications

🔴 **Not Recommended:**
- Direct firmware patching
- Bootloader modification
- Hardware tampering

---

## Device Information

**Remote Controller:** DJI RM330  
**Current Firmware:** v01.03.2200 (released 2025-07-22)  
**Anti-Rollback Level:** 4  
**Compatible Drone:** DJI Mini 3 (Non-Pro)  
**App:** DJI Fly (dji.go.v5)

### Firmware Modules

1. **sys_app (0205):** Android OS + DJI Fly app (~970 MB)
2. **RC_MCU (0600):** Microcontroller firmware (~43 KB)
3. **SPARROW_GND (1400):** Communication module (~2.6 MB)

---

## Research Goals

The original issue requested analysis to:

1. ✅ **Find vulnerabilities** - Comprehensive security assessment completed
2. ✅ **Understand anti-rollback** - Mechanism documented and explained
3. ✅ **Explore modification options** - Multiple strategies analyzed and documented
4. ✅ **Unlock hidden features** - Practical approaches identified (app-level mods)
5. ⚠️ **Respect signed software** - All recommendations account for signature verification

### What We Learned

- **Firmware is well-protected:** DJI has implemented industry-standard security
- **App layer is more accessible:** Feature unlocking likely requires app modification
- **Anti-rollback is hardware-enforced:** Cannot be bypassed via software alone
- **Multiple approaches exist:** From simple APK patching to advanced runtime hooking

---

## Safety & Legal Considerations

### Safety First

- Never disable critical safety features (RTH, altitude limits, battery monitoring)
- Always test in safe, open areas away from people and property
- Keep original firmware backup available
- Understand the risks before making any changes

### Legal Compliance

- **Aviation Regulations:** Ensure compliance with local drone laws
- **Warranty:** Modifications will void warranty
- **Terms of Service:** May violate DJI's ToS
- **Intellectual Property:** Respect DJI's copyrights and patents

### Privacy

⚠️ **This repository contains personal flight data:**
- GPS coordinates of flight locations
- Timestamps and flight patterns
- Device serial numbers

**Recommendation:** Sanitize or remove personal data before forking/sharing.

---

## Tools & Resources

### Essential Tools

- **ADB (Android Debug Bridge):** Device communication
- **apktool:** APK decompilation and rebuilding
- **jadx:** Java decompiler for Android apps
- **Frida:** Dynamic instrumentation framework
- **Charles Proxy / mitmproxy:** Network traffic analysis

### Learning Resources

- **Android Security Internals** (book)
- **Frida Documentation:** https://frida.re/docs/
- **DJI Developer:** https://developer.dji.com/
- **XDA Forums:** Android modding community

---

## Contributing

This repository is primarily for documentation and research purposes. If you have:

- Additional findings about RM330 security
- Successful modification techniques
- Corrections to the analysis
- Updated firmware information

Feel free to open an issue or submit a pull request.

### Guidelines

- ❌ Don't share personal flight data
- ❌ Don't distribute modified APKs
- ❌ Don't encourage unsafe practices
- ✅ Do share knowledge and research findings
- ✅ Do maintain safety and legal awareness
- ✅ Do help others learn responsibly

---

## FAQ

### Q: Can I unlock Pro features on my Mini 3?

**A:** It depends on whether features are restricted by hardware or software. App-level restrictions may be bypassable through APK modification or runtime hooking. Hardware limitations (e.g., sensors not present) cannot be overcome.

### Q: Will this brick my device?

**A:** If you follow the documentation and avoid firmware modifications, the risk is minimal. Always keep backups and test cautiously. Firmware modifications carry a high risk of bricking.

### Q: Is this legal?

**A:** Research and analysis for educational purposes is generally legal. However, actually modifying the device may violate warranties, ToS, or local regulations. Consult applicable laws in your jurisdiction.

### Q: Can I bypass anti-rollback protection?

**A:** No. Anti-rollback is enforced by hardware (secure element or fuses) and cannot be reset through software alone. This is by design to prevent exploitation of patched vulnerabilities.

### Q: How do I extract the APK?

**A:** See [PRACTICAL_GUIDE.md](PRACTICAL_GUIDE.md) Phase 1, Step 3 for detailed instructions using ADB.

### Q: Will DJI ban my account?

**A:** Possibly, if they detect modified software connecting to their servers. Modified APKs with different signatures won't be able to use cloud features.

---

## Frida Scripts

This repository now includes ready-to-use Frida scripts for runtime analysis:

📁 **[frida-scripts/](frida-scripts/)** - Dynamic instrumentation tools
- `frida_hook.py` - Python-based feature unlock hooks
- `advanced_hook.js` - Class discovery and enumeration
- `feature_enum.js` - Feature detection logging

See [frida-scripts/README.md](frida-scripts/README.md) for usage instructions.

### Quick Start with Frida

1. Install dependencies: `pip install -r requirements.txt`
2. Set up Frida server on rooted RM330
3. Run: `python frida-scripts/frida_hook.py`

⚠️ Requires rooted device. See [PRACTICAL_GUIDE.md](PRACTICAL_GUIDE.md) Phase 5 for details.

---

## Roadmap

Future research directions:

- [ ] APK extraction and decompilation
- [ ] Feature flag enumeration
- [ ] Network protocol analysis
- [x] Frida hook development ✅
- [ ] Model detection bypass research
- [ ] Database schema documentation
- [ ] Community tool development

---

## Acknowledgments

- **DJI** for creating sophisticated drone technology
- **Android security community** for developing analysis tools
- **Open-source contributors** for Frida, apktool, jadx, and other essential tools

---

## License

The documentation in this repository (SECURITY_ANALYSIS.md, PRACTICAL_GUIDE.md, FIRMWARE_REFERENCE.md) is provided for educational purposes.

The device data and firmware configurations are property of DJI and are included here for research and analysis purposes only.

**Note:** This is not an official DJI repository and is not affiliated with or endorsed by DJI.

---

## Contact & Support

For questions about this research:
- Open an issue in this repository
- Discuss in relevant communities (XDA, RCGroups, etc.)

For official DJI support:
- Visit: https://www.dji.com/support
- Do not contact DJI about unauthorized modifications

---

## Disclaimer (Repeated for Emphasis)

**Everything in this repository is for educational and research purposes only.**

The author(s) of this repository:
- Do not encourage illegal modifications
- Are not responsible for damage to devices
- Are not liable for violations of regulations
- Do not provide warranty for any techniques described
- Strongly recommend maintaining safety features

**Fly safely, research responsibly, and respect the law.** 🚁

---

**Last Updated:** November 18, 2025  
**Repository Version:** 1.0  
