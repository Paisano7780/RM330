/**
 * Simple Feature Enumeration Script
 * 
 * A basic Frida script to list all features checked by the DJI Fly app
 * 
 * Usage:
 *   frida -U -f dji.go.v5 -l feature_enum.js --no-pause
 */

Java.perform(function() {
    console.log('[*] Feature Enumeration Script Started');
    console.log('[*] This script will log all feature checks made by the app\n');
    
    // Track unique features
    const featuresFound = new Set();
    
    // Try to hook feature checking mechanisms
    const possibleClasses = [
        'com.dji.feature.FeatureManager',
        'com.dji.common.feature.FeatureManager',
        'dji.common.feature.FeatureManager'
    ];
    
    possibleClasses.forEach(function(className) {
        try {
            const FeatureClass = Java.use(className);
            console.log('[✓] Found class: ' + className);
            
            // Hook isFeatureEnabled or similar methods
            const possibleMethods = ['isFeatureEnabled', 'checkFeature', 'hasFeature', 'isEnabled'];
            
            possibleMethods.forEach(function(methodName) {
                try {
                    if (FeatureClass[methodName]) {
                        FeatureClass[methodName].implementation = function(feature) {
                            const result = this[methodName](feature);
                            
                            // Log and track the feature
                            const featureStr = String(feature);
                            if (!featuresFound.has(featureStr)) {
                                featuresFound.add(featureStr);
                                console.log('[+] NEW Feature: ' + featureStr + ' = ' + result);
                            }
                            
                            return result;
                        };
                        console.log('[✓] Hooked: ' + className + '.' + methodName);
                    }
                } catch(e) {
                    // Method doesn't exist or can't be hooked
                }
            });
            
        } catch(e) {
            // Class doesn't exist
        }
    });
    
    console.log('\n[*] Hooks installed. Use the app to discover features.');
    console.log('[*] All discovered features will be logged above.\n');
});
