/**
 * Advanced DJI Fly Feature Discovery Script
 * 
 * This Frida script enumerates loaded classes and methods to discover
 * feature-related functionality in the DJI Fly app.
 * 
 * Based on PRACTICAL_GUIDE.md Phase 5, Step 3
 * 
 * ⚠️ DISCLAIMER: Educational and research purposes only
 * 
 * Usage:
 *   frida -U -f dji.go.v5 -l advanced_hook.js --no-pause
 */

Java.perform(function() {
    console.log('[*] Advanced DJI Feature Discovery Script Loaded');
    console.log('[*] Starting class enumeration...\n');
    
    // Feature-related keywords to search for
    const keywords = [
        'feature',
        'product',
        'license',
        'unlock',
        'enable',
        'permission',
        'aircraft',
        'model',
        'pro',
        'mini'
    ];
    
    console.log('[*] Searching for classes matching keywords: ' + keywords.join(', '));
    
    // Enumerate loaded classes and find interesting ones
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            const lowerClassName = className.toLowerCase();
            
            // Check if class name contains any of our keywords
            for (let keyword of keywords) {
                if (lowerClassName.includes(keyword)) {
                    console.log('[+] Found interesting class: ' + className);
                    
                    try {
                        // Try to get the class and enumerate its methods
                        const clazz = Java.use(className);
                        const methods = clazz.class.getDeclaredMethods();
                        
                        if (methods.length > 0) {
                            console.log('    Methods:');
                            methods.forEach(function(method) {
                                console.log('      - ' + method.getName());
                            });
                        }
                    } catch(e) {
                        // Class might not be accessible
                        console.log('    (Could not enumerate methods)');
                    }
                    
                    console.log('');
                    break; // Only match each class once
                }
            }
        },
        onComplete: function() {
            console.log('[*] Class enumeration complete\n');
            console.log('[*] Installing hooks on known targets...\n');
            installHooks();
        }
    });
});

/**
 * Install hooks on known/suspected target classes
 */
function installHooks() {
    // List of target classes to hook (may not all exist)
    const targets = [
        {
            className: 'com.dji.feature.FeatureManager',
            methods: ['isFeatureEnabled', 'checkFeature', 'hasFeature']
        },
        {
            className: 'com.dji.product.ProductManager',
            methods: ['getProductType', 'getProductModel', 'isProModel']
        },
        {
            className: 'com.dji.product.ProductVerifier',
            methods: ['verify', 'checkProduct', 'validateProduct']
        },
        {
            className: 'com.dji.license.LicenseValidator',
            methods: ['isLicenseValid', 'validateLicense', 'checkLicense']
        },
        {
            className: 'com.dji.aircraft.AircraftManager',
            methods: ['getAircraftType', 'getModel']
        }
    ];
    
    targets.forEach(function(target) {
        try {
            const clazz = Java.use(target.className);
            console.log('[✓] Found class: ' + target.className);
            
            // Try to hook each method
            target.methods.forEach(function(methodName) {
                try {
                    // Check if method exists before hooking
                    const method = clazz[methodName];
                    if (method) {
                        // Hook the method
                        method.implementation = function() {
                            console.log('[→] ' + target.className + '.' + methodName + ' called');
                            console.log('    Arguments: ' + JSON.stringify(arguments));
                            
                            // Call original method
                            const result = method.apply(this, arguments);
                            console.log('    Original result: ' + result);
                            
                            // For boolean methods, consider forcing to true
                            if (typeof result === 'boolean') {
                                console.log('    Forcing result to: true');
                                return true;
                            }
                            
                            return result;
                        };
                        console.log('  [✓] Hooked method: ' + methodName);
                    }
                } catch(e) {
                    // Method might not exist or might have different signature
                    console.log('  [!] Could not hook method: ' + methodName + ' (' + e.message + ')');
                }
            });
            
            console.log('');
            
        } catch(e) {
            console.log('[!] Class not found: ' + target.className);
            console.log('');
        }
    });
    
    console.log('[*] Hook installation complete');
    console.log('[*] Monitor the output above for successful hooks');
    console.log('[*] Now use the DJI Fly app and observe the console\n');
}

/**
 * Utility: Hook all methods of a given class
 */
function hookAllMethods(className) {
    try {
        const clazz = Java.use(className);
        const methods = clazz.class.getDeclaredMethods();
        
        methods.forEach(function(method) {
            const methodName = method.getName();
            
            try {
                const original = clazz[methodName];
                
                clazz[methodName].implementation = function() {
                    console.log('[*] Called: ' + className + '.' + methodName);
                    const result = original.apply(this, arguments);
                    console.log('[*] Result: ' + result);
                    return result;
                };
                
            } catch(e) {
                // Some methods might be overloaded or have special signatures
            }
        });
        
    } catch(e) {
        console.log('[!] Error hooking class ' + className + ': ' + e.message);
    }
}

console.log('[*] Script ready. Waiting for Java VM...');
