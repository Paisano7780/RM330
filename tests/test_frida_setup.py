"""
Tests for Frida Setup and Environment

These tests verify that the Frida environment is properly configured
for DJI RM330 research.
"""

import sys
import pytest


class TestFridaInstallation:
    """Test Frida installation and basic functionality"""
    
    def test_frida_module_import(self):
        """Test that frida module can be imported"""
        try:
            import frida
            assert frida is not None
        except ImportError as e:
            pytest.fail(f"Failed to import frida: {e}")
    
    def test_frida_version(self):
        """Test that frida version is available"""
        import frida
        version = frida.__version__
        assert version is not None
        assert len(version) > 0
        print(f"Frida version: {version}")
    
    def test_frida_core_functionality(self):
        """Test basic Frida functionality"""
        import frida
        
        # Test that we can access device enumeration
        # Note: This won't find actual devices in CI, but tests the API
        try:
            devices = frida.enumerate_devices()
            assert devices is not None
            assert isinstance(devices, list)
        except Exception as e:
            # In CI environment, this might fail but API should be accessible
            assert 'frida' in str(type(e).__module__)


class TestFridaScripts:
    """Test that Frida scripts are valid"""
    
    def test_python_hook_script_exists(self):
        """Test that the main Python hook script exists"""
        import os
        script_path = os.path.join('frida-scripts', 'frida_hook.py')
        assert os.path.exists(script_path), f"Script not found: {script_path}"
    
    def test_python_hook_script_syntax(self):
        """Test that Python hook script has valid syntax"""
        import py_compile
        import os
        
        script_path = os.path.join('frida-scripts', 'frida_hook.py')
        try:
            py_compile.compile(script_path, doraise=True)
        except py_compile.PyCompileError as e:
            pytest.fail(f"Syntax error in {script_path}: {e}")
    
    def test_javascript_hooks_exist(self):
        """Test that JavaScript hook files exist"""
        import os
        
        expected_scripts = [
            'advanced_hook.js',
            'feature_enum.js'
        ]
        
        for script in expected_scripts:
            script_path = os.path.join('frida-scripts', script)
            assert os.path.exists(script_path), f"Script not found: {script_path}"
    
    def test_javascript_hooks_not_empty(self):
        """Test that JavaScript files are not empty"""
        import os
        
        js_scripts = [
            'advanced_hook.js',
            'feature_enum.js'
        ]
        
        for script in js_scripts:
            script_path = os.path.join('frida-scripts', script)
            if os.path.exists(script_path):
                with open(script_path, 'r') as f:
                    content = f.read()
                    assert len(content) > 0, f"Script is empty: {script}"
                    assert 'Java.perform' in content, f"Script doesn't contain Java.perform: {script}"


class TestDependencies:
    """Test that required dependencies are available"""
    
    def test_pytest_available(self):
        """Test that pytest is available"""
        import pytest
        assert pytest is not None
    
    def test_sys_available(self):
        """Test that sys module is available"""
        import sys
        assert sys is not None
    
    def test_python_version(self):
        """Test that Python version is compatible"""
        assert sys.version_info >= (3, 8), "Python 3.8 or higher required"


class TestDocumentation:
    """Test that documentation references Frida correctly"""
    
    def test_practical_guide_exists(self):
        """Test that PRACTICAL_GUIDE.md exists"""
        import os
        assert os.path.exists('PRACTICAL_GUIDE.md')
    
    def test_practical_guide_mentions_frida(self):
        """Test that practical guide mentions Frida"""
        with open('PRACTICAL_GUIDE.md', 'r') as f:
            content = f.read()
            assert 'Frida' in content or 'frida' in content
    
    def test_readme_exists(self):
        """Test that README.md exists"""
        import os
        assert os.path.exists('README.md')


if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v'])
