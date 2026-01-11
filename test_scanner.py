# tests/test_scanner.py
"""
Tests for ZeroTrustDjango Scanner
"""

import pytest
import tempfile
import json
from pathlib import Path
from zero_trust_scanner import ZeroTrustDjangoScanner, TestType, SecurityIssue, Severity

class TestZeroTrustDjangoScanner:
    
    @pytest.fixture
    def temp_project(self):
        """Create a temporary Django project for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "test_project"
            project_path.mkdir()
            
            # Create basic Django structure
            (project_path / "manage.py").write_text("#!/usr/bin/env python\nprint('Django')")
            
            # Create settings.py with insecure settings
            settings_content = """
DEBUG = True
SECRET_KEY = 'insecure-secret-key-here'
ALLOWED_HOSTS = []
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db.sqlite3',
    }
}
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
"""
            (project_path / "settings.py").write_text(settings_content)
            
            # Create a vulnerable view
            views_content = """
from django.http import HttpResponse
import sqlite3

def vulnerable_view(request):
    # SQL Injection vulnerability
    user_id = request.GET.get('id')
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # Vulnerable!
    return HttpResponse("Vulnerable")
"""
            (project_path / "views.py").write_text(views_content)
            
            yield project_path
            
    def test_scanner_initialization(self, temp_project):
        """Test scanner initialization"""
        scanner = ZeroTrustDjangoScanner(temp_project)
        assert scanner.project_path == Path(temp_project).resolve()
        assert len(scanner.results) == 0
        assert len(scanner.issues) == 0
        
    def test_environment_variables_check(self, temp_project):
        """Test environment variables check"""
        scanner = ZeroTrustDjangoScanner(temp_project)
        
        # Mock the check method
        scanner.check_environment_variables()
        
        # Should find hardcoded SECRET_KEY
        assert len(scanner.issues) > 0
        assert any("SECRET_KEY" in issue.title for issue in scanner.issues)
        
    def test_report_generation(self, temp_project):
        """Test report generation"""
        scanner = ZeroTrustDjangoScanner(temp_project)
        scanner.check_environment_variables()
        
        report = scanner.generate_report()
        
        assert "summary" in report
        assert "results" in report
        assert report["summary"]["total_issues"] > 0
        
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        scanner = ZeroTrustDjangoScanner("/tmp/test")
        
        issues_by_severity = {
            "CRITICAL": 2,
            "HIGH": 3,
            "MEDIUM": 5,
            "LOW": 10,
            "INFO": 20
        }
        
        score = scanner._calculate_risk_score(issues_by_severity)
        assert score > 0
        
    def test_severity_color_mapping(self):
        """Test severity color mapping"""
        scanner = ZeroTrustDjangoScanner("/tmp/test")
        
        assert scanner._get_severity_color("CRITICAL") == '\033[91m\033[1m'
        assert scanner._get_severity_color("HIGH") == '\033[91m'
        assert scanner._get_severity_color("MEDIUM") == '\033[93m'
        
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
