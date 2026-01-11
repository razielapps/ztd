#!/usr/bin/env python3
"""
ZeroTrustDjango Security Scanner
Comprehensive security auditing tool for Django applications
"""

import os
import sys
import json
import subprocess
import ast
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import argparse
import datetime
import re
from dataclasses import dataclass, field
from enum import Enum
import warnings

# Try to import Django components (optional)
try:
    import django
    from django.conf import settings
    from django.core.management import execute_from_command_line
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False
    print("Warning: Django not available. Some checks will be limited.")

# Color codes for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class TestType(Enum):
    NORMAL = "normal"
    SECURITY = "security"

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class SecurityIssue:
    """Class to represent a security issue found"""
    severity: Severity
    category: str
    title: str
    description: str
    location: str
    recommendation: str
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    
@dataclass
class TestResult:
    """Class to represent test results"""
    passed: bool
    test_name: str
    details: str
    issues: List[SecurityIssue] = field(default_factory=list)
    
class ZeroTrustDjangoScanner:
    """Main scanner class for Django security auditing"""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        self.results: List[TestResult] = []
        self.issues: List[SecurityIssue] = []
        self.report_data: Dict[str, Any] = {
            "scan_date": datetime.datetime.now().isoformat(),
            "project_path": str(self.project_path),
            "results": [],
            "summary": {}
        }
        
    def run_test(self, test_type: TestType) -> Dict[str, Any]:
        """Main entry point for running tests"""
        print(f"{Colors.BOLD}{Colors.CYAN}\n{'='*60}")
        print(f"ZeroTrustDjango Scanner")
        print(f"Scan Type: {test_type.value.upper()}")
        print(f"Project: {self.project_path}")
        print(f"{'='*60}{Colors.END}\n")
        
        if test_type == TestType.NORMAL:
            self._run_normal_tests()
        else:
            self._run_security_tests()
            
        return self.generate_report()
    
    def _run_normal_tests(self):
        """Run normal Django tests"""
        print(f"{Colors.BLUE}[*] Running normal Django tests...{Colors.END}")
        
        # Check if manage.py exists
        manage_py = self.project_path / "manage.py"
        if manage_py.exists():
            try:
                # Run Django's test command
                result = subprocess.run(
                    ['python', 'manage.py', 'test'],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True
                )
                
                test_result = TestResult(
                    passed=result.returncode == 0,
                    test_name="Django Standard Tests",
                    details=result.stdout if result.returncode == 0 else result.stderr
                )
                self.results.append(test_result)
                
            except Exception as e:
                self.results.append(TestResult(
                    passed=False,
                    test_name="Django Standard Tests",
                    details=f"Failed to run tests: {str(e)}"
                ))
        else:
            self.results.append(TestResult(
                passed=False,
                test_name="Django Standard Tests",
                details="manage.py not found"
            ))
            
    def _run_security_tests(self):
        """Run comprehensive security tests"""
        print(f"{Colors.BLUE}[*] Starting comprehensive security scan...{Colors.END}")
        
        # Foundational Security Tests
        self.check_environment_variables()
        self.check_django_security_settings()
        self.audit_dependencies()
        
        # API & Authentication Security
        self.check_rate_limiting()
        self.check_jwt_security()
        self.check_session_security()
        
        # Data & Business Logic Security
        self.check_sql_injection_prevention()
        self.check_xss_protection()
        self.check_email_security()
        
        # Infrastructure & Deployment Security
        self.check_cors_configuration()
        self.check_input_validation()
        self.check_file_upload_security()
        
        # Code Analysis
        self.analyze_project_structure()
        self.check_authentication_flows()
        
        # Monitoring & Logging
        self.check_monitoring_logging()
        
        # Advanced Tests
        self.run_security_test_cases()
        self.check_secret_leakage()
        
        print(f"\n{Colors.GREEN}[✓] Security scan completed!{Colors.END}")
        
    # ========== SECURITY CHECK METHODS ==========
    
    def check_environment_variables(self):
        """Check for hardcoded secrets and environment variable usage"""
        print(f"{Colors.YELLOW}[*] Checking environment variables and secrets...{Colors.END}")
        
        issues = []
        settings_files = list(self.project_path.rglob("settings.py")) + \
                       list(self.project_path.rglob("*.env*")) + \
                       list(self.project_path.rglob(".env*"))
        
        # Check for hardcoded secrets
        secret_patterns = [
            (r'SECRET_KEY\s*=\s*["\'].+["\']', "Hardcoded SECRET_KEY"),
            (r'PASSWORD\s*=\s*["\'].+["\']', "Hardcoded password"),
            (r'API_KEY\s*=\s*["\'].+["\']', "Hardcoded API key"),
            (r'TOKEN\s*=\s*["\'].+["\']', "Hardcoded token"),
        ]
        
        for file_path in settings_files:
            if file_path.exists():
                try:
                    content = file_path.read_text()
                    for pattern, description in secret_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            issues.append(SecurityIssue(
                                severity=Severity.CRITICAL,
                                category="Environment Variables",
                                title=description,
                                description=f"Hardcoded secret found in {file_path.relative_to(self.project_path)}",
                                location=str(file_path.relative_to(self.project_path)),
                                recommendation="Move all secrets to environment variables. Use python-decouple or django-environ.",
                                cwe_id="CWE-798"
                            ))
                except Exception as e:
                    continue
                    
        # Check for environment variable imports
        try:
            settings_content = (self.project_path / "settings.py").read_text()
            env_libraries = ['decouple', 'environ', 'os.environ.get', 'getenv']
            if not any(lib in settings_content for lib in env_libraries):
                issues.append(SecurityIssue(
                    severity=Severity.HIGH,
                    category="Environment Variables",
                    title="No environment variable management detected",
                    description="Secrets may be hardcoded in settings",
                    location="settings.py",
                    recommendation="Implement python-decouple or django-environ for secret management",
                    cwe_id="CWE-798"
                ))
        except:
            pass
            
        self._add_result("Environment Variables Check", issues)
        
    def check_django_security_settings(self):
        """Verify Django security settings"""
        print(f"{Colors.YELLOW}[*] Checking Django security settings...{Colors.END}")
        
        issues = []
        
        if not DJANGO_AVAILABLE:
            issues.append(SecurityIssue(
                severity=Severity.MEDIUM,
                category="Django Settings",
                title="Cannot analyze Django settings",
                description="Django not available in current environment",
                location="N/A",
                recommendation="Run scanner within Django environment"
            ))
            self._add_result("Django Security Settings", issues)
            return
            
        try:
            # Configure Django settings for analysis
            sys.path.insert(0, str(self.project_path))
            os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
            
            # Check individual settings
            checks = [
                ("DEBUG", False, Severity.HIGH, "Debug mode should be False in production"),
                ("SECURE_SSL_REDIRECT", True, Severity.HIGH, "SSL redirect should be enabled"),
                ("SESSION_COOKIE_SECURE", True, Severity.HIGH, "Session cookies should be secure"),
                ("CSRF_COOKIE_SECURE", True, Severity.HIGH, "CSRF cookies should be secure"),
                ("SECURE_BROWSER_XSS_FILTER", True, Severity.MEDIUM, "XSS filter should be enabled"),
                ("SECURE_CONTENT_TYPE_NOSNIFF", True, Severity.MEDIUM, "Content type nosniff should be enabled"),
                ("SECURE_HSTS_SECONDS", 31536000, Severity.HIGH, "HSTS should be enabled with sufficient duration"),
                ("X_FRAME_OPTIONS", "DENY", Severity.MEDIUM, "X-Frame-Options should be DENY"),
            ]
            
            for setting, expected_value, severity, description in checks:
                actual_value = getattr(settings, setting, None)
                if actual_value != expected_value:
                    issues.append(SecurityIssue(
                        severity=severity,
                        category="Django Settings",
                        title=f"Insecure {setting} setting",
                        description=f"{description}. Current: {actual_value}, Expected: {expected_value}",
                        location="settings.py",
                        recommendation=f"Set {setting} = {expected_value} in production settings"
                    ))
                    
        except Exception as e:
            issues.append(SecurityIssue(
                severity=Severity.MEDIUM,
                category="Django Settings",
                title="Error analyzing Django settings",
                description=str(e),
                location="settings.py",
                recommendation="Ensure Django is properly configured"
            ))
            
        self._add_result("Django Security Settings", issues)
        
    def audit_dependencies(self):
        """Check for vulnerable dependencies"""
        print(f"{Colors.YELLOW}[*] Auditing dependencies...{Colors.END}")
        
        issues = []
        
        # Check requirements.txt or Pipfile
        req_files = [
            self.project_path / "requirements.txt",
            self.project_path / "Pipfile",
            self.project_path / "pyproject.toml"
        ]
        
        req_file = None
        for f in req_files:
            if f.exists():
                req_file = f
                break
                
        if not req_file:
            issues.append(SecurityIssue(
                severity=Severity.LOW,
                category="Dependencies",
                title="No dependency file found",
                description="Cannot audit dependencies without requirements.txt or Pipfile",
                location="project root",
                recommendation="Create requirements.txt with pinned versions"
            ))
        else:
            # Try to run safety check if available
            try:
                result = subprocess.run(
                    ['safety', 'check', '-r', str(req_file), '--json'],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0 and result.stdout:
                    vulnerabilities = json.loads(result.stdout)
                    for vuln in vulnerabilities:
                        issues.append(SecurityIssue(
                            severity=Severity.HIGH if vuln.get('severity') == 'high' else Severity.MEDIUM,
                            category="Dependencies",
                            title=f"Vulnerable dependency: {vuln.get('package_name')}",
                            description=f"{vuln.get('advisory')}. Affected versions: {vuln.get('vulnerable_spec')}",
                            location=str(req_file.relative_to(self.project_path)),
                            recommendation=f"Update {vuln.get('package_name')} to {vuln.get('fixed_versions')}",
                            cwe_id=vuln.get('CVE', 'N/A')
                        ))
            except (subprocess.SubprocessError, json.JSONDecodeError):
                # Fallback to pip-audit
                try:
                    result = subprocess.run(
                        ['pip-audit', '-r', str(req_file), '--format', 'json'],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode == 0 and result.stdout:
                        vulnerabilities = json.loads(result.stdout)
                        for vuln in vulnerabilities.get('vulnerabilities', []):
                            issues.append(SecurityIssue(
                                severity=Severity.HIGH,
                                category="Dependencies",
                                title=f"Vulnerable dependency: {vuln.get('name')}",
                                description=f"CVE: {', '.join(vuln.get('aliases', []))}",
                                location=str(req_file.relative_to(self.project_path)),
                                recommendation=f"Update {vuln.get('name')} to a secure version",
                                cwe_id=vuln.get('id', 'N/A')
                            ))
                except:
                    issues.append(SecurityIssue(
                        severity=Severity.LOW,
                        category="Dependencies",
                        title="Cannot run dependency audit",
                        description="safety or pip-audit not available",
                        location="system",
                        recommendation="Install safety or pip-audit: pip install safety pip-audit"
                    ))
                    
        self._add_result("Dependency Audit", issues)
        
    def check_rate_limiting(self):
        """Check for rate limiting implementation"""
        print(f"{Colors.YELLOW}[*] Checking rate limiting...{Colors.END}")
        
        issues = []
        
        # Look for rate limiting decorators or configuration
        rate_limit_patterns = [
            r'@ratelimit',
            r'RateLimitMiddleware',
            r'django-ratelimit',
            r'throttle'
        ]
        
        python_files = list(self.project_path.rglob("*.py"))
        found_rate_limiting = False
        
        for file_path in python_files:
            try:
                content = file_path.read_text()
                for pattern in rate_limit_patterns:
                    if re.search(pattern, content):
                        found_rate_limiting = True
                        break
            except:
                continue
                
        if not found_rate_limiting:
            issues.append(SecurityIssue(
                severity=Severity.MEDIUM,
                category="Rate Limiting",
                title="No rate limiting detected",
                description="Critical endpoints (login, registration, password reset) should have rate limiting",
                location="views.py / urls.py",
                recommendation="Implement django-ratelimit or DRF throttling for sensitive endpoints"
            ))
            
        self._add_result("Rate Limiting Check", issues)
        
    def check_jwt_security(self):
        """Check JWT implementation security"""
        print(f"{Colors.YELLOW}[*] Checking JWT security...{Colors.END}")
        
        issues = []
        
        # Check for JWT configuration
        jwt_patterns = [
            r'SimpleJWT',
            r'JSONWebTokenAuthentication',
            r'jwt\.',
            r'access_token',
            r'refresh_token'
        ]
        
        python_files = list(self.project_path.rglob("*.py"))
        has_jwt = False
        
        for file_path in python_files:
            try:
                content = file_path.read_text()
                if any(pattern in content for pattern in jwt_patterns):
                    has_jwt = True
                    
                    # Check for secure JWT settings
                    insecure_patterns = [
                        (r'SIMPLE_JWT\s*=\s*\{[^}]*ALGORITHM\s*:\s*["\']HS256["\']', 
                         "JWT using HS256 algorithm"),
                        (r'JWT_SECRET_KEY\s*=\s*["\'].+["\']',
                         "Hardcoded JWT secret"),
                    ]
                    
                    for pattern, description in insecure_patterns:
                        if re.search(pattern, content, re.DOTALL | re.IGNORECASE):
                            issues.append(SecurityIssue(
                                severity=Severity.HIGH,
                                category="JWT Security",
                                title=description,
                                description="Insecure JWT configuration detected",
                                location=str(file_path.relative_to(self.project_path)),
                                recommendation="Use RS256 algorithm and ensure proper token rotation"
                            ))
            except:
                continue
                
        if has_jwt:
            # Check for refresh token implementation
            try:
                settings_content = (self.project_path / "settings.py").read_text()
                if 'SIMPLE_JWT' in settings_content:
                    if 'REFRESH_TOKEN_LIFETIME' not in settings_content:
                        issues.append(SecurityIssue(
                            severity=Severity.MEDIUM,
                            category="JWT Security",
                            title="No refresh token configuration",
                            description="Refresh tokens not properly configured",
                            location="settings.py",
                            recommendation="Configure refresh token lifetime and rotation"
                        ))
            except:
                pass
                
        self._add_result("JWT Security Check", issues)
        
    def check_session_security(self):
        """Check session security configuration"""
        print(f"{Colors.YELLOW}[*] Checking session security...{Colors.END}")
        
        issues = []
        
        if DJANGO_AVAILABLE:
            try:
                # Check session settings
                if not getattr(settings, 'SESSION_COOKIE_HTTPONLY', False):
                    issues.append(SecurityIssue(
                        severity=Severity.HIGH,
                        category="Session Security",
                        title="Session cookies not HttpOnly",
                        description="Session cookies should be inaccessible to JavaScript",
                        location="settings.py",
                        recommendation="Set SESSION_COOKIE_HTTPONLY = True"
                    ))
                    
                if not getattr(settings, 'SESSION_COOKIE_SAMESITE', 'Lax') in ['Strict', 'Lax']:
                    issues.append(SecurityIssue(
                        severity=Severity.MEDIUM,
                        category="Session Security",
                        title="Weak SameSite cookie setting",
                        description="SameSite should be 'Strict' or 'Lax' for CSRF protection",
                        location="settings.py",
                        recommendation="Set SESSION_COOKIE_SAMESITE = 'Lax' or 'Strict'"
                    ))
                    
                session_timeout = getattr(settings, 'SESSION_COOKIE_AGE', 1209600)
                if session_timeout > 86400:  # More than 24 hours
                    issues.append(SecurityIssue(
                        severity=Severity.MEDIUM,
                        category="Session Security",
                        title="Session timeout too long",
                        description=f"Session timeout is {session_timeout} seconds ({session_timeout/3600:.1f} hours)",
                        location="settings.py",
                        recommendation="Set shorter session timeout (e.g., 3600 seconds for 1 hour)"
                    ))
                    
            except Exception as e:
                issues.append(SecurityIssue(
                    severity=Severity.LOW,
                    category="Session Security",
                    title="Error checking session settings",
                    description=str(e),
                    location="settings.py",
                    recommendation="Manually verify session configuration"
                ))
                
        self._add_result("Session Security Check", issues)
        
    def check_sql_injection_prevention(self):
        """Check for SQL injection vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Checking SQL injection prevention...{Colors.END}")
        
        issues = []
        
        # Look for raw SQL queries
        raw_sql_patterns = [
            r'\.raw\(',
            r'\.execute\(',
            r'cursor\(\)',
            r'connection\.cursor',
            r'extra\('
        ]
        
        python_files = list(self.project_path.rglob("*.py"))
        
        for file_path in python_files:
            try:
                content = file_path.read_text()
                for pattern in raw_sql_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Get context
                        start = max(0, match.start() - 100)
                        end = min(len(content), match.end() + 100)
                        context = content[start:end]
                        
                        issues.append(SecurityIssue(
                            severity=Severity.HIGH,
                            category="SQL Injection",
                            title="Potential raw SQL query detected",
                            description=f"Raw SQL method '{match.group()}' found. May be vulnerable to SQL injection.",
                            location=str(file_path.relative_to(self.project_path)),
                            recommendation="Use Django ORM or parameterized queries exclusively",
                            code_snippet=context,
                            cwe_id="CWE-89"
                        ))
            except:
                continue
                
        self._add_result("SQL Injection Prevention", issues)
        
    def check_xss_protection(self):
        """Check XSS protection measures"""
        print(f"{Colors.YELLOW}[*] Checking XSS protection...{Colors.END}")
        
        issues = []
        
        # Check for autoescape in templates
        template_files = list(self.project_path.rglob("*.html"))
        
        for file_path in template_files:
            try:
                content = file_path.read_text()
                
                # Check for unsafe filters
                unsafe_filters = ['safe', 'escapejs']
                for filter_name in unsafe_filters:
                    if f'|{filter_name}' in content:
                        # Get line with context
                        lines = content.split('\n')
                        for i, line in enumerate(lines):
                            if f'|{filter_name}' in line:
                                issues.append(SecurityIssue(
                                    severity=Severity.HIGH if filter_name == 'safe' else Severity.MEDIUM,
                                    category="XSS Protection",
                                    title=f"Unsafe template filter: |{filter_name}",
                                    description=f"Potentially unsafe filter usage in template",
                                    location=str(file_path.relative_to(self.project_path)),
                                    recommendation=f"Avoid |{filter_name} filter or ensure content is sanitized",
                                    code_snippet=f"Line {i+1}: {line.strip()}",
                                    cwe_id="CWE-79"
                                ))
            except:
                continue
                
        # Check CSP configuration
        if DJANGO_AVAILABLE:
            try:
                if not hasattr(settings, 'CSP_DEFAULT_SRC'):
                    issues.append(SecurityIssue(
                        severity=Severity.MEDIUM,
                        category="XSS Protection",
                        title="No Content Security Policy (CSP)",
                        description="CSP not configured for XSS protection",
                        location="settings.py",
                        recommendation="Implement django-csp middleware for CSP headers"
                    ))
            except:
                pass
                
        self._add_result("XSS Protection", issues)
        
    def check_email_security(self):
        """Check email system security"""
        print(f"{Colors.YELLOW}[*] Checking email security...{Colors.END}")
        
        issues = []
        
        # Look for email-related views
        email_patterns = [
            r'password_reset',
            r'email_verification',
            r'send_email',
            r'PasswordResetView'
        ]
        
        python_files = list(self.project_path.rglob("*.py"))
        
        for file_path in python_files:
            try:
                content = file_path.read_text()
                for pattern in email_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Check for rate limiting on email endpoints
                        if not ('@ratelimit' in content or 'throttle' in content):
                            issues.append(SecurityIssue(
                                severity=Severity.MEDIUM,
                                category="Email Security",
                                title="Email endpoint without rate limiting",
                                description=f"Email-related function without rate limiting protection",
                                location=str(file_path.relative_to(self.project_path)),
                                recommendation="Add rate limiting to email sending endpoints",
                                cwe_id="CWE-799"
                            ))
                        break
            except:
                continue
                
        self._add_result("Email System Security", issues)
        
    def check_cors_configuration(self):
        """Check CORS configuration"""
        print(f"{Colors.YELLOW}[*] Checking CORS configuration...{Colors.END}")
        
        issues = []
        
        if DJANGO_AVAILABLE:
            try:
                # Check if django-cors-headers is installed
                installed_apps = getattr(settings, 'INSTALLED_APPS', [])
                if 'corsheaders' not in installed_apps:
                    issues.append(SecurityIssue(
                        severity=Severity.MEDIUM,
                        category="CORS Configuration",
                        title="CORS headers not configured",
                        description="No CORS middleware detected",
                        location="settings.py",
                        recommendation="Install and configure django-cors-headers"
                    ))
                else:
                    # Check CORS settings
                    if getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False):
                        issues.append(SecurityIssue(
                            severity=Severity.HIGH,
                            category="CORS Configuration",
                            title="CORS allows all origins",
                            description="CORS_ALLOW_ALL_ORIGINS = True is insecure",
                            location="settings.py",
                            recommendation="Set CORS_ALLOWED_ORIGINS with specific domains"
                        ))
                        
                    allowed_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
                    if not allowed_origins and not getattr(settings, 'CORS_ALLOW_ALL_ORIGINS', False):
                        issues.append(SecurityIssue(
                            severity=Severity.MEDIUM,
                            category="CORS Configuration",
                            title="CORS origins not configured",
                            description="No CORS allowed origins specified",
                            location="settings.py",
                            recommendation="Set CORS_ALLOWED_ORIGINS with your frontend domains"
                        ))
            except Exception as e:
                issues.append(SecurityIssue(
                    severity=Severity.LOW,
                    category="CORS Configuration",
                    title="Error checking CORS configuration",
                    description=str(e),
                    location="settings.py",
                    recommendation="Manually verify CORS settings"
                ))
                
        self._add_result("CORS Configuration", issues)
        
    def check_input_validation(self):
        """Check input validation implementation"""
        print(f"{Colors.YELLOW}[*] Checking input validation...{Colors.END}")
        
        issues = []
        
        # Look for serializers and forms
        serializer_files = list(self.project_path.rglob("*serializer*.py"))
        form_files = list(self.project_path.rglob("*form*.py"))
        
        all_files = serializer_files + form_files
        
        for file_path in all_files[:10]:  # Limit to first 10 files
            try:
                content = file_path.read_text()
                
                # Check for validation patterns
                validation_patterns = [
                    (r'class.*Serializer', 'DRF Serializer validation'),
                    (r'class.*Form', 'Django Form validation'),
                    (r'\.validate_', 'Custom validation methods'),
                    (r'validators\s*=\s*\[', 'Field validators'),
                ]
                
                has_validation = any(pattern in content for pattern, _ in validation_patterns)
                
                if not has_validation and 'serializer' in str(file_path).lower():
                    issues.append(SecurityIssue(
                        severity=Severity.MEDIUM,
                        category="Input Validation",
                        title="Minimal input validation detected",
                        description="Serializer/Form may lack comprehensive validation",
                        location=str(file_path.relative_to(self.project_path)),
                        recommendation="Implement field-level validation and custom validation methods",
                        cwe_id="CWE-20"
                    ))
                    
                # Check for dangerous fields without validation
                dangerous_fields = ['FileField', 'ImageField', 'JSONField', 'CharField']
                for field in dangerous_fields:
                    if field in content:
                        # Check if field has validation
                        field_pattern = rf'{field}\('
                        if re.search(field_pattern, content):
                            # Look for validators or constraints near the field
                            lines = content.split('\n')
                            for i, line in enumerate(lines):
                                if field in line:
                                    # Check next few lines for validation
                                    context = '\n'.join(lines[max(0,i-2):min(len(lines),i+3)])
                                    if 'validators' not in context and 'max_length' not in context:
                                        issues.append(SecurityIssue(
                                            severity=Severity.LOW,
                                            category="Input Validation",
                                            title=f"Unvalidated {field}",
                                            description=f"{field} without explicit validation constraints",
                                            location=str(file_path.relative_to(self.project_path)),
                                            recommendation=f"Add validators and constraints to {field}",
                                            code_snippet=context,
                                            cwe_id="CWE-20"
                                        ))
                                    break
            except:
                continue
                
        self._add_result("Input Validation", issues)
        
    def check_file_upload_security(self):
        """Check file upload security"""
        print(f"{Colors.YELLOW}[*] Checking file upload security...{Colors.END}")
        
        issues = []
        
        # Look for file upload handling
        upload_patterns = [
            r'FileField',
            r'ImageField',
            r'request\.FILES',
            r'\.upload',
            r'UploadView'
        ]
        
        python_files = list(self.project_path.rglob("*.py"))
        
        for file_path in python_files:
            try:
                content = file_path.read_text()
                has_upload = any(pattern in content for pattern in upload_patterns)
                
                if has_upload:
                    # Check for security measures
                    security_checks = [
                        (r'content_type', 'Content type validation'),
                        (r'file_size', 'File size validation'),
                        (r'\.name\.endswith\(', 'File extension check'),
                        (r'virus', 'Virus scanning'),
                        (r'magic', 'File type verification'),
                    ]
                    
                    has_security = any(check in content for check, _ in security_checks)
                    
                    if not has_security:
                        issues.append(SecurityIssue(
                            severity=Severity.HIGH,
                            category="File Upload Security",
                            title="Insecure file upload handling",
                            description="File upload without proper security validation",
                            location=str(file_path.relative_to(self.project_path)),
                            recommendation="Implement file type validation, size limits, and virus scanning",
                            cwe_id="CWE-434"
                        ))
            except:
                continue
                
        self._add_result("File Upload Security", issues)
        
    def analyze_project_structure(self):
        """Analyze overall project structure"""
        print(f"{Colors.YELLOW}[*] Analyzing project structure...{Colors.END}")
        
        issues = []
        
        # Check for common Django project structure
        expected_dirs = ['static', 'templates', 'media']
        missing_dirs = []
        
        for dir_name in expected_dirs:
            dir_path = self.project_path / dir_name
            if not dir_path.exists():
                missing_dirs.append(dir_name)
                
        if missing_dirs:
            issues.append(SecurityIssue(
                severity=Severity.LOW,
                category="Project Structure",
                title="Missing common directories",
                description=f"Missing directories: {', '.join(missing_dirs)}",
                location="project root",
                recommendation="Create standard Django directories for better organization"
            ))
            
        # Check for requirements.txt
        if not (self.project_path / "requirements.txt").exists():
            issues.append(SecurityIssue(
                severity=Severity.LOW,
                category="Project Structure",
                title="No requirements.txt file",
                description="Missing dependencies specification",
                location="project root",
                recommendation="Create requirements.txt with pinned versions"
            ))
            
        self._add_result("Project Structure Analysis", issues)
        
    def check_authentication_flows(self):
        """Check authentication implementation"""
        print(f"{Colors.YELLOW}[*] Checking authentication flows...{Colors.END}")
        
        issues = []
        
        # Look for authentication views
        auth_patterns = [
            r'LoginView',
            r'logout',
            r'register',
            r'signup',
            r'authenticate'
        ]
        
        python_files = list(self.project_path.rglob("*.py"))
        has_auth = False
        
        for file_path in python_files:
            try:
                content = file_path.read_text()
                if any(pattern in content for pattern in auth_patterns):
                    has_auth = True
                    
                    # Check for security decorators
                    if '@login_required' not in content and 'LoginRequiredMixin' not in content:
                        issues.append(SecurityIssue(
                            severity=Severity.MEDIUM,
                            category="Authentication",
                            title="Missing authentication requirement",
                            description="View may lack authentication requirement",
                            location=str(file_path.relative_to(self.project_path)),
                            recommendation="Add @login_required decorator or LoginRequiredMixin",
                            cwe_id="CWE-306"
                        ))
                    break
            except:
                continue
                
        if not has_auth:
            issues.append(SecurityIssue(
                severity=Severity.INFO,
                category="Authentication",
                title="No custom authentication views found",
                description="Using Django's built-in auth or third-party package",
                location="views.py",
                recommendation="Ensure built-in auth is properly configured"
            ))
            
        self._add_result("Authentication Flow Analysis", issues)
        
    def check_monitoring_logging(self):
        """Check monitoring and logging configuration"""
        print(f"{Colors.YELLOW}[*] Checking monitoring and logging...{Colors.END}")
        
        issues = []
        
        # Check for logging configuration
        if DJANGO_AVAILABLE:
            try:
                logging_config = getattr(settings, 'LOGGING', {})
                if not logging_config:
                    issues.append(SecurityIssue(
                        severity=Severity.LOW,
                        category="Monitoring & Logging",
                        title="No logging configuration",
                        description="LOGGING setting not configured",
                        location="settings.py",
                        recommendation="Configure Django logging for security events"
                    ))
                else:
                    # Check for security logging
                    handlers = logging_config.get('handlers', {})
                    has_file_handler = any('FileHandler' in str(handler) for handler in handlers.values())
                    
                    if not has_file_handler:
                        issues.append(SecurityIssue(
                            severity=Severity.LOW,
                            category="Monitoring & Logging",
                            title="No file-based logging",
                            description="Logs may not be persisted",
                            location="settings.py",
                            recommendation="Add file handler to logging configuration"
                        ))
            except Exception as e:
                issues.append(SecurityIssue(
                    severity=Severity.LOW,
                    category="Monitoring & Logging",
                    title="Error checking logging configuration",
                    description=str(e),
                    location="settings.py",
                    recommendation="Manually verify logging setup"
                ))
                
        self._add_result("Monitoring & Logging", issues)
        
    def run_security_test_cases(self):
        """Run security-focused test cases"""
        print(f"{Colors.YELLOW}[*] Running security test cases...{Colors.END}")
        
        issues = []
        
        # Check if there are any security tests
        test_files = list(self.project_path.rglob("*test*.py"))
        has_security_tests = False
        
        for file_path in test_files:
            try:
                content = file_path.read_text().lower()
                security_keywords = ['csrf', 'xss', 'sql', 'injection', 'auth', 'permission', 'security']
                if any(keyword in content for keyword in security_keywords):
                    has_security_tests = True
                    break
            except:
                continue
                
        if not has_security_tests:
            issues.append(SecurityIssue(
                severity=Severity.MEDIUM,
                category="Testing",
                title="No security-focused test cases",
                description="Missing security-specific tests",
                location="tests/",
                recommendation="Create test cases for security vulnerabilities (CSRF, XSS, SQLi, auth)"
            ))
            
        self._add_result("Security Test Cases", issues)
        
    def check_secret_leakage(self):
        """Check for secret leakage in code"""
        print(f"{Colors.YELLOW}[*] Checking for secret leakage...{Colors.END}")
        
        issues = []
        
        # Common secret patterns
        secret_patterns = [
            (r'(?i)api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', "API Key"),
            (r'(?i)secret["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', "Secret"),
            (r'(?i)password["\']?\s*[:=]\s*["\'][^"\']{5,}["\']', "Password"),
            (r'(?i)token["\']?\s*[:=]\s*["\'][^"\']{10,}["\']', "Token"),
            (r'(?i)aws[_-]?access[_-]?key', "AWS Access Key"),
            (r'(?i)aws[_-]?secret[_-]?key', "AWS Secret Key"),
        ]
        
        # Check all Python files
        python_files = list(self.project_path.rglob("*.py"))
        
        for file_path in python_files:
            try:
                content = file_path.read_text()
                for pattern, secret_type in secret_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Get context
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 50)
                        context = content[start:end]
                        
                        issues.append(SecurityIssue(
                            severity=Severity.CRITICAL,
                            category="Secret Leakage",
                            title=f"Hardcoded {secret_type} detected",
                            description=f"Potential secret found in code",
                            location=str(file_path.relative_to(self.project_path)),
                            recommendation=f"Remove hardcoded {secret_type}. Use environment variables.",
                            code_snippet=context,
                            cwe_id="CWE-798"
                        ))
            except:
                continue
                
        self._add_result("Secret Leakage Check", issues)
        
    def _add_result(self, test_name: str, issues: List[SecurityIssue]):
        """Add test result to overall results"""
        passed = len(issues) == 0
        
        result = TestResult(
            passed=passed,
            test_name=test_name,
            details=f"Found {len(issues)} issues" if issues else "No issues found",
            issues=issues.copy()
        )
        
        self.results.append(result)
        self.issues.extend(issues)
        
        # Print immediate result
        if passed:
            print(f"  {Colors.GREEN}✓ {test_name}: PASSED{Colors.END}")
        else:
            print(f"  {Colors.RED}✗ {test_name}: FAILED ({len(issues)} issues){Colors.END}")
            
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive scan report"""
        
        # Calculate statistics
        total_issues = len(self.issues)
        issues_by_severity = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        
        for issue in self.issues:
            issues_by_severity[issue.severity.value] += 1
            
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.passed)
        
        # Prepare report data
        self.report_data["results"] = [
            {
                "test_name": r.test_name,
                "passed": r.passed,
                "details": r.details,
                "issues": [
                    {
                        "severity": i.severity.value,
                        "category": i.category,
                        "title": i.title,
                        "description": i.description,
                        "location": i.location,
                        "recommendation": i.recommendation,
                        "cwe_id": i.cwe_id,
                        "cvss_score": i.cvss_score
                    } for i in r.issues
                ]
            } for r in self.results
        ]
        
        self.report_data["summary"] = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "total_issues": total_issues,
            "issues_by_severity": issues_by_severity,
            "risk_score": self._calculate_risk_score(issues_by_severity)
        }
        
        return self.report_data
        
    def _calculate_risk_score(self, issues_by_severity: Dict[str, int]) -> float:
        """Calculate overall risk score (0-100)"""
        weights = {
            Severity.CRITICAL.value: 10,
            Severity.HIGH.value: 5,
            Severity.MEDIUM.value: 2,
            Severity.LOW.value: 1,
            Severity.INFO.value: 0.5,
        }
        
        score = sum(
            count * weights[severity]
            for severity, count in issues_by_severity.items()
        )
        
        # Normalize to 0-100 scale
        max_possible = 100  # Arbitrary maximum
        return min(score, max_possible)
        
    def print_report(self, report_data: Dict[str, Any]):
        """Print formatted report to console"""
        
        summary = report_data["summary"]
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print("ZEROTRUSTDJANGO SCAN REPORT")
        print(f"{'='*60}{Colors.END}\n")
        
        # Print summary
        print(f"{Colors.BOLD}SUMMARY:{Colors.END}")
        print(f"  Tests Run: {summary['total_tests']}")
        print(f"  Tests Passed: {Colors.GREEN if summary['passed_tests'] == summary['total_tests'] else Colors.YELLOW}"
              f"{summary['passed_tests']}{Colors.END}")
        print(f"  Tests Failed: {Colors.RED if summary['failed_tests'] > 0 else Colors.GREEN}"
              f"{summary['failed_tests']}{Colors.END}")
        print(f"  Total Issues: {Colors.RED if summary['total_issues'] > 0 else Colors.GREEN}"
              f"{summary['total_issues']}{Colors.END}")
        print(f"  Risk Score: {self._get_risk_color(summary['risk_score'])}{summary['risk_score']:.1f}/100{Colors.END}")
        
        # Print severity breakdown
        print(f"\n{Colors.BOLD}ISSUES BY SEVERITY:{Colors.END}")
        for severity, count in summary["issues_by_severity"].items():
            color = self._get_severity_color(severity)
            print(f"  {color}{severity}: {count}{Colors.END}")
            
        # Print detailed results
        print(f"\n{Colors.BOLD}DETAILED RESULTS:{Colors.END}")
        for result in report_data["results"]:
            status_color = Colors.GREEN if result["passed"] else Colors.RED
            status_icon = "✓" if result["passed"] else "✗"
            
            print(f"\n  {status_color}{status_icon} {result['test_name']}{Colors.END}")
            print(f"    Details: {result['details']}")
            
            if result["issues"]:
                for issue in result["issues"]:
                    severity_color = self._get_severity_color(issue["severity"])
                    print(f"    {severity_color}[{issue['severity']}] {issue['title']}{Colors.END}")
                    print(f"      Location: {issue['location']}")
                    print(f"      Recommendation: {issue['recommendation']}")
                    
        # Print recommendations
        print(f"\n{Colors.BOLD}{Colors.YELLOW}RECOMMENDATIONS:{Colors.END}")
        
        critical_issues = [i for i in self.issues if i.severity in [Severity.CRITICAL, Severity.HIGH]]
        if critical_issues:
            print(f"\n{Colors.RED}CRITICAL ACTIONS REQUIRED:{Colors.END}")
            for i, issue in enumerate(critical_issues[:5], 1):
                print(f"  {i}. {issue.recommendation}")
                
        if summary["risk_score"] > 50:
            print(f"\n{Colors.RED}⚠️  HIGH RISK DETECTED - Immediate remediation required{Colors.END}")
        elif summary["risk_score"] > 20:
            print(f"\n{Colors.YELLOW}⚠️  MEDIUM RISK - Address issues promptly{Colors.END}")
        else:
            print(f"\n{Colors.GREEN}✅ LOW RISK - Good security posture{Colors.END}")
            
        # Save report to file
        report_file = self.project_path / f"security_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
            
        print(f"\n{Colors.BLUE}📄 Full report saved to: {report_file}{Colors.END}")
        
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH": Colors.RED,
            "MEDIUM": Colors.YELLOW,
            "LOW": Colors.BLUE,
            "INFO": Colors.CYAN,
        }
        return colors.get(severity, Colors.WHITE)
        
    def _get_risk_color(self, score: float) -> str:
        """Get color code for risk score"""
        if score >= 70:
            return Colors.RED + Colors.BOLD
        elif score >= 40:
            return Colors.YELLOW
        elif score >= 20:
            return Colors.BLUE
        else:
            return Colors.GREEN

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="ZeroTrustDjango Security Scanner - Comprehensive Django security auditing tool"
    )
    
    parser.add_argument(
        "project_path",
        help="Path to Django project directory"
    )
    
    parser.add_argument(
        "--type",
        choices=["normal", "security"],
        default="security",
        help="Type of test to run (default: security)"
    )
    
    parser.add_argument(
        "--output",
        choices=["console", "json", "both"],
        default="both",
        help="Output format (default: both)"
    )
    
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick scan (skip some time-consuming checks)"
    )
    
    args = parser.parse_args()
    
    # Validate project path
    project_path = Path(args.project_path)
    if not project_path.exists():
        print(f"{Colors.RED}Error: Project path '{project_path}' does not exist{Colors.END}")
        sys.exit(1)
        
    # Check for manage.py
    if not (project_path / "manage.py").exists():
        print(f"{Colors.YELLOW}Warning: manage.py not found in '{project_path}'{Colors.END}")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
            
    # Initialize scanner
    scanner = ZeroTrustDjangoScanner(args.project_path)
    
    # Run scan
    test_type = TestType(args.type)
    report_data = scanner.run_test(test_type)
    
    # Output results
    if args.output in ["console", "both"]:
        scanner.print_report(report_data)
        
    if args.output in ["json", "both"]:
        report_file = project_path / f"security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        print(f"\nJSON report saved to: {report_file}")
        
    # Exit with appropriate code
    if report_data["summary"]["total_issues"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
