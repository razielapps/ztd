# ZeroTrustDjango Security Scanner

![ZeroTrustDjango Banner](https://img.shields.io/badge/ZeroTrustDjango-Security%20Scanner-blue)
![Python Version](https://img.shields.io/badge/python-3.8%2B-green)
![Django Version](https://img.shields.io/badge/django-3.2%2B-green)
![License](https://img.shields.io/badge/license-MIT-blue)

**ZeroTrustDjango** is a comprehensive security auditing and testing tool for Django applications that implements the Zero Trust security model. It performs automated security scanning, vulnerability detection, and compliance checking to ensure your Django applications follow security best practices.

## 🚀 Features

### 🔍 **Comprehensive Security Checks**
- **Foundational Security**: Environment variables, Django settings, middleware order
- **Dependency Audit**: Vulnerability scanning with `safety` and `pip-audit`
- **API Security**: Rate limiting, JWT validation, session security
- **Data Security**: SQL injection prevention, XSS protection, email security
- **Infrastructure**: CORS configuration, input validation, file upload security

### 📊 **Detailed Reporting**
- **Color-coded console output** with severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **JSON reports** for CI/CD integration
- **HTML reports** with interactive filtering
- **Risk scoring** (0-100 scale)
- **Actionable recommendations**

### ⚡ **Advanced Capabilities**
- **OWASP ZAP integration** for automated penetration testing
- **Custom plugin system** for extending checks
- **CI/CD ready** with multiple output formats
- **Programmatic API** for integration into workflows

## 📋 Prerequisites

- **Python**: 3.8 or higher
- **Django**: 3.2 or higher (for scanning Django projects)
- **pip**: Latest version
- **Virtual environment** (recommended)

## 🛠️ Installation

### Quick Install (Linux/macOS)

```bash
# Clone the repository
git clone https://github.com/yourusername/zerotrustdjango-scanner.git
cd zerotrustdjango-scanner

# Run installation script
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements-scanner.txt

# Make scanner executable
chmod +x zero_trust_scanner.py
```

### Docker Installation

```bash
# Build Docker image
docker build -t zerotrustdjango .

# Run scanner in container
docker run -v $(pwd):/app zerotrustdjango /app/zero_trust_scanner.py /app/your-django-project
```

## 🚦 Quick Start

### Basic Usage

```bash
# Run security scan on a Django project
./zero_trust_scanner.py /path/to/your/django/project --type security

# Run normal Django tests
./zero_trust_scanner.py /path/to/your/django/project --type normal

# Quick scan (skip time-consuming checks)
./zero_trust_scanner.py /path/to/your/django/project --type security --quick

# Specify output format
./zero_trust_scanner.py /path/to/your/django/project --type security --output both
```

### Example Output

```
============================================================
ZeroTrustDjango Scanner
Scan Type: SECURITY
Project: /path/to/your/django/project
============================================================

[*] Starting comprehensive security scan...
[*] Checking environment variables and secrets...
  ✗ Environment Variables Check: FAILED (2 issues)
[*] Checking Django security settings...
  ✓ Django Security Settings: PASSED
[*] Auditing dependencies...
  ✗ Dependency Audit: FAILED (1 issues)

...

SUMMARY:
  Tests Run: 15
  Tests Passed: 10
  Tests Failed: 5
  Total Issues: 8
  Risk Score: 45.5/100

ISSUES BY SEVERITY:
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 3
  LOW: 2
  INFO: 0

📄 Full report saved to: security_scan_20240101_120000.json
```

## 📖 Command Line Reference

### Basic Syntax

```bash
./zero_trust_scanner.py PROJECT_PATH [OPTIONS]
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `PROJECT_PATH` | Path to Django project directory |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--type {normal,security}` | Type of test to run | `security` |
| `--output {console,json,both}` | Output format | `both` |
| `--quick` | Run quick scan (skip time-consuming checks) | `False` |
| `--help` | Show help message | - |

### Examples

```bash
# Full security scan with JSON output
./zero_trust_scanner.py /var/www/myapp --type security --output json

# Quick scan for CI/CD
./zero_trust_scanner.py . --type security --quick --output json

# Normal Django tests
./zero_trust_scanner.py /home/user/project --type normal
```

## 🔧 Configuration

### Configuration File

Create `config/scanner_config.yaml` for custom configuration:

```yaml
version: "1.0"
scanner:
  checks:
    foundational:
      - environment_variables
      - django_settings
      - dependencies
    authentication:
      - rate_limiting
      - jwt_security
      - session_security
    data_security:
      - sql_injection
      - xss_protection
    infrastructure:
      - cors_configuration
      - input_validation
  
  severity_weights:
    CRITICAL: 10
    HIGH: 5
    MEDIUM: 2
    LOW: 1
    INFO: 0.5
  
  risk_thresholds:
    high: 70
    medium: 40
    low: 20
  
  excluded_paths:
    - "*/migrations/*"
    - "*/tests/*"
    - "*/venv/*"
    - "*/node_modules/*"
```

### Environment Variables

```bash
# Scanner configuration
export ZTD_SCANNER_QUICK_MODE=true
export ZTD_OUTPUT_FORMAT=json
export ZTD_RISK_THRESHOLD=50

# Security tool integration
export SAFETY_API_KEY=your_safety_api_key
export ZAP_API_KEY=your_zap_api_key
export ZAP_HOST=http://localhost:8080
```

## 📊 Security Checks Reference

### 1. Foundational Security

| Check | Description | Severity |
|-------|-------------|----------|
| Environment Variables | Hardcoded secrets, missing env var management | CRITICAL |
| Django Settings | DEBUG mode, SSL redirects, secure headers | HIGH |
| Dependency Audit | Vulnerable packages, outdated dependencies | HIGH |

### 2. API & Authentication Security

| Check | Description | Severity |
|-------|-------------|----------|
| Rate Limiting | Missing rate limits on auth endpoints | MEDIUM |
| JWT Security | Weak algorithms, missing token rotation | HIGH |
| Session Security | Insecure cookie settings, long timeouts | HIGH |

### 3. Data & Business Logic Security

| Check | Description | Severity |
|-------|-------------|----------|
| SQL Injection | Raw SQL queries, unsafe ORM usage | CRITICAL |
| XSS Protection | Unsafe template filters, missing CSP | HIGH |
| Email Security | Missing rate limits, token expiration | MEDIUM |

### 4. Infrastructure & Deployment Security

| Check | Description | Severity |
|-------|-------------|----------|
| CORS Configuration | Overly permissive CORS settings | MEDIUM |
| Input Validation | Missing validation in serializers/forms | MEDIUM |
| File Upload Security | Missing file type/size validation | HIGH |

## 🔌 Plugin System

### Creating Custom Plugins

Create `plugins/custom_checks.py`:

```python
from zero_trust_scanner import SecurityIssue, Severity

class CustomSecurityCheck:
    def __init__(self, project_path):
        self.project_path = project_path
    
    def check_custom_vulnerability(self):
        """Example custom check"""
        issues = []
        
        # Your check logic here
        issues.append(SecurityIssue(
            severity=Severity.MEDIUM,
            category="Custom Check",
            title="Custom vulnerability found",
            description="Description of the issue",
            location="file.py",
            recommendation="How to fix it"
        ))
        
        return issues
```

### Registering Plugins

```python
# In your scanner configuration
from plugins.custom_checks import CustomSecurityCheck

scanner = ZeroTrustDjangoScanner(project_path)
custom_check = CustomSecurityCheck(project_path)
scanner.custom_checks = [custom_check.check_custom_vulnerability]
```

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements-scanner.txt
        pip install safety pip-audit
    
    - name: Run ZeroTrustDjango Scanner
      run: |
        python zero_trust_scanner.py . --type security --output json --quick
    
    - name: Upload security report
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-report
        path: security_report_*.json
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - test
  - security

security_scan:
  stage: security
  image: python:3.11
  before_script:
    - pip install -r requirements-scanner.txt
    - pip install safety pip-audit
  script:
    - python zero_trust_scanner.py . --type security --output json --quick
  artifacts:
    reports:
      security: security_report_*.json
    paths:
      - security_report_*.json
  only:
    - merge_requests
    - main
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh '''
                    python -m venv venv
                    source venv/bin/activate
                    pip install -r requirements-scanner.txt
                    python zero_trust_scanner.py . --type security --output json
                    '''
                }
            }
            post {
                always {
                    junit 'security_report_*.json'
                }
            }
        }
    }
}
```

## 🧪 Testing Your Application

### Pre-production Scan

```bash
# Full comprehensive scan
./zero_trust_scanner.py /path/to/project --type security

# Generate HTML report for stakeholders
./zero_trust_scanner.py /path/to/project --type security --output html

# Check specific security aspects
./zero_trust_scanner.py /path/to/project --quick --type security
```

### Continuous Monitoring

```bash
# Add to your deploy script
echo "Running security scan..."
if ./zero_trust_scanner.py . --type security --quick --output json; then
    echo "Security checks passed!"
else
    echo "Security issues found! Check security_report.json"
    exit 1
fi
```

### Integration with Django Management Commands

Create `management/commands/security_scan.py`:

```python
from django.core.management.base import BaseCommand
from zero_trust_scanner import ZeroTrustDjangoScanner, TestType

class Command(BaseCommand):
    help = 'Run ZeroTrustDjango security scan'
    
    def handle(self, *args, **options):
        scanner = ZeroTrustDjangoScanner('.')
        report = scanner.run_test(TestType.SECURITY)
        
        if report['summary']['total_issues'] > 0:
            self.stdout.write(
                self.style.ERROR(
                    f"Found {report['summary']['total_issues']} security issues!"
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS("All security checks passed!")
            )
```

Then run:
```bash
python manage.py security_scan
```

## 📈 Interpreting Results

### Risk Score Interpretation

| Score Range | Risk Level | Action Required |
|-------------|------------|-----------------|
| 0-20 | Low | Good security posture |
| 21-40 | Medium | Review and fix issues |
| 41-70 | High | Immediate attention needed |
| 71-100 | Critical | Stop deployment, fix immediately |

### Issue Severity Guidelines

- **CRITICAL**: Fix immediately (e.g., hardcoded secrets, SQL injection)
- **HIGH**: Fix before next release (e.g., insecure Django settings)
- **MEDIUM**: Fix in next sprint (e.g., missing rate limiting)
- **LOW**: Consider fixing (e.g., project structure issues)
- **INFO**: Informational only

## 🔗 Integration with Other Tools

### OWASP ZAP Integration

```python
from plugins.owasp_zap_integration import OWASPZAPIntegration

# Initialize ZAP integration
zap = OWASPZAPIntegration(zap_host="http://localhost:8080")

# Run ZAP scan and integrate results
zap_alerts = zap.get_alerts(risk_level="high")
zap_issues = zap.integrate_with_scanner(scanner_issues)

# Generate combined report
combined_report = scanner.generate_report()
combined_report["zap_findings"] = zap_alerts
```

### Safety Integration

```bash
# Install safety
pip install safety

# Run safety check
safety check -r requirements.txt --json

# The scanner automatically uses safety if available
```

### Bandit Integration (Static Analysis)

```python
import subprocess
import json

def run_bandit_scan(project_path):
    """Run bandit static analysis"""
    result = subprocess.run(
        ['bandit', '-r', project_path, '-f', 'json'],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        return json.loads(result.stdout)
    return {}
```

## 🛡️ Security Best Practices

### Recommended Django Settings

```python
# settings.py - Security Recommendations
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000  # 1 year
X_FRAME_OPTIONS = 'DENY'
```

### Environment Management

```python
# Use python-decouple for secrets
from decouple import config

SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
DATABASE_URL = config('DATABASE_URL', default='sqlite:///db.sqlite3')
```

### Regular Scanning Schedule

```bash
# Daily scan (add to cron)
0 2 * * * cd /path/to/project && ./zero_trust_scanner.py . --type security --quick >> /var/log/security-scan.log

# Pre-commit hook
# Add to .git/hooks/pre-commit
#!/bin/bash
./zero_trust_scanner.py . --type security --quick --output json
if [ $? -ne 0 ]; then
    echo "Security issues found! Commit blocked."
    exit 1
fi
```

## 🚨 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **Django not found** | Install Django or run scanner within Django environment |
| **Permission denied** | Make script executable: `chmod +x zero_trust_scanner.py` |
| **Missing dependencies** | Install from requirements: `pip install -r requirements-scanner.txt` |
| **Scan takes too long** | Use `--quick` flag to skip time-consuming checks |
| **False positives** | Review and customize checks in configuration |

### Debug Mode

```bash
# Enable verbose output
export ZTD_DEBUG=1
./zero_trust_scanner.py /path/to/project --type security

# Or with Python debug
python -m pdb zero_trust_scanner.py /path/to/project --type security
```

## 📚 API Reference

### Programmatic Usage

```python
from zero_trust_scanner import ZeroTrustDjangoScanner, TestType

# Initialize scanner
scanner = ZeroTrustDjangoScanner("/path/to/project")

# Run scan
report = scanner.run_test(TestType.SECURITY)

# Access results
print(f"Total issues: {report['summary']['total_issues']}")
print(f"Risk score: {report['summary']['risk_score']}")

# Get critical issues
critical_issues = [
    issue for result in report['results']
    for issue in result['issues']
    if issue['severity'] == 'CRITICAL'
]

# Export to different formats
from utils.exporters import JSONExporter, HTMLExporter

json_exporter = JSONExporter(report)
json_exporter.export(Path("report.json"))

html_exporter = HTMLExporter(report)
html_exporter.export(Path("report.html"))
```

### Customizing Scans

```python
class CustomScanner(ZeroTrustDjangoScanner):
    def __init__(self, project_path):
        super().__init__(project_path)
        self.custom_checks = [
            self.check_custom_vulnerability,
            self.check_api_endpoints
        ]
    
    def check_custom_vulnerability(self):
        """Your custom security check"""
        # Implementation here
        pass
    
    def run_custom_scan(self):
        """Run scan with custom checks"""
        for check in self.custom_checks:
            check()
```

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Run tests**
   ```bash
   python -m pytest tests/
   ```
5. **Commit your changes**
   ```bash
   git commit -m 'Add amazing feature'
   ```
6. **Push to the branch**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Development Setup

```bash
# Clone repository
git clone https://github.com/razielapps/ztd.git
cd zerotrustdjango-scanner

# Set up development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .

# Run tests
pytest tests/

# Run linter
pylint ztd.py

# Run type checking
mypy ztd.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Django Security Team** for security best practices
- **OWASP Foundation** for security guidelines
- **Safety** and **pip-audit** for dependency scanning
- **All contributors** who help improve this tool

## 📞 Support

- **Imail**: avtxconscience@gmail.com


---

**ZeroTrustDjango Scanner** - Because security should never be an afterthought. 🔐
