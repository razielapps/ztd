# config/__init__.py
"""
ZeroTrustDjango Scanner Configuration
"""

SCANNER_CONFIG = {
    "version": "1.0.0",
    "name": "ZeroTrustDjango Security Scanner",
    "checks": {
        "foundational": [
            "environment_variables",
            "django_settings",
            "dependencies"
        ],
        "authentication": [
            "rate_limiting",
            "jwt_security",
            "session_security"
        ],
        "data_security": [
            "sql_injection",
            "xss_protection",
            "email_security"
        ],
        "infrastructure": [
            "cors_configuration",
            "input_validation",
            "file_upload_security"
        ],
        "advanced": [
            "project_structure",
            "authentication_flows",
            "monitoring_logging",
            "security_tests",
            "secret_leakage"
        ]
    },
    "severity_weights": {
        "CRITICAL": 10,
        "HIGH": 5,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0.5
    },
    "risk_thresholds": {
        "high": 70,
        "medium": 40,
        "low": 20
    }
}

# Default security headers to check
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

# Common vulnerable patterns
VULNERABLE_PATTERNS = {
    "sql_injection": [
        r"\.raw\(",
        r"\.execute\(",
        r"cursor\(\)",
        r"connection\.cursor",
        r"extra\("
    ],
    "xss": [
        r"\|safe",
        r"\|escapejs",
        r"mark_safe\(",
        r"HttpResponse\(.*\)"
    ],
    "secrets": [
        r'(?i)api[_-]?key["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
        r'(?i)secret["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
        r'(?i)password["\']?\s*[:=]\s*["\'][^"\']{5,}["\']',
        r'(?i)token["\']?\s*[:=]\s*["\'][^"\']{10,}["\']',
    ]
}
