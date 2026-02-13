#!/usr/bin/env python3
"""
Guardrail Scanner for Governance Control Plane
TDD implementation - Layer 3: Validation Engine

Scans code for forbidden patterns and security violations.
"""

import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class GuardrailLevel(Enum):
    """Severity levels for guardrail violations."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class GuardrailViolation:
    """Represents a guardrail violation."""
    rule_id: str
    level: GuardrailLevel
    message: str
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    suggested_fix: str = ""


@dataclass
class GuardrailScanResult:
    """Results of a guardrail scan."""
    violations: List[GuardrailViolation] = field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    scan_duration_ms: float = 0.0
    
    @property
    def passed(self) -> bool:
        """Check if scan passed (no critical/high violations)."""
        return not any(
            v.level in (GuardrailLevel.CRITICAL, GuardrailLevel.HIGH) 
            for v in self.violations
        )
    
    @property
    def violation_count(self) -> int:
        """Total violation count."""
        return len(self.violations)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "violations": [
                {
                    "ruleId": v.rule_id,
                    "level": v.level.value,
                    "message": v.message,
                    "filePath": v.file_path,
                    "lineNumber": v.line_number,
                    "codeSnippet": v.code_snippet,
                    "suggestedFix": v.suggested_fix,
                }
                for v in self.violations
            ],
            "filesScanned": self.files_scanned,
            "linesScanned": self.lines_scanned,
            "scanDurationMs": self.scan_duration_ms,
            "passed": self.passed,
            "violationCount": self.violation_count,
        }


# Forbidden patterns for different languages

PYTHON_FORBIDDEN = {
    "eval_usage": {
        "pattern": re.compile(r'\beval\s*\('),
        "level": GuardrailLevel.HIGH,
        "message": "Use of eval() is forbidden - RCE risk",
        "suggestion": "Use AST parsing or safe evaluation",
    },
    "exec_usage": {
        "pattern": re.compile(r'\bexec\s*\('),
        "level": GuardrailLevel.HIGH,
        "message": "Use of exec() is forbidden - RCE risk",
        "suggestion": "Use safe alternatives",
    },
    "pickle_load": {
        "pattern": re.compile(r'pickle\.loads?\('),
        "level": GuardrailLevel.HIGH,
        "message": "Use of pickle is forbidden - deserialization risk",
        "suggestion": "Use JSON or schema validation",
    },
    "subprocess_shell": {
        "pattern": re.compile(r'subprocess\.run\([^)]*shell\s*=\s*True'),
        "level": GuardrailLevel.HIGH,
        "message": "subprocess with shell=True is forbidden",
        "suggestion": "Use shell=False with argument list",
    },
    "os_system": {
        "pattern": re.compile(r'os\.system\('),
        "level": GuardrailLevel.HIGH,
        "message": "os.system() is forbidden - shell injection risk",
        "suggestion": "Use subprocess with argument list",
    },
    "hardcoded_secret": {
        "pattern": re.compile(r'(?:password|secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
        "level": GuardrailLevel.CRITICAL,
        "message": "Hardcoded secret detected",
        "suggestion": "Use environment variables or secrets manager",
    },
    "sql_injection": {
        "pattern": re.compile(r'(?:execute|executemany|cursor\.)\s*\([^)]*\+[^)]*\)'),
        "level": GuardrailLevel.CRITICAL,
        "message": "Potential SQL injection risk - use parameterized queries",
        "suggestion": "Use parameterized queries",
    },
    "yamlunsafe": {
        "pattern": re.compile(r'yaml\.unsafe_load\('),
        "level": GuardrailLevel.HIGH,
        "message": "yaml.unsafe_load() is forbidden - arbitrary code execution risk",
        "suggestion": "Use yaml.safe_load() or SafeLoader",
    },
    "temp_file_insecure": {
        "pattern": re.compile(r'TemporaryFile\s*\(\s*mode\s*=\s*[\'"]w[\'"]'),
        "level": GuardrailLevel.MEDIUM,
        "message": "Insecure temporary file creation",
        "suggestion": "Use NamedTemporaryFile with delete=True",
    },
    "debug_true": {
        "pattern": re.compile(r'debug\s*=\s*True', re.IGNORECASE),
        "level": GuardrailLevel.MEDIUM,
        "message": "Debug mode enabled in production code",
        "suggestion": "Set debug=False for production",
    },
}

JAVASCRIPT_FORBIDDEN = {
    "eval_usage": {
        "pattern": re.compile(r'\beval\s*\('),
        "level": GuardrailLevel.HIGH,
        "message": "Use of eval() is forbidden",
        "suggestion": "Use JSON.parse or safe alternatives",
    },
    "inner_html": {
        "pattern": re.compile(r'innerHTML\s*='),
        "level": GuardrailLevel.MEDIUM,
        "message": "Direct innerHTML assignment - XSS risk",
        "suggestion": "Use textContent or sanitize input",
    },
    "hardcoded_secret": {
        "pattern": re.compile(r'(?:password|secret|apiKey|token)\s*[:=]\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
        "level": GuardrailLevel.CRITICAL,
        "message": "Hardcoded secret detected",
        "suggestion": "Use environment variables",
    },
    "sql_injection": {
        "pattern": re.compile(r'\.query\s*\(\s*[\'"][^\'"]*\+'),
        "level": GuardrailLevel.CRITICAL,
        "message": "Potential SQL injection risk",
        "suggestion": "Use parameterized queries",
    },
    "unsafe_redirect": {
        "pattern": re.compile(r'window\.location\s*=\s*\S+'),
        "level": GuardrailLevel.MEDIUM,
        "message": "Potential unvalidated redirect",
        "suggestion": "Validate and whitelist URLs",
    },
}


class GuardrailScanner:
    """
    Scanner for forbidden patterns in code.
    """
    
    def __init__(self, custom_rules: Optional[Dict[str, Dict]] = None):
        """
        Initialize scanner with rules.
        
        Args:
            custom_rules: Optional custom rules to add/override
        """
        self.rules = PYTHON_FORBIDDEN.copy()
        if custom_rules:
            self.rules.update(custom_rules)
    
    def scan_file(self, file_path: str) -> List[GuardrailViolation]:
        """
        Scan a single file for violations.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of violations found
        """
        violations = []
        
        # Determine language and use appropriate rules
        if file_path.endswith(".py"):
            rules = PYTHON_FORBIDDEN
        elif file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
            rules = JAVASCRIPT_FORBIDDEN
        else:
            # Skip unknown file types
            return violations
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (IOError, UnicodeDecodeError):
            return violations
        
        for line_num, line in enumerate(lines, start=1):
            for rule_id, rule in rules.items():
                pattern = rule["pattern"]
                if pattern.search(line):
                    violations.append(GuardrailViolation(
                        rule_id=rule_id,
                        level=rule["level"],
                        message=rule["message"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip()[:100],
                        suggested_fix=rule["suggestion"],
                    ))
        
        return violations
    
    def scan_directory(self, directory: str, extensions: Optional[List[str]] = None) -> GuardrailScanResult:
        """
        Scan a directory recursively.
        
        Args:
            directory: Directory to scan
            extensions: File extensions to scan (default: .py, .js, .ts)
            
        Returns:
            Scan results
        """
        if extensions is None:
            extensions = [".py", ".js", ".ts", ".jsx", ".tsx"]
        
        violations = []
        files_scanned = 0
        lines_scanned = 0
        
        directory_path = Path(directory)
        
        for file_path in directory_path.rglob("*"):
            if file_path.is_file() and any(str(file_path).endswith(ext) for ext in extensions):
                # Skip node_modules, venv, __pycache__, etc.
                if any(skip in str(file_path) for skip in ["node_modules", "venv", "__pycache__", ".git", ".next"]):
                    continue
                
                file_violations = self.scan_file(str(file_path))
                violations.extend(file_violations)
                files_scanned += 1
                
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        lines_scanned += len(f.readlines())
                except (IOError, UnicodeDecodeError):
                    pass
        
        return GuardrailScanResult(
            violations=violations,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
        )
    
    def scan_code_string(self, code: str, language: str = "python") -> List[GuardrailViolation]:
        """
        Scan a code string directly.
        
        Args:
            code: Code to scan
            language: Language (python or javascript)
            
        Returns:
            List of violations found
        """
        violations = []
        
        if language == "python":
            rules = PYTHON_FORBIDDEN
        elif language == "javascript":
            rules = JAVASCRIPT_FORBIDDEN
        else:
            return violations
        
        lines = code.split("\n")
        
        for line_num, line in enumerate(lines, start=1):
            for rule_id, rule in rules.items():
                pattern = rule["pattern"]
                if pattern.search(line):
                    violations.append(GuardrailViolation(
                        rule_id=rule_id,
                        level=rule["level"],
                        message=rule["message"],
                        line_number=line_num,
                        code_snippet=line.strip()[:100],
                        suggested_fix=rule["suggestion"],
                    ))
        
        return violations


# Convenience function

def scan_for_violations(path: str) -> GuardrailScanResult:
    """
    Scan a file or directory for guardrail violations.
    
    Args:
        path: File or directory path
        
    Returns:
        Scan results
    """
    scanner = GuardrailScanner()
    
    if Path(path).is_file():
        violations = scanner.scan_file(path)
        return GuardrailScanResult(
            violations=violations,
            files_scanned=1,
        )
    else:
        return scanner.scan_directory(path)
