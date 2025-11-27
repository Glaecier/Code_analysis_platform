#!/usr/bin/env python3
"""
Code Analysis API - Server Component
Run with: uvicorn code_analyzer_api:app --reload
"""

import subprocess
import tempfile
import os
import re
import json
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List
from fastapi.middleware.cors import CORSMiddleware

# ===== FASTAPI SERVER SETUP =====

app = FastAPI(title="Code Analysis API")
# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins - for hackathon
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Data Models
class LintIssue(BaseModel):
    line: int
    column: int
    message: str
    code: str
    severity: str

class SecurityIssue(BaseModel):
    line: int
    message: str
    code: str
    severity: str
    confidence: str
    cwe: str
    description: str

class TestResult(BaseModel):
    test_name: str
    passed: bool
    output: str

class CodeSubmission(BaseModel):
    code: str
    test_code: Optional[str] = None
    language: str = "python"

class AnalysisResult(BaseModel):
    lint_issues: List[LintIssue]
    lint_summary: dict
    security_issues: List[SecurityIssue]
    security_summary: dict
    test_results: List[TestResult]
    test_summary: dict
    success: bool
    error: Optional[str] = None

# ===== ANALYSIS ENGINE =====

def parse_flake8_output(output: str) -> dict:
    """Convert flake8 raw output to structured data"""
    issues = []

    for line in output.strip().split('\n'):
        if not line:
            continue

        match = re.match(r'[^:]+:(\d+):(\d+): (\w+)\s+(.+)', line)
        if match:
            line_num, col_num, code, message = match.groups()

            if code.startswith('E') or code.startswith('F'):
                severity = 'error'
            elif code.startswith('W'):
                severity = 'warning'
            else:
                severity = 'info'

            issues.append({
                'line': int(line_num),
                'column': int(col_num),
                'message': message.strip(),
                'code': code,
                'severity': severity
            })

    summary = {
        'total_issues': len(issues),
        'errors': len([i for i in issues if i['severity'] == 'error']),
        'warnings': len([i for i in issues if i['severity'] == 'warning']),
        'info': len([i for i in issues if i['severity'] == 'info'])
    }

    return {'issues': issues, 'summary': summary}

def run_flake8_analysis(code: str) -> dict:
    """Run flake8 on the provided code and return structured results"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_file = f.name

    try:
        result = subprocess.run(
            ['flake8', temp_file],
            capture_output=True,
            text=True,
            timeout=30
        )

        structured_results = parse_flake8_output(result.stdout)

        return {
            **structured_results,
            'raw_output': result.stdout,
            'success': True
        }

    except subprocess.TimeoutExpired:
        return {
            'issues': [],
            'summary': {'total_issues': 0, 'errors': 0, 'warnings': 0, 'info': 0},
            'success': False,
            'error': 'Analysis timed out'
        }
    except Exception as e:
        return {
            'issues': [],
            'summary': {'total_issues': 0, 'errors': 0, 'warnings': 0, 'info': 0},
            'success': False,
            'error': str(e)
        }
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

def parse_bandit_output(bandit_data: dict) -> dict:
    """Parse Bandit JSON output into structured results"""
    security_issues = []

    for issue in bandit_data.get('results', []):
        cwe_id = issue.get('issue_cwe', {}).get('id', 'N/A')
        cwe_str = str(cwe_id) if cwe_id != 'N/A' else 'N/A'

        security_issues.append({
            'line': issue['line_number'],
            'message': issue['issue_text'],
            'code': issue['test_id'],
            'severity': issue['issue_severity'].lower(),
            'confidence': issue['issue_confidence'].lower(),
            'cwe': cwe_str,
            'description': f"{issue['issue_text']} (CWE: {cwe_str})"
        })

    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    for issue in security_issues:
        severity_counts[issue['severity']] += 1

    summary = {
        'total_issues': len(security_issues),
        'high': severity_counts['high'],
        'medium': severity_counts['medium'],
        'low': severity_counts['low']
    }

    return {
        'security_issues': security_issues,
        'summary': summary,
        'success': True
    }

def run_security_analysis(code: str) -> dict:
    """Run Bandit security analysis on the provided code"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_file = f.name

    try:
        result = subprocess.run(
            ['bandit', '-f', 'json', temp_file],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode in [0, 1]:
            try:
                bandit_results = json.loads(result.stdout)
                return parse_bandit_output(bandit_results)
            except json.JSONDecodeError:
                return {
                    'security_issues': [],
                    'summary': {'total_issues': 0, 'high': 0, 'medium': 0, 'low': 0},
                    'success': False,
                    'error': 'Failed to parse Bandit output'
                }
        else:
            return {
                'security_issues': [],
                'summary': {'total_issues': 0, 'high': 0, 'medium': 0, 'low': 0},
                'success': False,
                'error': f'Security scan failed: {result.stderr}'
            }

    except subprocess.TimeoutExpired:
        return {
            'security_issues': [],
            'summary': {'total_issues': 0, 'high': 0, 'medium': 0, 'low': 0},
            'success': False,
            'error': 'Security analysis timed out'
        }
    except Exception as e:
        return {
            'security_issues': [],
            'summary': {'total_issues': 0, 'high': 0, 'medium': 0, 'low': 0},
            'success': False,
            'error': f'Security analysis failed: {str(e)}'
        }
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

def parse_pytest_output(output: str) -> dict:
    """Parse pytest verbose output into structured results"""
    test_cases = []
    lines = output.strip().split('\n')

    total_tests = 0
    passed = 0
    failed = 0

    for line in lines:
        line = line.strip()

        match = re.match(r'(.+?)::(.+?) (PASSED|FAILED|ERROR)', line)
        if match:
            filename, test_name, status = match.groups()
            total_tests += 1

            if status == 'PASSED':
                passed += 1
            else:
                failed += 1

            test_cases.append({
                'test_name': test_name,
                'passed': status == 'PASSED',
                'status': status.lower(),
                'output': line
            })

    return {
        'test_cases': test_cases,
        'summary': {
            'total_tests': total_tests,
            'passed': passed,
            'failed': failed,
            'success': total_tests > 0 and failed == 0
        }
    }

def run_pytest_analysis(code: str, test_code: str = None) -> dict:
    """Run pytest on the provided code and return structured results"""
    print(f"🔍 PYTEST DEBUG: Starting pytest analysis")
    print(f"🔍 PYTEST DEBUG: Code length: {len(code)}, Test code: {'provided' if test_code else 'none'}")

    if not test_code:
        print("🔍 PYTEST DEBUG: No test code provided, returning empty")
        return {
            'test_cases': [],
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'success': True
            },
            'success': True
        }

    # Create temporary directory for both files
    with tempfile.TemporaryDirectory() as temp_dir:
        code_file = os.path.join(temp_dir, "code_under_test.py")
        test_file = os.path.join(temp_dir, "test_code.py")

        # Write both files to the same directory
        with open(code_file, 'w') as f:
            f.write(code)
            print(f"🔍 PYTEST DEBUG: Wrote code to {code_file}")

        with open(test_file, 'w') as f:
            # Add import statement to access the functions from code_under_test
            test_content = "from code_under_test import *\n\n" + test_code
            f.write(test_content)
            print(f"🔍 PYTEST DEBUG: Wrote tests to {test_file}")

        print(f"🔍 PYTEST DEBUG: Created files in temp dir: {temp_dir}")

        try:
            # Run pytest on the test file
            result = subprocess.run(
                ['pytest', test_file, '-v', '--tb=short'],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=temp_dir  # Run in the temp directory
            )

            print(f"🔍 PYTEST DEBUG: Pytest return code: {result.returncode}")
            print(f"🔍 PYTEST DEBUG: Pytest stdout:\n{result.stdout}")
            print(f"🔍 PYTEST DEBUG: Pytest stderr:\n{result.stderr}")

            # Parse pytest output
            test_results = parse_pytest_output(result.stdout)
            print(f"🔍 PYTEST DEBUG: Parsed {len(test_results['test_cases'])} test cases")

            return {
                'test_cases': test_results['test_cases'],
                'summary': test_results['summary'],
                'raw_output': result.stdout,
                'success': True
            }

        except subprocess.TimeoutExpired:
            print("🔍 PYTEST DEBUG: Timeout")
            return {
                'test_cases': [],
                'summary': {'total_tests': 0, 'passed': 0, 'failed': 0, 'success': False},
                'success': False,
                'error': 'Test execution timed out'
            }
        except Exception as e:
            print(f"🔍 PYTEST DEBUG: Exception: {e}")
            return {
                'test_cases': [],
                'summary': {'total_tests': 0, 'passed': 0, 'failed': 0, 'success': False},
                'success': False,
                'error': f'Test execution failed: {str(e)}'
            }

# ===== API ENDPOINTS =====

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_code(submission: CodeSubmission):
    try:
        lint_analysis = run_flake8_analysis(submission.code)
        security_analysis = run_security_analysis(submission.code)
        test_analysis = run_pytest_analysis(submission.code, submission.test_code)

        return AnalysisResult(
            lint_issues=lint_analysis['issues'],
            lint_summary=lint_analysis['summary'],
            security_issues=security_analysis['security_issues'],
            security_summary=security_analysis['summary'],
            test_results=test_analysis['test_cases'],
            test_summary=test_analysis['summary'],
            success=lint_analysis['success'] and security_analysis['success'] and test_analysis['success']
        )

    except Exception as e:
        return AnalysisResult(
            lint_issues=[],
            lint_summary={'total_issues': 0, 'errors': 0, 'warnings': 0, 'info': 0},
            security_issues=[],
            security_summary={'total_issues': 0, 'high': 0, 'medium': 0, 'low': 0},
            test_results=[],
            test_summary={'total_tests': 0, 'passed': 0, 'failed': 0, 'success': False},
            success=False,
            error=str(e)
        )

@app.get("/")
async def root():
    return {"message": "Code Analysis API is running!"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "Code Analysis API"}
#end
