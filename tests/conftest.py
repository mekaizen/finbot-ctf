"""
Global test configuration for FinBot CTF.
"""

import os
import re
import sys

import pytest
from fastapi.testclient import TestClient

from finbot.main import app
from finbot.core.testing.google_sheets_reporter import GoogleSheetsReporter

# Import the plugin
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
pytest_plugins = ['pytest_google_sheets']


# Initialize Google Sheets reporter if credentials are available
SHEETS_REPORTER = None
SPREADSHEET_ID = os.getenv('GOOGLE_SHEETS_ID')
CREDENTIALS_FILE = 'google-credentials.json'

if os.path.exists(CREDENTIALS_FILE) and SPREADSHEET_ID:
    try:
        # Reporter for Isolation Testing Framework TCs worksheet
        SHEETS_REPORTER = GoogleSheetsReporter(CREDENTIALS_FILE, SPREADSHEET_ID)
    except Exception as e:
        print(f"Warning: Could not initialize Google Sheets reporter: {e}")

# Track test results for summary
TEST_RESULTS = {
    'total': 0,
    'passed': 0,
    'failed': 0,
    'total_time': 0.0,
    'tests': []  # List of test details: (iso_code, test_name, result)
}


@pytest.fixture
def client():
    """Test client for the Main FinBot app."""
    with TestClient(app) as test_client:
        yield test_client


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "smoke: Critical functionality tests")
    config.addinivalue_line("markers", "web: Web application tests")


def pytest_collection_modifyitems(config, items):
    """Auto-mark tests based on location."""
    _ = config

    for item in items:
        test_path = str(item.fspath)

        # Mark by directory
        if "/unit/" in test_path or "\\unit\\" in test_path:
            item.add_marker(pytest.mark.unit)
        elif "/integration/" in test_path or "\\integration\\" in test_path:
            item.add_marker(pytest.mark.integration)

        if "/web/" in test_path or "\\web\\" in test_path:
            item.add_marker(pytest.mark.web)


def extract_iso_code(docstring):
    """Extract ISO code from test docstring
    
    Args:
        docstring: Test function docstring
        
    Returns:
        ISO code (e.g., 'ISO-DAT-001') or None
    """
    if not docstring:
        return None
    
    # Match pattern like "ISO-XXX-###"
    match = re.search(r'(ISO-[A-Z]+-\d+)', docstring)
    if match:
        return match.group(1)
    return None


def pytest_runtest_makereport(item, call):
    """Hook to capture test results and update Google Sheets"""
    if call.when == "call":
        # Extract ISO code from docstring
        iso_code = extract_iso_code(item.obj.__doc__ if item.obj else None)
        
        # Determine result
        result = "PASSED" if call.excinfo is None else "FAILED"
        execution_time = call.duration
        test_name = item.name
        
        # Update Isolation Testing Framework TCs worksheet only
        # Skip meta/regression tests (ISO-REG-*) as they're not actual isolation tests
        if SHEETS_REPORTER and iso_code and not iso_code.startswith('ISO-REG-'):
            try:
                notes = str(call.excinfo.value) if call.excinfo else ""
                SHEETS_REPORTER.update_test_result(
                    test_id=iso_code,
                    result=result,
                    notes=notes[:100]  # Limit notes to 100 chars
                )
            except Exception as e:
                print(f"Warning: Could not update Isolation Testing Framework TCs for {iso_code}: {e}")
        
        # Track results for summary
        TEST_RESULTS['total'] += 1
        if result == "PASSED":
            TEST_RESULTS['passed'] += 1
        else:
            TEST_RESULTS['failed'] += 1
        TEST_RESULTS['total_time'] += execution_time
        
        # Track test details
        if iso_code:
            TEST_RESULTS['tests'].append({
                'iso_code': iso_code,
                'test_name': test_name,
                'result': result,
                'duration': execution_time
            })


def pytest_sessionfinish(session, exitstatus):
    """Hook to add summary after all tests run"""
    if SHEETS_REPORTER and TEST_RESULTS['total'] > 0:
        try:
            SHEETS_REPORTER.add_summary(
                total_tests=TEST_RESULTS['total'],
                passed=TEST_RESULTS['passed'],
                failed=TEST_RESULTS['failed'],
                total_time=TEST_RESULTS['total_time'],
                test_details=TEST_RESULTS['tests']
            )
            print(f"\n✓ Test results updated to Google Sheets")
        except Exception as e:
            print(f"Warning: Could not add summary to Google Sheets: {e}")
