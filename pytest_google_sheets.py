"""
Pytest Plugin for Google Sheets Test Result Reporting

This plugin automatically reports test results to Google Sheets.
Results are written to a specified worksheet with formatting.

Installation:
    pip install gspread google-auth

Configuration:
    Set the following environment variables:
    - GOOGLE_SHEETS_ID: Your Google Sheets spreadsheet ID
    - GOOGLE_CREDENTIALS_FILE: Path to service account credentials (default: google-credentials.json)

Usage:
    pytest --google-sheets
    pytest --google-sheets --sheets-worksheet="My Tests"
"""

import os
import re
from datetime import datetime
from typing import Optional

import pytest
import gspread
from google.oauth2.service_account import Credentials


class GoogleSheetsReporter:
    """Reports test automation results to Google Sheets"""

    def __init__(self, credentials_file: str, spreadsheet_id: str, worksheet_name: str = 'Isolation Testing Framework TCs'):
        """Initialize Google Sheets reporter
        
        Args:
            credentials_file: Path to google-credentials.json
            spreadsheet_id: Your Google Sheet ID from the URL
            worksheet_name: Name of the tab to store results
        """
        scope = ['https://www.googleapis.com/auth/spreadsheets',
                 'https://www.googleapis.com/auth/drive']
        creds = Credentials.from_service_account_file(credentials_file, scopes=scope)
        self.client = gspread.authorize(creds)
        self.sheet = self.client.open_by_key(spreadsheet_id)
        try:
            self.worksheet = self.sheet.worksheet(worksheet_name)
        except gspread.exceptions.WorksheetNotFound:
            self.worksheet = self.sheet.add_worksheet(title=worksheet_name, rows=1000, cols=26)
        
        # Determine worksheet type
        self.worksheet_name = worksheet_name
        self.is_isolation_framework = 'Isolation Testing Framework' in worksheet_name

    def update_test_result(self, test_id: str, result: str, notes: str = ""):
        """Update automation result in Google Sheet
        
        Args:
            test_id: ISO code of the test case (e.g., 'ISO-DAT-001')
            result: e.g., "PASS" or "FAIL"
            notes: Optional notes or error messages
        """
        all_values = self.worksheet.get_all_values()
        if not all_values:
            return
        
        headers = all_values[0]
        
        # Determine test_id column based on worksheet type
        if self.is_isolation_framework:
            test_id_col = 0  # Isolation Testing Framework TCs: US ID is in column 0
        else:
            test_id_col = 1  # RTM: US ID is in column 1
        
        # Find automation columns - order: automation_status, automation_notes, last_run
        status_col = -1
        notes_col = -1
        last_run_col = -1
        
        for i, header in enumerate(headers):
            if 'automation_status' in header.lower():
                status_col = i + 1
            elif 'automation_notes' in header.lower():
                notes_col = i + 1
            elif 'last_run' in header.lower():
                last_run_col = i + 1
        
        # Create columns if they don't exist (in correct order)
        if status_col == -1:
            status_col = len(headers) + 1
            self.worksheet.update_cell(1, status_col, 'automation_status')
            headers.append('automation_status')
        
        if notes_col == -1:
            notes_col = len(headers) + 1
            self.worksheet.update_cell(1, notes_col, 'automation_notes')
            headers.append('automation_notes')
        
        if last_run_col == -1:
            last_run_col = len(headers) + 1
            self.worksheet.update_cell(1, last_run_col, 'last_run')
            headers.append('last_run')
        
        # Find the row with matching test_id
        row_num = None
        for idx, row in enumerate(all_values[1:], start=2):
            if row and len(row) > test_id_col and row[test_id_col] == test_id:
                row_num = idx
                break
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if row_num:
            self.worksheet.update_cell(row_num, status_col, result)
            if notes:
                self.worksheet.update_cell(row_num, notes_col, notes)
            self.worksheet.update_cell(row_num, last_run_col, timestamp)
    
    def add_summary(self, total_tests: int, passed: int, failed: int, total_time: float, test_details: list = None, worksheet_stats: dict = None, max_history_rows: int = 100):
        """Add summary row to Summary sheet with test names and worksheet breakdown
        
        Args:
            max_history_rows: Maximum number of summary rows to keep (default: 100, keeps ~3 months of daily testing)
        """
        try:
            summary_sheet = self.sheet.worksheet('Summary')
        except gspread.exceptions.WorksheetNotFound:
            summary_sheet = self.sheet.add_worksheet(title='Summary', rows=1000, cols=26)
            summary_sheet.append_row(['timestamp', 'total_tests', 'passed', 'failed', 'pass_rate', 'total_time', 'test_categories', 'test_list'])
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        pass_rate = f"{(passed/total_tests*100):.1f}%" if total_tests > 0 else "N/A"
        
        # Build worksheet breakdown - only include worksheets with tests executed
        worksheet_breakdown = ""
        if worksheet_stats:
            breakdown_list = []
            for ws_name, stats in worksheet_stats.items():
                ws_total = stats.get('total', 0)
                if ws_total > 0:  # Only include worksheets that had tests executed
                    ws_passed = stats.get('passed', 0)
                    ws_failed = stats.get('failed', 0)
                    ws_rate = f"{(ws_passed/ws_total*100):.1f}%"
                    breakdown_list.append(f"{ws_name}: {ws_passed}/{ws_total} ({ws_rate})")
            worksheet_breakdown = "\n".join(breakdown_list)
        
        # Build test details
        test_names_str = ""
        if test_details:
            test_list = []
            for test in test_details:
                iso = test.get('iso_code', '')
                name = test.get('test_name', '')
                result = test.get('result', '')
                duration = test.get('duration', 0)
                worksheets = test.get('worksheets', [])
                ws_count = len(worksheets)
                test_list.append(f"{iso}: {name} ({result}, {duration:.2f}s) - {ws_count} worksheet(s)")
            test_names_str = "\n".join(test_list)
        
        # Insert row at position 2 (right after header) to keep latest on top
        new_row = [
            timestamp, total_tests, passed, failed, pass_rate, round(total_time, 2), worksheet_breakdown, test_names_str
        ]
        summary_sheet.insert_row(new_row, index=2)
        
        # Keep history clean - maintain rolling window of last N runs
        try:
            all_rows = summary_sheet.get_all_values()
            total_rows = len(all_rows)
            
            # If we exceed the limit, delete oldest rows (from bottom)
            if total_rows > max_history_rows + 1:  # +1 for header row
                rows_to_delete = total_rows - (max_history_rows + 1)
                # Delete from the bottom (oldest entries)
                for _ in range(rows_to_delete):
                    summary_sheet.delete_rows(total_rows)
                    total_rows -= 1
        except Exception as e:
            # Don't fail the test run if cleanup fails
            pass
        



def extract_iso_code(docstring: Optional[str]) -> Optional[str]:
    """Extract ISO code from test docstring"""
    if not docstring:
        return None
    match = re.search(r'(ISO-[A-Z]+-\d+)', docstring)
    return match.group(1) if match else None


def detect_test_category(item) -> str:
    """Detect which worksheet category a test belongs to based on its file path or markers
    
    Args:
        item: pytest test item
        
    Returns:
        Worksheet name that this test belongs to
    """
    # Get the file path
    fspath = str(item.fspath) if hasattr(item, 'fspath') else str(item.path)
    
    # Map file paths to worksheet names
    if 'vendor_isolation' in fspath or 'test_vendor_isolation' in fspath:
        return 'Isolation Testing Framework TCs'
    elif 'security' in fspath or 'penetration' in fspath:
        return 'Security Penetration Testing'
    elif 'ctf' in fspath or 'challenge' in fspath:
        return 'CTF Challenge Validation'
    elif 'performance' in fspath:
        return 'Performance Testing'
    elif 'browser' in fspath or 'cross_browser' in fspath:
        return 'Cross_Browser'
    elif 'e2e' in fspath or 'end_to_end' in fspath or 'integration' in fspath:
        return 'End-To-End'
    
    # Default to Isolation Testing Framework if no match
    return 'Isolation Testing Framework TCs'


class GoogleSheetsPlugin:
    """Pytest plugin for Google Sheets reporting"""
    
    # Default worksheets to report to
    DEFAULT_WORKSHEETS = [
        'Isolation Testing Framework TCs',
        'Security Penetration Testing',
        'CTF Challenge Validation',
        'Performance Testing',
        'Cross_Browser',
        'End-To-End'
    ]
    
    def __init__(self, config):
        self.config = config
        self.reporters = []  # List of reporters for multiple worksheets
        self.test_results = {
            'total': 0,
            'passed': 0,
            'failed': 0,
            'total_time': 0.0,
            'tests': [],
            'by_worksheet': {}  # Track results per worksheet
        }
        
        # Initialize reporters if enabled
        if config.getoption("--google-sheets"):
            spreadsheet_id = os.getenv('GOOGLE_SHEETS_ID')
            credentials_file = os.getenv('GOOGLE_CREDENTIALS_FILE', 'google-credentials.json')
            worksheet_names = config.getoption("--sheets-worksheet")
            
            if os.path.exists(credentials_file) and spreadsheet_id:
                # Use custom worksheets or default ones
                if worksheet_names == 'all':
                    worksheets = self.DEFAULT_WORKSHEETS
                else:
                    worksheets = [w.strip() for w in worksheet_names.split(',')]
                
                # Initialize reporter for each worksheet
                for worksheet_name in worksheets:
                    try:
                        reporter = GoogleSheetsReporter(credentials_file, spreadsheet_id, worksheet_name)
                        self.reporters.append(reporter)
                        self.test_results['by_worksheet'][worksheet_name] = {
                            'total': 0, 'passed': 0, 'failed': 0
                        }
                        print(f"✓ Initialized Google Sheets reporter for '{worksheet_name}'")
                    except Exception as e:
                        print(f"Warning: Could not initialize reporter for '{worksheet_name}': {e}")

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        """Capture test results and update Google Sheets"""
        outcome = yield
        report = outcome.get_result()
        
        if report.when == "call" and self.reporters:
            iso_code = extract_iso_code(item.obj.__doc__ if item.obj else None)
            
            if iso_code:
                result = "PASS" if report.outcome == "passed" else "FAIL"
                execution_time = report.duration
                test_name = item.name
                notes = str(report.longrepr) if report.outcome == "failed" else ""
                
                # Detect which worksheet this test belongs to
                target_worksheet = detect_test_category(item)
                
                # Update only the matching worksheet
                updated_worksheets = []
                for reporter in self.reporters:
                    if reporter.worksheet_name == target_worksheet:
                        try:
                            reporter.update_test_result(
                                test_id=iso_code,
                                result=result,
                                notes=notes[:100]
                            )
                            updated_worksheets.append(reporter.worksheet_name)
                            
                            # Track per worksheet
                            ws_name = reporter.worksheet_name
                            self.test_results['by_worksheet'][ws_name]['total'] += 1
                            if result == "PASS":
                                self.test_results['by_worksheet'][ws_name]['passed'] += 1
                            else:
                                self.test_results['by_worksheet'][ws_name]['failed'] += 1
                        except Exception as e:
                            print(f"Warning: Could not update {reporter.worksheet_name} for {iso_code}: {e}")
                        break  # Only update one worksheet per test
                
                # Track for overall summary (count once, not per worksheet)
                if not hasattr(self, '_tracked_tests'):
                    self._tracked_tests = set()
                
                if iso_code not in self._tracked_tests:
                    self._tracked_tests.add(iso_code)
                    self.test_results['total'] += 1
                    if result == "PASS":
                        self.test_results['passed'] += 1
                    else:
                        self.test_results['failed'] += 1
                    self.test_results['total_time'] += execution_time
                    self.test_results['tests'].append({
                        'iso_code': iso_code,
                        'test_name': test_name,
                        'result': result,
                        'duration': execution_time,
                        'worksheets': updated_worksheets
                    })

    def pytest_sessionfinish(self, session, exitstatus):
        """Add summary after all tests run"""
        if self.reporters and self.test_results['total'] > 0:
            # Add summary to the first reporter only (to avoid duplicate summaries)
            try:
                self.reporters[0].add_summary(
                    total_tests=self.test_results['total'],
                    passed=self.test_results['passed'],
                    failed=self.test_results['failed'],
                    total_time=self.test_results['total_time'],
                    test_details=self.test_results['tests'],
                    worksheet_stats=self.test_results['by_worksheet']
                )
                
                # Print summary to console
                print(f"\n{'='*80}")
                print(f"Google Sheets Test Results Summary")
                print(f"{'='*80}")
                print(f"Overall: {self.test_results['passed']}/{self.test_results['total']} passed ({(self.test_results['passed']/self.test_results['total']*100):.1f}%)")
                print(f"\nWorksheet Breakdown:")
                
                # Only show worksheets that had tests executed
                updated_count = 0
                for ws_name, stats in self.test_results['by_worksheet'].items():
                    ws_total = stats['total']
                    if ws_total > 0:
                        ws_passed = stats['passed']
                        ws_rate = f"{(ws_passed/ws_total*100):.1f}%"
                        print(f"  ✓ {ws_name}: {ws_passed}/{ws_total} ({ws_rate})")
                        updated_count += 1
                
                print(f"{'='*80}")
                print(f"✓ Results saved to {updated_count} worksheet(s) + Summary")
            except Exception as e:
                print(f"Warning: Could not add summary to Google Sheets: {e}")


def pytest_addoption(parser):
    """Add command-line options for the plugin"""
    group = parser.getgroup('google-sheets', 'Google Sheets test reporting')
    group.addoption(
        '--google-sheets',
        action='store_true',
        default=False,
        help='Enable Google Sheets test result reporting'
    )
    group.addoption(
        '--sheets-worksheet',
        action='store',
        default='all',
        help='Comma-separated worksheet names or "all" for all default worksheets (default: all)'
    )


def pytest_configure(config):
    """Register the plugin"""
    if config.getoption("--google-sheets"):
        plugin = GoogleSheetsPlugin(config)
        config.pluginmanager.register(plugin, 'google_sheets_reporter')
