"""Google Sheets Reporter for Test Automation Results"""

import gspread
from google.oauth2.service_account import Credentials
from datetime import datetime
from gspread.utils import a1_range_to_grid_range


class GoogleSheetsReporter:
    """Reports test automation results to Google Sheets"""

    def __init__(self, credentials_file: str, spreadsheet_id: str, worksheet_name: str = 'Isolation Testing Framework TCs'):
        """Initialize Google Sheets reporter
        
        Args:
            credentials_file: Path to google-credentials.json
            spreadsheet_id: Your Google Sheet ID from the URL
            worksheet_name: Name of the tab to store results (default: 'Isolation Testing Framework TCs')
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
        
        # Determine worksheet type to know column layout
        self.worksheet_name = worksheet_name
        self.is_isolation_framework = 'Isolation Testing Framework' in worksheet_name
    
    def update_test_result(self, test_id: str, result: str, notes: str = ""):
        """Update automation result in Google Sheet
        
        Args:
            test_id: ISO code of the test case (e.g., 'ISO-DAT-001')
            result: e.g., "PASS" or "FAIL"
            notes: Optional notes or error messages
        """
        # Get all rows and headers
        all_values = self.worksheet.get_all_values()
        if not all_values:
            return
        
        headers = all_values[0]
        
        # Determine test_id column based on worksheet type
        if self.is_isolation_framework:
            # Isolation Testing Framework TCs: US ID is in column 0
            test_id_col = 0
        else:
            # RTM: US ID is in column 1
            test_id_col = 1
        
        # Find automation_status column - use lowercase version if it exists
        status_col = -1
        if 'automation_status' in headers:
            status_col = headers.index('automation_status') + 1
        elif 'Automation_status' in headers:
            status_col = headers.index('Automation_status') + 1
        else:
            status_col = len(headers) + 1
            self.worksheet.update_cell(1, status_col, 'automation_status')
        
        # Find automation_notes column
        notes_col = -1
        if 'automation_notes' in headers:
            notes_col = headers.index('automation_notes') + 1
        elif 'Automation_notes' in headers:
            notes_col = headers.index('Automation_notes') + 1
        else:
            notes_col = len(headers) + 1
            self.worksheet.update_cell(1, notes_col, 'automation_notes')
        
        # Find last_run column
        last_run_col = -1
        if 'last_run' in headers:
            last_run_col = headers.index('last_run') + 1
        else:
            last_run_col = len(headers) + 1
            self.worksheet.update_cell(1, last_run_col, 'last_run')
        
        # Find the row with the matching test_id
        row_num = None
        for idx, row in enumerate(all_values[1:], start=2):  # Skip header row
            # Check if row is not empty and has enough columns
            if not row or len(row) <= test_id_col:
                continue
            # Check if this cell matches the test_id exactly
            cell_value = row[test_id_col].strip() if row[test_id_col] else ""
            
            # Skip title/header rows (US ID, Test Name, etc.)
            if cell_value in ['US ID', 'Test Name', 'Test ID', 'ID', '']:
                continue
                
            if cell_value == test_id:
                # Additional check: ensure this is a data row, not a title row
                # A data row should have at least one more non-empty cell besides the test_id
                has_data = any(
                    row[i].strip() if i < len(row) and row[i] else "" 
                    for i in range(len(row)) if i != test_id_col
                )
                if has_data:
                    row_num = idx
                    break
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if row_num:
            # Update existing row with formatted result
            self.worksheet.update_cell(row_num, status_col, result)
            # Apply center alignment to the status cell
            cell_range = f'{chr(64 + status_col)}{row_num}'
            self.worksheet.format(cell_range, {'horizontalAlignment': 'CENTER'})
            
            if notes:
                self.worksheet.update_cell(row_num, notes_col, notes)
            self.worksheet.update_cell(row_num, last_run_col, timestamp)
    
    def add_summary(self, total_tests: int, passed: int, failed: int, total_time: float, test_details: list = None):
        """Add summary row to Summary sheet with test categories and names
        
        Args:
            total_tests: Total number of tests run
            passed: Number of passed tests
            failed: Number of failed tests
            total_time: Total execution time in seconds
            test_details: List of dicts with test details (iso_code, test_name, result, duration)
        """
        try:
            summary_sheet = self.sheet.worksheet('Summary')
        except gspread.exceptions.WorksheetNotFound:
            summary_sheet = self.sheet.add_worksheet(title='Summary', rows=1000, cols=26)
        
        # Ensure header row exists
        all_values = summary_sheet.get_all_values()
        expected_headers = ['timestamp', 'total_tests', 'passed', 'failed', 'pass_rate', 'total_time', 'test_categories', 'test_names', 'results']
        if not all_values or all_values[0] != expected_headers:
            # Insert or update header row
            summary_sheet.update(range_name='A1:I1', values=[expected_headers])
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        pass_rate = f"{(passed/total_tests*100):.1f}%" if total_tests > 0 else "N/A"
        
        # Map ISO code prefixes to test categories
        iso_category_map = {
            'ISO-DAT': 'Isolation Testing Framework - Data',
            'ISO-SES': 'Isolation Testing Framework - Session',
            'ISO-NAM': 'Isolation Testing Framework - Namespace',
            'ISO-MUL': 'Isolation Testing Framework - Multi-Vendor',
            'ISO-REG': 'Regression Testing',
        }
        
        # Separate test categories, names, and results
        test_categories_str = ""
        test_names_str = ""
        results_str = ""
        
        if test_details:
            categories = []
            names = []
            results = []
            for test in test_details:
                iso = test.get('iso_code', '')
                name = test.get('test_name', '')
                result = test.get('result', '')
                duration = test.get('duration', 0)
                
                # Extract category from iso_code (e.g., "ISO-DAT" from "ISO-DAT-001")
                iso_prefix = '-'.join(iso.split('-')[:-1]) if iso else ''
                category = iso_category_map.get(iso_prefix, 'Unknown')
                
                categories.append(category)
                names.append(f"{iso}: {name} ({duration:.2f}s)")
                results.append(result)
            
            test_categories_str = "\n".join(categories)
            test_names_str = "\n".join(names)
            results_str = "\n".join(results)
        
        # Insert new row at position 2 (right after header) to put latest execution on top
        summary_sheet.insert_row([
            timestamp, total_tests, passed, failed, pass_rate, round(total_time, 2), 
            test_categories_str, test_names_str, results_str
        ], index=2)
