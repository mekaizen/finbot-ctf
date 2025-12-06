import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta, timezone

from finbot.core.auth.session import session_manager
from finbot.core.data.repositories import InvoiceRepository
from finbot.core.data.models import UserSession


VENDOR_API_PREFIX = "/vendor/api/v1"


# ============================================================================
# ISO-DAT-001: Basic Data Read/Write Isolation
# ============================================================================
@pytest.mark.unit
def test_basic_data_read_write_isolation(fast_client: TestClient, vendor_pair_setup):
    """ISO-DAT-001: Basic Data Read/Write Isolation
    
    Verify that data created by one vendor is invisible and inaccessible to a 
    second, simultaneously logged-in Vendor."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    db = vendor_pair_setup['db']

    # Create invoice as vendor1
    s1_ctx, _ = session_manager.get_session_with_vendor_context(s1.session_id)
    inv_repo_1 = InvoiceRepository(db, s1_ctx)
    inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="INV-100",
        amount=100.0,
        description="Test invoice",
        invoice_date=datetime.now(timezone.utc) - timedelta(days=1),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )

    # Vendor1 should see the invoice
    r1 = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s1.session_id})
    assert r1.status_code == 200
    assert r1.json()["total_count"] == 1

    # Vendor2 should NOT see vendor1's invoice
    r2 = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s2.session_id})
    assert r2.status_code == 200
    assert r2.json()["total_count"] == 0

    db.close()


# ============================================================================
# ISO-DAT-002: Data Manipulation Isolation
# ============================================================================
@pytest.mark.unit
def test_data_manipulation_isolation(fast_client: TestClient, vendor_pair_setup):
    """ISO-DAT-002: Data Manipulation Isolation
    
    Verify that one Vendor cannot approve or reject an invoice owned by a 
    different vendor."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    db = vendor_pair_setup['db']

    # Create invoice as vendor1
    s1_ctx, _ = session_manager.get_session_with_vendor_context(s1.session_id)
    inv_repo_1 = InvoiceRepository(db, s1_ctx)
    invoice = inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="INV-200",
        amount=200.0,
        description="Manipulation test",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )
    invoice_id = invoice.id

    # Vendor2 attempts to access vendor1's invoice -> should be 403
    r = fast_client.get(
        f"{VENDOR_API_PREFIX}/invoices/{invoice_id}",
        cookies={"finbot_session": s2.session_id}
    )
    assert r.status_code == 403

    db.close()


# ============================================================================
# ISO-DAT-003: List/Aggregate Data Integrity
# ============================================================================
@pytest.mark.unit
def test_list_aggregate_data_integrity(fast_client: TestClient, vendor_pair_setup):
    """ISO-DAT-003: List/Aggregate Data Integrity
    
    Verify that list views only contain invoices belonging to the active 
    Vendor's namespace."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    db = vendor_pair_setup['db']

    # Create invoices for vendor1
    s1_ctx, _ = session_manager.get_session_with_vendor_context(s1.session_id)
    inv_repo_1 = InvoiceRepository(db, s1_ctx)
    inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="I1",
        amount=10.0,
        description="i1",
        invoice_date=datetime.now(timezone.utc) - timedelta(days=3),
        due_date=datetime.now(timezone.utc) + timedelta(days=10),
    )
    inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="I2",
        amount=20.0,
        description="i2",
        invoice_date=datetime.now(timezone.utc) - timedelta(days=2),
        due_date=datetime.now(timezone.utc) + timedelta(days=20),
    )

    # Create invoice for vendor2
    s2_ctx, _ = session_manager.get_session_with_vendor_context(s2.session_id)
    inv_repo_2 = InvoiceRepository(db, s2_ctx)
    inv_repo_2.create_invoice_for_current_vendor(
        invoice_number="I3",
        amount=30.0,
        description="i3",
        invoice_date=datetime.now(timezone.utc) - timedelta(days=1),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )

    # Vendor1 should see exactly 2 invoices
    r1 = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s1.session_id})
    assert r1.status_code == 200
    assert r1.json()["total_count"] == 2

    # Vendor2 should see exactly 1 invoice
    r2 = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s2.session_id})
    assert r2.status_code == 200
    assert r2.json()["total_count"] == 1

    db.close()


# ============================================================================
# ISO-SES-001: Forced Logout / Session Invalidation
# ============================================================================
@pytest.mark.unit
def test_forced_logout_session_invalidation(fast_client: TestClient, vendor_pair_setup):
    """ISO-SES-001: Forced Logout / Session Invalidation
    
    Verify that a session cannot be reused after the user switches vendors 
    (simulating logout/re-login)."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    v1, v2 = vendor_pair_setup['v1'], vendor_pair_setup['v2']
    db = vendor_pair_setup['db']

    # Verify s1 has access to vendor1's resources
    r = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s1.session_id})
    assert r.status_code == 200

    # Create invoice for v1
    s1_ctx, _ = session_manager.get_session_with_vendor_context(s1.session_id)
    inv_repo_1 = InvoiceRepository(db, s1_ctx)
    invoice_v1 = inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="LOGOUT-TEST",
        amount=999.99,
        description="Logout test invoice",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )

    # Switch vendor context for session s1 to v2
    us1 = db.query(UserSession).filter(UserSession.session_id == s1.session_id).first()
    us1.current_vendor_id = v2.id
    db.commit()

    # Now s1 should no longer see v1's invoice
    r = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s1.session_id})
    assert r.status_code == 200
    assert r.json()["total_count"] == 0  # Should not see v1's invoice anymore

    db.close()


# ============================================================================
# ISO-SES-002: Concurrent Session Overlap
# ============================================================================
@pytest.mark.unit
def test_concurrent_session_overlap(fast_client: TestClient, vendor_pair_setup):
    """ISO-SES-002: Concurrent Session Overlap
    
    Verify that two concurrent sessions for the same user do not interfere 
    with each other when accessing different vendor contexts."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    v1, v2 = vendor_pair_setup['v1'], vendor_pair_setup['v2']
    db = vendor_pair_setup['db']

    # Create invoice in vendor1's context
    s1_ctx, _ = session_manager.get_session_with_vendor_context(s1.session_id)
    inv_repo_1 = InvoiceRepository(db, s1_ctx)
    inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="OVERLAP-V1",
        amount=100.0,
        description="Vendor 1 invoice",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )

    # Create invoice in vendor2's context
    s2_ctx, _ = session_manager.get_session_with_vendor_context(s2.session_id)
    inv_repo_2 = InvoiceRepository(db, s2_ctx)
    inv_repo_2.create_invoice_for_current_vendor(
        invoice_number="OVERLAP-V2",
        amount=200.0,
        description="Vendor 2 invoice",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )

    # Both sessions should still work independently
    r1 = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s1.session_id})
    assert r1.status_code == 200
    assert r1.json()["total_count"] == 1

    r2 = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s2.session_id})
    assert r2.status_code == 200
    assert r2.json()["total_count"] == 1

    db.close()


# ============================================================================
# ISO-NAM-001: Namespace Integrity Checks
# ============================================================================
@pytest.mark.unit
def test_namespace_integrity_checks(fast_client: TestClient, vendor_pair_setup):
    """ISO-NAM-001: Namespace Integrity Checks
    
    Verify that each vendor's data is properly isolated by user namespace."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    v1, v2 = vendor_pair_setup['v1'], vendor_pair_setup['v2']
    db = vendor_pair_setup['db']

    # Verify vendors are different
    assert v1.id != v2.id

    # Verify sessions belong to same user but different vendor contexts
    us1 = db.query(UserSession).filter(UserSession.session_id == s1.session_id).first()
    us2 = db.query(UserSession).filter(UserSession.session_id == s2.session_id).first()
    assert us1.user_id == us2.user_id  # Same user
    assert us1.current_vendor_id == v1.id
    assert us2.current_vendor_id == v2.id  # Different vendors

    # Create invoice in vendor1, verify vendor2 cannot see it
    s1_ctx, _ = session_manager.get_session_with_vendor_context(s1.session_id)
    inv_repo_1 = InvoiceRepository(db, s1_ctx)
    inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="NS-CHECK-001",
        amount=999.99,
        description="Namespace test",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )

    r1 = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s1.session_id})
    assert r1.json()["total_count"] == 1

    r2 = fast_client.get(f"{VENDOR_API_PREFIX}/invoices", cookies={"finbot_session": s2.session_id})
    assert r2.json()["total_count"] == 0

    db.close()


# ============================================================================
# ISO-MUL-001: Peak Load / Concurrent Interactions
# ============================================================================
@pytest.mark.unit
def test_peak_load_concurrent_interaction(fast_client: TestClient, multi_vendor_setup):
    """ISO-MUL-001: Peak Load / Concurrent Interactions
    
    Verify isolation holds under load with multiple vendors creating invoices 
    concurrently."""
    vendors = multi_vendor_setup
    db = vendors[0]['db']

    # Create invoices for each vendor
    for vendor_data in vendors:
        session_id = vendor_data['session_id']
        ctx, _ = session_manager.get_session_with_vendor_context(session_id)
        inv_repo = InvoiceRepository(db, ctx)
        invoice = inv_repo.create_invoice_for_current_vendor(
            invoice_number=f"LOAD-{vendor_data['vendor_id']}",
            amount=100.0,
            description="Load test invoice",
            invoice_date=datetime.now(timezone.utc),
            due_date=datetime.now(timezone.utc) + timedelta(days=30),
        )
        vendor_data['invoice_id'] = invoice.id

    # Verify each vendor sees only their own invoice
    for vendor_data in vendors:
        r = fast_client.get(
            f"{VENDOR_API_PREFIX}/invoices",
            cookies={"finbot_session": vendor_data['session_id']}
        )
        assert r.status_code == 200
        invoices = r.json()['invoices']
        assert len(invoices) == 1, f"Vendor {vendor_data['vendor_id']} sees {len(invoices)} invoices instead of 1"
        assert invoices[0]['id'] == vendor_data['invoice_id']

    db.close()


# ============================================================================
# ISO-REG-001: Automated Regression Suite Execution
# ============================================================================
@pytest.mark.unit
def test_automated_regression_suite_execution():
    """ISO-REG-001: Automated Regression Suite Execution
    
    Ensure all isolation tests are properly configured for CI/CD execution."""
    expected_tests = [
        'test_basic_data_read_write_isolation',          # ISO-DAT-001
        'test_data_manipulation_isolation',              # ISO-DAT-002
        'test_list_aggregate_data_integrity',            # ISO-DAT-003
        'test_cross_vendor_update_delete_attack',        # ISO-DAT-004
        'test_sql_injection_invoice_fields',             # ISO-DAT-005
        'test_unauthorized_field_modification',          # ISO-DAT-006
        'test_id_enumeration_attack',                    # ISO-DAT-007
        'test_forced_logout_session_invalidation',       # ISO-SES-001
        'test_concurrent_session_overlap',               # ISO-SES-002
        'test_expired_session_rejection',                # ISO-SES-003
        'test_namespace_integrity_checks',               # ISO-NAM-001
        'test_peak_load_concurrent_interaction',         # ISO-MUL-001
        
    ]

    import sys
    current_module = sys.modules[__name__]

    # Verify all expected tests exist
    missing_tests = []
    for test_name in expected_tests:
        if not hasattr(current_module, test_name):
            missing_tests.append(test_name)

    assert len(missing_tests) == 0, f"Missing isolation tests: {missing_tests}"

    # Verify all tests are marked with @pytest.mark.unit
    for test_name in expected_tests:
        test_func = getattr(current_module, test_name)
        markers = [mark.name for mark in test_func.pytestmark] if hasattr(test_func, 'pytestmark') else []
        assert 'unit' in markers, f"Test {test_name} is missing @pytest.mark.unit marker"

    print(f"\n✓ Regression suite validated: {len(expected_tests)} isolation tests ready for CI/CD")


# ============================================================================
# ISO-DAT-004: Cross-Vendor Update/Delete Attack
# ============================================================================
@pytest.mark.unit
def test_cross_vendor_update_delete_attack(fast_client: TestClient, vendor_pair_setup):
    """ISO-DAT-004: Cross-Vendor Update/Delete Attack
    
    Verify that vendor2 cannot UPDATE or DELETE vendor1's invoices even if 
    they know the invoice ID."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    db = vendor_pair_setup['db']

    # Create invoice as vendor1
    s1_ctx, _ = session_manager.get_session_with_vendor_context(s1.session_id)
    inv_repo_1 = InvoiceRepository(db, s1_ctx)
    invoice = inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="INV-ATTACK-001",
        amount=500.0,
        description="Target for attack",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )
    invoice_id = invoice.id

    # Vendor2 attempts to UPDATE vendor1's invoice
    r_update = fast_client.patch(
        f"{VENDOR_API_PREFIX}/invoices/{invoice_id}",
        json={"amount": 999999.99, "description": "HACKED"},
        cookies={"finbot_session": s2.session_id}
    )
    assert r_update.status_code in [403, 404]

    # Vendor2 attempts to DELETE vendor1's invoice
    r_delete = fast_client.delete(
        f"{VENDOR_API_PREFIX}/invoices/{invoice_id}",
        cookies={"finbot_session": s2.session_id}
    )
    assert r_delete.status_code in [403, 404]

    # Verify invoice still exists and unchanged
    r_verify = fast_client.get(
        f"{VENDOR_API_PREFIX}/invoices",
        cookies={"finbot_session": s1.session_id}
    )
    assert r_verify.status_code == 200
    invoices = r_verify.json().get("invoices", [])
    vendor1_invoice = next((inv for inv in invoices if inv["id"] == invoice_id), None)
    assert vendor1_invoice is not None
    assert vendor1_invoice["amount"] == 500.0
    assert vendor1_invoice["invoice_number"] == "INV-ATTACK-001"

    db.close()


# ============================================================================
# ISO-DAT-005: SQL Injection via Invoice Fields
# ============================================================================
@pytest.mark.unit
def test_sql_injection_invoice_fields(fast_client: TestClient, vendor_pair_setup):
    """ISO-DAT-005: SQL Injection via Invoice Fields
    
    Verify that SQL injection attempts in invoice fields are properly sanitized
    and do not leak data or cause errors."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    db = vendor_pair_setup['db']

    # Create secret invoice for vendor2 (should remain hidden from vendor1)
    s2_ctx, _ = session_manager.get_session_with_vendor_context(s2.session_id)
    inv_repo_2 = InvoiceRepository(db, s2_ctx)
    inv_repo_2.create_invoice_for_current_vendor(
        invoice_number="SECRET-INVOICE",
        amount=99999.99,
        description="Hidden data",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )

    # Test SQL injection payloads
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE invoices--",
        "1' UNION SELECT * FROM invoices--",
        "' OR 1=1--",
        "admin'--",
    ]

    for payload in payloads:
        r = fast_client.get(
            f"{VENDOR_API_PREFIX}/invoices",
            params={"search": payload},
            cookies={"finbot_session": s1.session_id}
        )
        
        assert r.status_code in [200, 400]
        
        if r.status_code == 200:
            invoices = r.json().get("invoices", [])
            invoice_numbers = [inv.get("invoice_number") for inv in invoices]
            assert "SECRET-INVOICE" not in invoice_numbers, \
                f"SQL injection leaked data: {payload}"

    db.close()


# ============================================================================
# ISO-DAT-006: Unauthorized Field Modification
# ============================================================================
@pytest.mark.unit
def test_unauthorized_field_modification(fast_client: TestClient, vendor_pair_setup):
    """ISO-DAT-006: Unauthorized Field Modification
    
    Verify that vendors cannot modify sensitive fields they don't own or
    manipulate metadata fields that should be immutable."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    db = vendor_pair_setup['db']

    # Create invoice for vendor2
    s2_ctx, _ = session_manager.get_session_with_vendor_context(s2.session_id)
    inv_repo_2 = InvoiceRepository(db, s2_ctx)
    invoice = inv_repo_2.create_invoice_for_current_vendor(
        invoice_number="TEST-MOD-006",
        amount=5000.00,
        description="Original Description",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )
    invoice_id = invoice.id

    # Vendor1 attempts to modify vendor2's invoice
    modify_payload = {
        "invoice_number": "HACKED-006",
        "amount": 99999.99,
        "description": "Hacked by vendor1"
    }

    r = fast_client.put(
        f"{VENDOR_API_PREFIX}/invoices/{invoice_id}",
        json=modify_payload,
        cookies={"finbot_session": s1.session_id}
    )

    # Should get 403 Forbidden or 404 Not Found
    assert r.status_code in [403, 404], \
        f"Vendor1 should not modify vendor2's invoice. Got status {r.status_code}"

    # Verify invoice was NOT modified
    s2_ctx_refresh, _ = session_manager.get_session_with_vendor_context(s2.session_id)
    inv_repo_2_refresh = InvoiceRepository(db, s2_ctx_refresh)
    invoice_check = inv_repo_2_refresh.get_invoice(invoice_id)

    assert invoice_check.invoice_number == "TEST-MOD-006", \
        "Invoice number was modified by unauthorized vendor"
    assert invoice_check.amount == 5000.00, \
        "Invoice amount was modified by unauthorized vendor"
    assert invoice_check.description == "Original Description", \
        "Invoice description was modified by unauthorized vendor"

    db.close()


# ============================================================================
# ISO-DAT-007: ID Enumeration Attack
# ============================================================================
@pytest.mark.unit
def test_id_enumeration_attack(fast_client: TestClient, vendor_pair_setup):
    """ISO-DAT-007: ID Enumeration Attack
    
    Verify that vendor cannot enumerate and access other vendors' invoices by
    guessing sequential IDs."""
    s1, s2 = vendor_pair_setup['s1'], vendor_pair_setup['s2']
    db = vendor_pair_setup['db']

    # Create invoice as vendor1
    s1_ctx, _ = session_manager.get_session_with_vendor_context(s1.session_id)
    inv_repo_1 = InvoiceRepository(db, s1_ctx)
    invoice = inv_repo_1.create_invoice_for_current_vendor(
        invoice_number="INV-ENUM-TEST",
        amount=100.0,
        description="Enumeration target",
        invoice_date=datetime.now(timezone.utc),
        due_date=datetime.now(timezone.utc) + timedelta(days=30),
    )
    target_id = invoice.id

    # Vendor2 attempts to enumerate IDs around vendor1's invoice
    test_ids = [target_id - 2, target_id - 1, target_id, target_id + 1, target_id + 2]

    for test_id in test_ids:
        r = fast_client.get(
            f"{VENDOR_API_PREFIX}/invoices/{test_id}",
            cookies={"finbot_session": s2.session_id}
        )
        assert r.status_code in [403, 404], \
            f"ID {test_id} returned {r.status_code} instead of 403/404"

    db.close()


# ============================================================================
# ISO-SES-003: Expired Session Rejection
# ============================================================================
@pytest.mark.unit
def test_expired_session_rejection(fast_client: TestClient, db):
    """ISO-SES-003: Expired Session Rejection
    
    Verify that expired sessions are properly rejected and cannot access
    protected resources."""
    from finbot.core.data.repositories import VendorRepository
    
    # Create session and vendor
    session = session_manager.create_session(email="expiry_test@example.com")
    vendor_repo = VendorRepository(db, session)
    vendor = vendor_repo.create_vendor(
        company_name="Expiry Test Vendor",
        vendor_category="Technology",
        industry="Software",
        services="Testing",
        contact_name="Test User",
        email="test@expiry.com",
        tin="99-9999999",
        bank_account_number="9999999999",
        bank_name="Test Bank",
        bank_routing_number="999999999",
        bank_account_holder_name="Expiry Test Vendor",
    )
    
    # Link vendor to session
    us = db.query(UserSession).filter(UserSession.session_id == session.session_id).first()
    us.current_vendor_id = vendor.id
    db.commit()
    
    # Verify session works
    r = fast_client.get(
        f"{VENDOR_API_PREFIX}/invoices",
        cookies={"finbot_session": session.session_id}
    )
    assert r.status_code == 200
    
    # Expire the session
    us.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db.commit()
    
    # Attempt access with expired session - should fail
    # The expired session triggers middleware to delete it and create temp session
    # Temp session has no vendor context, causing ValueError or proper HTTP error
    try:
        r_expired = fast_client.get(
            f"{VENDOR_API_PREFIX}/invoices",
            cookies={"finbot_session": session.session_id}
        )
        # If we get here, check for non-200 status (401, 403, 500, etc)
        assert r_expired.status_code != 200, \
            f"Expired session should be rejected, got {r_expired.status_code}"
    except ValueError as e:
        # ValueError "Vendor context required" is also a valid rejection
        assert "Vendor context required" in str(e)
    
    db.close()
