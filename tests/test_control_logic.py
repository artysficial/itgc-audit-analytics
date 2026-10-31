"""Each control is tested against a tiny hand-built population, so its logic is proven
independently of the audit data (positive and negative cases)."""

import pytest

from audit import controls as c


def evidence(people=(), accounts=(), changes=(), ceremonies=(), systems=None):
    policy = {
        "standard": {"min_length": 12, "max_age_days": 90, "lockout_attempts": 5, "history": 12, "mfa": True},
        "systems": systems or {"X": {"min_length": 12, "max_age_days": 90, "lockout_attempts": 5, "history": 12, "mfa": True}},
        "approved_non_personal": ["svc.ok"],
        "privileged_roles": ["SAP_ALL"],
    }
    return c.Evidence(list(people), list(accounts), list(changes), list(ceremonies), policy)


person = lambda emp, status="Active", term="", title="Buyer": {"employee_id": emp, "name": f"P {emp}", "job_title": title, "status": status, "termination_date": term}
account = lambda user, emp, roles, last="2026-10-30", system="SAP S/4HANA": {"system": system, "user_id": user, "employee_id": emp, "roles": roles, "last_login": last, "status": "Enabled"}
change = lambda cid, **kw: {"change_id": cid, "system": "SAP S/4HANA", "type": "Standard", "developer": "D1", "approver": "A1", "deployer": "O1",
                            "approved_date": "2026-05-01", "deployed_date": "2026-05-03", "tested": "Y", "post_review_date": "", **kw}


@pytest.mark.category("Access controls")
@pytest.mark.severity("critical")
def test_leaver_with_enabled_account_is_an_exception():
    """A terminated employee's enabled account is reported; an active employee's is not"""
    ev = evidence([person("E1", "Terminated", "2026-03-01"), person("E2")], [account("a", "E1", "R"), account("b", "E2", "R")])
    result = c.leavers_removed(ev)
    assert [e["subject"] for e in result.exceptions] == ["P E1 (SAP S/4HANA)"] and result.conclusion == "Ineffective"


@pytest.mark.category("Access controls")
@pytest.mark.severity("critical")
def test_conflicting_roles_are_detected_per_system():
    """Vendor maintenance + payment run is a conflict; the same roles split across users are not"""
    ev = evidence(accounts=[account("one", "E1", "Z_MM_VENDOR_MAINTAIN;Z_FI_PAYMENT_RUN"), account("two", "E2", "Z_MM_VENDOR_MAINTAIN"), account("three", "E3", "Z_FI_PAYMENT_RUN")])
    assert [e["subject"] for e in c.segregation_of_duties(ev).exceptions] == ["one (SAP S/4HANA)"]


@pytest.mark.category("Access controls")
@pytest.mark.severity("critical")
def test_dual_control_conflict_is_critical():
    """Holding both HSM key-custodian roles is a critical SoD conflict"""
    ev = evidence(accounts=[account("k", "E1", "key-custodian-a;key-custodian-b", system="HSM API Console")])
    result = c.segregation_of_duties(ev)
    assert result.risk == "Critical" and result.conclusion == "Ineffective"


@pytest.mark.category("Access controls")
@pytest.mark.severity("high")
def test_unowned_accounts_are_flagged_unless_approved():
    """Accounts without an owner are exceptions, except approved service accounts"""
    ev = evidence(accounts=[account("shared", "", "R"), account("svc.ok", "", "R")])
    assert [e["subject"] for e in c.shared_accounts(ev).exceptions] == ["shared (SAP S/4HANA)"]


@pytest.mark.category("Access controls")
@pytest.mark.severity("medium")
@pytest.mark.parametrize("last_login, dormant", [("2026-08-02", False), ("2026-08-01", True)])
def test_dormancy_threshold_is_ninety_days(last_login, dormant):
    """An account is dormant after more than 90 days without login (boundary checked)"""
    ev = evidence(accounts=[account("u", "E1", "R", last=last_login)])
    assert bool(c.dormant_accounts(ev).exceptions) is dormant


@pytest.mark.category("Access controls")
@pytest.mark.severity("high")
def test_weak_authentication_settings_are_listed():
    """Settings below the standard are each named, and missing MFA raises the risk to high"""
    ev = evidence(systems={"Weak": {"min_length": 8, "max_age_days": 180, "lockout_attempts": 10, "history": 5, "mfa": False}})
    result = c.password_configuration(ev)
    assert result.risk == "High"
    for gap in ("min length", "max age", "lockout", "history", "MFA"):
        assert gap in result.exceptions[0]["detail"]


@pytest.mark.category("Change controls")
@pytest.mark.severity("high")
@pytest.mark.parametrize("approved, deployed, exception", [("2026-05-01", "2026-05-03", False), ("", "2026-05-03", True), ("2026-05-04", "2026-05-03", True)])
def test_change_needs_approval_before_deployment(approved, deployed, exception):
    """Missing or after-the-fact approval is an exception"""
    ev = evidence(changes=[change("C1", approved_date=approved, deployed_date=deployed)])
    assert bool(c.changes_approved(ev).exceptions) is exception


@pytest.mark.category("Change controls")
@pytest.mark.severity("high")
def test_developer_deploying_own_change_is_flagged():
    """A change deployed by its developer breaks segregation"""
    ev = evidence(changes=[change("C1", deployer="D1"), change("C2")])
    assert [e["subject"] for e in c.developer_not_deployer(ev).exceptions] == ["C1"]


@pytest.mark.category("Change controls")
@pytest.mark.severity("medium")
@pytest.mark.parametrize("review, exception", [("2026-05-07", False), ("2026-05-09", True), ("", True)])
def test_emergency_change_review_window(review, exception):
    """Emergency changes need a review within 5 days of deployment"""
    ev = evidence(changes=[change("C1", type="Emergency", post_review_date=review)])
    assert bool(c.emergency_reviewed(ev).exceptions) is exception


@pytest.mark.category("Operations controls")
@pytest.mark.severity("critical")
def test_same_custodian_twice_breaks_dual_control():
    """A key ceremony with the same custodian twice is a critical exception"""
    ev = evidence(ceremonies=[{"ceremony_id": "K1", "date": "2026-02-01", "purpose": "Key rotation", "custodian_1": "E1", "custodian_2": "E1"},
                              {"ceremony_id": "K2", "date": "2026-03-01", "purpose": "Key rotation", "custodian_1": "E1", "custodian_2": "E2"}])
    result = c.dual_control(ev)
    assert [e["subject"] for e in result.exceptions] == ["K1"] and result.risk == "Critical"


@pytest.mark.category("Conclusions")
@pytest.mark.severity("medium")
@pytest.mark.parametrize("exceptions, risk, conclusion", [([], "Low", "Effective"), ([{}], "Medium", "Partially effective"), ([{}], "High", "Ineffective"), ([{}], "Critical", "Ineffective")])
def test_conclusion_follows_risk(exceptions, risk, conclusion):
    """Conclusions: no exceptions = effective; medium = partially effective; high/critical = ineffective"""
    result = c.ControlResult("X", "Access", "n", "o", "c", "i", 10, exceptions, risk)
    assert result.conclusion == conclusion
