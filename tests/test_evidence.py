"""Completeness and integrity of the audit evidence, then the audit results themselves."""

from collections import Counter

import pytest


@pytest.mark.category("Evidence integrity")
@pytest.mark.severity("critical")
def test_every_personal_account_maps_to_the_hr_roster(ev):
    """Every account with an owner matches an employee in the HR roster (completeness)"""
    staff = {p["employee_id"] for p in ev.people}
    assert all(a["employee_id"] in staff for a in ev.accounts if a["employee_id"])


@pytest.mark.category("Evidence integrity")
@pytest.mark.severity("high")
def test_leavers_have_termination_dates(ev):
    """Every terminated employee has a termination date, and active staff have none"""
    for p in ev.people:
        assert bool(p["termination_date"]) is (p["status"] == "Terminated")


@pytest.mark.category("Evidence integrity")
@pytest.mark.severity("high")
def test_change_ids_are_unique(ev):
    """Change tickets have unique ids"""
    assert max(Counter(c["change_id"] for c in ev.changes).values()) == 1


@pytest.mark.category("Evidence integrity")
@pytest.mark.severity("medium")
def test_evidence_is_within_the_audit_period(ev):
    """All changes and ceremonies fall inside 1 Jan - 31 Oct 2026"""
    for c in ev.changes:
        assert "2026-01-01" <= c["deployed_date"] <= "2026-10-31"
    for k in ev.ceremonies:
        assert "2026-01-01" <= k["date"] <= "2026-10-31"


@pytest.mark.category("Audit results")
@pytest.mark.severity("high")
def test_all_planted_exceptions_are_found(results):
    """The audit reports every exception planted in the evidence"""
    found = {r.id: len(r.exceptions) for r in results}
    assert found["AC-01"] == 3 and found["AC-02"] == 2 and found["AC-03"] == 1
    assert found["CM-03"] == 1 and found["CM-04"] == 1 and found["OP-01"] == 1


@pytest.mark.category("Audit results")
@pytest.mark.severity("medium")
def test_every_control_is_mapped_to_frameworks(results):
    """Each control carries a COBIT 2019 objective and an ISO 27001:2022 Annex A reference"""
    for r in results:
        assert r.cobit[:3] in ("DSS", "BAI", "APO", "MEA", "EDM") and r.iso.startswith("A.")
