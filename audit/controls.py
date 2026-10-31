"""IT general controls (ITGC) tested over the full population, not a sample.

Each control returns its population, the exceptions found and a conclusion, mapped to
COBIT 2019 and ISO/IEC 27001:2022 Annex A.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"
PERIOD_END = date(2026, 10, 31)
DORMANT_DAYS = 90
EMERGENCY_REVIEW_DAYS = 5

# role pairs that one person must not hold together (system, role A, role B, risk, why)
SOD_RULES = [
    ("SAP S/4HANA", "Z_MM_VENDOR_MAINTAIN", "Z_FI_PAYMENT_RUN", "High", "could create a fictitious vendor and pay it"),
    ("SAP S/4HANA", "Z_MM_PO_CREATE", "Z_MM_PO_RELEASE", "High", "could raise and approve own purchase orders"),
    ("SAP S/4HANA", "Z_AP_INVOICE_ENTRY", "Z_FI_PAYMENT_RUN", "High", "could enter and pay own invoices"),
    ("SAP S/4HANA", "Z_DEV_ABAP", "SAP_ALL", "High", "developer with unrestricted production access"),
    ("HSM API Console", "key-custodian-a", "key-custodian-b", "Critical", "one person holds both key components (breaks dual control)"),
]


@dataclass
class Evidence:
    people: list[dict]
    accounts: list[dict]
    changes: list[dict]
    ceremonies: list[dict]
    policy: dict

    @classmethod
    def load(cls, data_dir: Path = DATA) -> "Evidence":
        read = lambda n: list(csv.DictReader(open(data_dir / f"{n}.csv", encoding="utf-8")))
        return cls(read("hr_roster"), read("accounts"), read("changes"), read("key_ceremonies"), json.loads((data_dir / "policy.json").read_text(encoding="utf-8")))


@dataclass
class ControlResult:
    id: str
    domain: str
    name: str
    objective: str
    cobit: str
    iso: str
    population: int
    exceptions: list[dict] = field(default_factory=list)
    risk: str = "Medium"
    recommendation: str = ""

    @property
    def conclusion(self) -> str:
        # the conclusion follows the risk of what was found, not just the count
        if not self.exceptions:
            return "Effective"
        return "Ineffective" if self.risk in ("High", "Critical") else "Partially effective"


def roles(account: dict) -> set[str]:
    return set(account["roles"].split(";")) if account["roles"] else set()


def leavers_removed(ev: Evidence) -> ControlResult:
    leavers = {p["employee_id"]: p for p in ev.people if p["status"] == "Terminated"}
    exceptions = []
    for a in ev.accounts:
        person = leavers.get(a["employee_id"])
        if person and a["status"] == "Enabled":
            used_after = date.fromisoformat(a["last_login"]) > date.fromisoformat(person["termination_date"])
            exceptions.append({"subject": f"{person['name']} ({a['system']})", "detail": f"left {person['termination_date']}, account enabled" + (f", used {a['last_login']}" if used_after else "")})
    return ControlResult("AC-01", "Access", "Leavers are removed promptly", "Accounts of terminated staff are disabled by their last day",
                         "DSS05.04", "A.5.18", len(leavers), exceptions, "High" if exceptions else "Low",
                         "Automate HR-to-IAM deprovisioning; disable on termination date and alert when it fails")


def segregation_of_duties(ev: Evidence) -> ControlResult:
    exceptions = []
    for a in ev.accounts:
        held = roles(a)
        for system, first, second, risk, why in SOD_RULES:
            if a["system"] == system and {first, second} <= held:
                exceptions.append({"subject": f"{a['user_id']} ({system})", "detail": f"{first} + {second}: {why}", "risk": risk})
    worst = "Critical" if any(e["risk"] == "Critical" for e in exceptions) else ("High" if exceptions else "Low")
    return ControlResult("AC-02", "Access", "Segregation of duties", "No user holds conflicting roles",
                         "DSS06.03", "A.5.3", len(ev.accounts), exceptions, worst,
                         "Remove conflicting roles; add SoD rules to role design and to quarterly access reviews")


def shared_accounts(ev: Evidence) -> ControlResult:
    approved = set(ev.policy["approved_non_personal"])
    exceptions = [{"subject": f"{a['user_id']} ({a['system']})", "detail": f"no owner, roles {a['roles']}"}
                  for a in ev.accounts if not a["employee_id"] and a["user_id"] not in approved]
    return ControlResult("AC-03", "Access", "No shared or unowned accounts", "Every interactive account belongs to one named person",
                         "DSS05.04", "A.5.16", len(ev.accounts), exceptions, "High" if exceptions else "Low",
                         "Disable the shared account; use named accounts with privileged access management for support")


def dormant_accounts(ev: Evidence) -> ControlResult:
    exceptions = [{"subject": f"{a['user_id']} ({a['system']})", "detail": f"last login {a['last_login']} ({(PERIOD_END - date.fromisoformat(a['last_login'])).days} days)"}
                  for a in ev.accounts if a["status"] == "Enabled" and (PERIOD_END - date.fromisoformat(a["last_login"])).days > DORMANT_DAYS]
    return ControlResult("AC-04", "Access", f"Dormant accounts disabled after {DORMANT_DAYS} days", "Unused access is removed",
                         "DSS05.04", "A.5.18", len(ev.accounts), exceptions, "Medium" if exceptions else "Low",
                         "Disable accounts unused for 90 days automatically; re-enable through a request")


def password_configuration(ev: Evidence) -> ControlResult:
    standard, exceptions = ev.policy["standard"], []
    for system, cfg in ev.policy["systems"].items():
        gaps = []
        if cfg["min_length"] < standard["min_length"]:
            gaps.append(f"min length {cfg['min_length']} < {standard['min_length']}")
        if cfg["max_age_days"] > standard["max_age_days"]:
            gaps.append(f"max age {cfg['max_age_days']} > {standard['max_age_days']} days")
        if cfg["lockout_attempts"] > standard["lockout_attempts"]:
            gaps.append(f"lockout after {cfg['lockout_attempts']} > {standard['lockout_attempts']} attempts")
        if cfg["history"] < standard["history"]:
            gaps.append(f"history {cfg['history']} < {standard['history']}")
        if standard["mfa"] and not cfg["mfa"]:
            gaps.append("MFA not enforced")
        if gaps:
            exceptions.append({"subject": system, "detail": "; ".join(gaps)})
    return ControlResult("AC-05", "Access", "Authentication settings meet the standard", "Password, lockout and MFA settings match the bank standard",
                         "DSS05.04", "A.5.17, A.8.5", len(ev.policy["systems"]), exceptions, "High" if any("MFA" in e["detail"] for e in exceptions) else "Medium",
                         "Enforce MFA for SAP GUI/Fiori; align HSM console lockout and password age with the standard")


def changes_approved(ev: Evidence) -> ControlResult:
    exceptions = [{"subject": c["change_id"], "detail": f"{c['system']} change deployed {c['deployed_date']} without recorded approval"}
                  for c in ev.changes if c["type"] == "Standard" and (not c["approved_date"] or c["approved_date"] > c["deployed_date"])]
    return ControlResult("CM-01", "Change", "Changes are approved before deployment", "Production changes have documented prior approval",
                         "BAI06.01", "A.8.32", len(ev.changes), exceptions, "High" if exceptions else "Low",
                         "Block deployment pipelines until the change ticket is approved")


def developer_not_deployer(ev: Evidence) -> ControlResult:
    exceptions = [{"subject": c["change_id"], "detail": f"{c['developer']} developed and deployed it ({c['system']})"} for c in ev.changes if c["developer"] == c["deployer"]]
    return ControlResult("CM-02", "Change", "Developers do not deploy their own changes", "Segregation between development and production",
                         "BAI06.01", "A.8.31, A.5.3", len(ev.changes), exceptions, "High" if exceptions else "Low",
                         "Remove production deploy rights from developers; deploy through the pipeline only")


def changes_tested(ev: Evidence) -> ControlResult:
    exceptions = [{"subject": c["change_id"], "detail": f"no test evidence ({c['system']})"} for c in ev.changes if c["tested"] != "Y"]
    return ControlResult("CM-03", "Change", "Changes are tested before deployment", "Each change has test evidence",
                         "BAI07.04", "A.8.29", len(ev.changes), exceptions, "Medium" if exceptions else "Low",
                         "Make test evidence (automated results) a mandatory field of the change ticket")


def emergency_reviewed(ev: Evidence) -> ControlResult:
    emergency = [c for c in ev.changes if c["type"] == "Emergency"]
    exceptions = []
    for c in emergency:
        if not c["post_review_date"]:
            exceptions.append({"subject": c["change_id"], "detail": "emergency change never reviewed"})
        elif (date.fromisoformat(c["post_review_date"]) - date.fromisoformat(c["deployed_date"])).days > EMERGENCY_REVIEW_DAYS:
            exceptions.append({"subject": c["change_id"], "detail": "post-implementation review later than 5 days"})
    return ControlResult("CM-04", "Change", "Emergency changes are reviewed within 5 days", "Emergency changes get retrospective approval",
                         "BAI06.02", "A.8.32", len(emergency), exceptions, "Medium" if exceptions else "Low",
                         "Track emergency changes on a CAB dashboard until the review is closed")


def dual_control(ev: Evidence) -> ControlResult:
    exceptions = [{"subject": k["ceremony_id"], "detail": f"{k['purpose']} on {k['date']}: both components entered by {k['custodian_1']}"}
                  for k in ev.ceremonies if k["custodian_1"] == k["custodian_2"]]
    return ControlResult("OP-01", "Operations", "HSM key ceremonies use dual control", "Two different custodians enter key components",
                         "DSS05.03", "A.8.24", len(ev.ceremonies), exceptions, "Critical" if exceptions else "Low",
                         "Repeat the ceremony with two custodians and re-key; enforce custodian separation in the HSM console")


def privileged_access(ev: Evidence) -> ControlResult:
    privileged = set(ev.policy["privileged_roles"])
    titles = {p["employee_id"]: p["job_title"] for p in ev.people}
    expected = {"System Administrator", "DBA"}
    holders = [a for a in ev.accounts if roles(a) & privileged]
    exceptions = [{"subject": f"{a['user_id']} ({a['system']})", "detail": f"{', '.join(sorted(roles(a) & privileged))} held by {titles.get(a['employee_id'], 'no owner')}"}
                  for a in holders if titles.get(a["employee_id"]) not in expected and a["user_id"] not in ev.policy["approved_non_personal"]]
    return ControlResult("AC-06", "Access", "Privileged access is restricted", "Only administrators hold privileged roles",
                         "DSS05.04", "A.8.2", len(holders), exceptions, "High" if exceptions else "Low",
                         "Move privileged roles into a PAM vault with just-in-time elevation")


CONTROLS = [leavers_removed, segregation_of_duties, shared_accounts, dormant_accounts, privileged_access, password_configuration,
            changes_approved, developer_not_deployer, changes_tested, emergency_reviewed, dual_control]


def run_all(ev: Evidence) -> list[ControlResult]:
    return [control(ev) for control in CONTROLS]
