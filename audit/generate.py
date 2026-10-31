"""Generates the audit evidence in data/ (seeded and reproducible).

Fictional Arunika Bank, audit period 1 January - 31 October 2026. Exceptions are planted so the
control tests have real findings: leavers with active accounts, segregation-of-duties conflicts,
a shared account, dormant accounts, a change without test evidence, an emergency change without
review, a key ceremony without dual control, and HSM console password settings below standard.
"""

from __future__ import annotations

import csv
import json
import random
from datetime import date, timedelta
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"
PERIOD_END = date(2026, 10, 31)

FIRST = ["Adi", "Bayu", "Citra", "Dewi", "Eka", "Fajar", "Gita", "Hadi", "Indah", "Joko", "Kartika", "Lukas", "Maya", "Nanda", "Oki", "Putri", "Rizki", "Sari", "Tono", "Wulan", "Yudi", "Zahra"]
LAST = ["Pratama", "Santoso", "Wijaya", "Lestari", "Hidayat", "Kusuma", "Saputra", "Nugroho", "Rahayu", "Siregar"]
DEPARTMENTS = {
    "Finance": ["AP Clerk", "AP Supervisor", "Treasury Officer", "Controller"],
    "Procurement": ["Buyer", "Procurement Manager"],
    "IT Operations": ["System Administrator", "DBA", "Service Desk"],
    "Development": ["Developer", "Lead Developer"],
    "Information Security": ["Key Custodian", "Security Officer"],
}
ROLE_BY_TITLE = {  # system -> roles a job title should have
    "AP Clerk": {"SAP S/4HANA": ["Z_AP_INVOICE_ENTRY"]},
    "AP Supervisor": {"SAP S/4HANA": ["Z_AP_INVOICE_RELEASE"]},
    "Treasury Officer": {"SAP S/4HANA": ["Z_FI_PAYMENT_RUN"]},
    "Controller": {"SAP S/4HANA": ["Z_FI_DISPLAY"]},
    "Buyer": {"SAP S/4HANA": ["Z_MM_PO_CREATE"]},
    "Procurement Manager": {"SAP S/4HANA": ["Z_MM_PO_RELEASE", "Z_MM_VENDOR_MAINTAIN"]},
    "System Administrator": {"Active Directory": ["Domain Admins"], "HSM API Console": ["hsm-operator"]},
    "DBA": {"SAP S/4HANA": ["Z_BASIS_DB"]},
    "Service Desk": {"Active Directory": ["Helpdesk Password Reset"]},
    "Developer": {"SAP S/4HANA": ["Z_DEV_ABAP"]},
    "Lead Developer": {"SAP S/4HANA": ["Z_DEV_ABAP", "Z_TRANSPORT_RELEASE"]},
    "Key Custodian": {"HSM API Console": ["key-custodian-a"]},
    "Security Officer": {"HSM API Console": ["audit-reader"], "Active Directory": ["Security Auditors"]},
}


def write_csv(name, header, rows):
    with open(DATA / f"{name}.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    rng = random.Random(27001)
    DATA.mkdir(exist_ok=True)
    people, accounts = [], []
    titles = [(dept, t) for dept, ts in DEPARTMENTS.items() for t in ts]
    for i in range(60):
        dept, title = titles[i % len(titles)]
        emp = f"E{1000 + i}"
        name = f"{FIRST[i % len(FIRST)]} {LAST[(i * 7) % len(LAST)]}"
        terminated = i in (5, 18, 33, 41, 52)
        term_date = (date(2026, 1, 1) + timedelta(days=rng.randint(20, 270))).isoformat() if terminated else ""
        people.append([emp, name, dept, title, "Terminated" if terminated else "Active", term_date])
        for system, roles in ROLE_BY_TITLE[title].items():
            last_login = PERIOD_END - timedelta(days=rng.randint(0, 25))
            if terminated:
                # leavers: most removed promptly; three planted with accounts still enabled
                if i not in (5, 33, 52):
                    continue
                last_login = date.fromisoformat(term_date) + timedelta(days=rng.choice([0, 6, 21]))
            if i in (27, 58):
                last_login = PERIOD_END - timedelta(days=rng.randint(120, 200))  # dormant
            accounts.append([system, f"{name.split()[0].lower()}.{name.split()[1].lower()}", emp, ";".join(roles), last_login.isoformat(), "Enabled"])

    # planted segregation-of-duties conflicts
    accounts[[a[2] for a in accounts].index("E1031")][3] += ";Z_FI_PAYMENT_RUN"          # PO release + vendor maintain + payment run
    custodian_b = next(a for a in accounts if a[3] == "key-custodian-a" and a[2] == "E1024")
    custodian_b[3] += ";key-custodian-b"                                                   # one person holds both HSM key components
    accounts.append(["SAP S/4HANA", "sap.support", "", "Z_SUPPORT_DISPLAY", (PERIOD_END - timedelta(days=3)).isoformat(), "Enabled"])  # shared account
    accounts.append(["Active Directory", "svc.backup", "", "Backup Operators", PERIOD_END.isoformat(), "Enabled"])  # service account (approved)
    write_csv("hr_roster", ["employee_id", "name", "department", "job_title", "status", "termination_date"], people)
    write_csv("accounts", ["system", "user_id", "employee_id", "roles", "last_login", "status"], accounts)

    developers = [p for p in people if p[3] in ("Developer", "Lead Developer") and p[4] == "Active"]
    admins = [p for p in people if p[3] == "System Administrator" and p[4] == "Active"]
    approvers = [p for p in people if p[3] in ("Lead Developer", "Security Officer") and p[4] == "Active"]
    changes = []
    for n in range(48):
        system = rng.choice(["SAP S/4HANA", "HSM API Console", "HSM API Console", "Active Directory"])
        dev, deployer, approver = rng.choice(developers), rng.choice(admins), rng.choice(approvers)
        deployed = date(2026, 1, 5) + timedelta(days=rng.randint(0, 295))
        kind = "Emergency" if n in (9, 30, 41) else "Standard"
        approved = (deployed - timedelta(days=rng.randint(1, 6))).isoformat()
        tested = "Y"
        review = (deployed + timedelta(days=rng.randint(1, 4))).isoformat() if kind == "Emergency" else ""
        if n == 26:
            tested = "N"                        # no test evidence
        if n == 41:
            review = ""                         # emergency change never reviewed
        changes.append([f"CHG{26000 + n}", system, kind, dev[0], approver[0] if approved else "", deployer[0], approved, deployed.isoformat(), tested, review])
    write_csv("changes", ["change_id", "system", "type", "developer", "approver", "deployer", "approved_date", "deployed_date", "tested", "post_review_date"], changes)

    ceremonies = []
    custodians = [p[0] for p in people if p[3] == "Key Custodian" and p[4] == "Active"]
    for n in range(8):
        a, b = rng.sample(custodians, 2)
        if n == 5:
            b = a                               # one person entered both key components
        ceremonies.append([f"KC-2026-{n + 1:02d}", (date(2026, 2, 1) + timedelta(days=30 * n)).isoformat(), "Zone master key load" if n % 2 else "Key rotation", a, b])
    write_csv("key_ceremonies", ["ceremony_id", "date", "purpose", "custodian_1", "custodian_2"], ceremonies)

    policy = {
        "standard": {"min_length": 12, "max_age_days": 90, "lockout_attempts": 5, "history": 12, "mfa": True},
        "systems": {
            "Active Directory": {"min_length": 14, "max_age_days": 90, "lockout_attempts": 5, "history": 24, "mfa": True},
            "SAP S/4HANA": {"min_length": 12, "max_age_days": 90, "lockout_attempts": 5, "history": 12, "mfa": True},
            "HSM API Console": {"min_length": 12, "max_age_days": 180, "lockout_attempts": 10, "history": 12, "mfa": True},
        },
        "approved_non_personal": ["svc.backup"],
        "privileged_roles": ["SAP_ALL", "Domain Admins", "Z_BASIS_DB", "hsm-operator"],
    }
    (DATA / "policy.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")
    print(f"wrote {len(people)} people, {len(accounts)} accounts, {len(changes)} changes, {len(ceremonies)} key ceremonies")


if __name__ == "__main__":
    main()
