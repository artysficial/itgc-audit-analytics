"""Builds the ITGC audit dashboard (site/index.html)."""

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import report_kit as rk  # noqa: E402
from audit.controls import Evidence, run_all  # noqa: E402

# management responses agreed in the (fictional) closing meeting
RESPONSES = {
    "AC-01": ("Head of IT Operations", "2026-11-30"),
    "AC-02": ("CISO / SAP Security Lead", "2026-11-15"),
    "AC-03": ("SAP Basis Lead", "2026-11-15"),
    "AC-04": ("IAM Manager", "2026-12-15"),
    "AC-05": ("HSM Platform Owner", "2026-12-31"),
    "CM-03": ("Head of Delivery", "2026-12-15"),
    "CM-04": ("Change Manager", "2026-11-30"),
    "OP-01": ("CISO", "2026-11-07"),
}


def main() -> None:
    ev = Evidence.load()
    results = run_all(ev)
    tests = json.loads((ROOT / "reports" / "results.json").read_text(encoding="utf-8"))
    conclusions = Counter(r.conclusion for r in results)
    findings = [r for r in results if r.exceptions]
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda r: order[r.risk])

    population = len(ev.accounts) + len(ev.changes) + len(ev.ceremonies) + len(ev.people)
    body = rk.kpis([
        ("Controls tested", len(results), "access, change and operations"),
        ("Effective", conclusions["Effective"], "no exceptions", "ok"),
        ("Partially effective", conclusions["Partially effective"], "medium-risk exceptions", "warn"),
        ("Ineffective", conclusions["Ineffective"], "high or critical exceptions", "bad"),
        ("Records analysed", f"{population:,}", "full population, no sampling"),
    ])
    domains = {}
    for r in results:
        domains.setdefault(r.domain, Counter())[r.conclusion] += 1
    body += rk.grid(
        rk.section("Control conclusions", rk.donut([
            ("Effective", conclusions["Effective"], "var(--green)"),
            ("Partially effective", conclusions["Partially effective"], "var(--orange)"),
            ("Ineffective", conclusions["Ineffective"], "var(--red)"),
        ], center=f"{conclusions['Effective']}/{len(results)}", caption="effective controls")),
        rk.section("Exceptions by control", rk.bars([(f"{r.id} {r.name}", len(r.exceptions)) for r in results if r.exceptions])),
    )

    finding_rows = []
    for r in findings:
        owner, due = RESPONSES.get(r.id, ("Control owner", "2026-12-31"))
        detail = "<br>".join(rk.esc(f"{e['subject']}: {e['detail']}") for e in r.exceptions[:4])
        if len(r.exceptions) > 4:
            detail += f"<br>… and {len(r.exceptions) - 4} more"
        finding_rows.append([r.id, rk.pill(r.risk), rk.esc(r.name), detail, rk.esc(r.recommendation), rk.esc(f"{owner}, by {due}")])
    body += rk.section("Findings and management actions", rk.table(["Control", "Risk", "Finding", "Exceptions", "Recommendation", "Owner & due date"], finding_rows, {0, 1, 2, 3, 4, 5}),
                       "Sorted by risk. Exceptions show the first four items; the full lists are in the evidence files.")
    control_rows = [[r.id, r.domain, r.name, r.objective, r.population, len(r.exceptions), rk.pill(r.conclusion), f"{r.cobit} · {r.iso}"] for r in results]
    body += rk.section("Control matrix", rk.table(["ID", "Domain", "Control", "Objective", "Population", "Exceptions", "Conclusion", "COBIT 2019 · ISO 27001:2022"], control_rows, {6}))
    body += rk.section("Scope", rk.table(["System", "Accounts", "Changes"], [
        [s, sum(1 for a in ev.accounts if a["system"] == s), sum(1 for c in ev.changes if c["system"] == s)] for s in ("SAP S/4HANA", "HSM API Console", "Active Directory")
    ]), "Audit period 1 January to 31 October 2026. Evidence: HR roster, account listings, change tickets, key ceremony logs and configuration exports.")
    passed = sum(1 for t in tests["tests"] if t["status"] == "passed")
    body += rk.section(f"Audit analytics tests · {passed}/{len(tests['tests'])} passing", rk.table(["Test", "Area", "Result"], [[t["title"], t["category"], rk.pill(t["status"])] for t in tests["tests"]], {2}),
                       "Every control's logic is proven on hand-built positive and negative cases before it is run on the evidence.")

    critical = [r for r in findings if r.risk == "Critical"]
    verdict = (f"{len(critical)} critical and {sum(1 for r in findings if r.risk == 'High')} high findings: report to the Audit Committee", "bad") if critical else ("No critical findings", "ok")
    takeaways = [
        f"{conclusions['Effective']} of {len(results)} IT controls work as designed; {conclusions['Partially effective']} are partially effective and {conclusions['Ineffective']} are ineffective.",
        f"All {population:,} records in the audit period were tested (full population, no sampling), so the exceptions below are complete, not estimates.",
    ]
    if findings:
        worst = findings[0]
        takeaways.append(f"Most serious: {worst.id} {worst.name} ({worst.risk.lower()} risk, {len(worst.exceptions)} exception{'s' if len(worst.exceptions) != 1 else ''}). {worst.recommendation}")
        dues = [RESPONSES.get(r.id, ("", "2026-12-31"))[1] for r in findings]
        takeaways.append(f"Management has agreed {len(findings)} actions with named owners, all due by {max(dues)}.")
    rk.write(str(ROOT / "site" / "index.html"), rk.page(
        title="ITGC Audit Analytics",
        eyebrow="IT Auditor · IT general controls",
        summary="Full-population testing of IT general controls over SAP S/4HANA, the HSM API console and Active Directory: access, segregation of duties, change management and HSM key ceremonies.",
        body=body, repo="itgc-audit-analytics", verdict=verdict, takeaways=takeaways,
    ))
    print(f"dashboard built: {len(findings)} findings")


if __name__ == "__main__":
    main()
