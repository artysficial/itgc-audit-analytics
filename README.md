# ITGC Audit Analytics

[![Tests and dashboard](https://github.com/artysficial/itgc-audit-analytics/actions/workflows/tests.yml/badge.svg)](https://github.com/artysficial/itgc-audit-analytics/actions/workflows/tests.yml)
[![Dashboard](https://img.shields.io/badge/dashboard-live-0071e3)](https://artysficial.github.io/itgc-audit-analytics/)

Full-population testing of **IT general controls** for the fictional Arunika Bank, covering SAP S/4HANA, the HSM
API console and Active Directory, with findings, management actions and a control matrix mapped to
**COBIT 2019** and **ISO/IEC 27001:2022 Annex A**.

**[View the live audit dashboard →](https://artysficial.github.io/itgc-audit-analytics/)**

## Controls

| ID | Control | COBIT 2019 | ISO 27001:2022 |
| --- | --- | --- | --- |
| AC-01 | Leavers are removed promptly (HR roster vs accounts) | DSS05.04 | A.5.18 |
| AC-02 | Segregation of duties (SAP P2P conflicts, HSM key-custodian dual control) | DSS06.03 | A.5.3 |
| AC-03 | No shared or unowned accounts | DSS05.04 | A.5.16 |
| AC-04 | Dormant accounts disabled after 90 days | DSS05.04 | A.5.18 |
| AC-05 | Authentication settings meet the standard (length, age, lockout, history, MFA) | DSS05.04 | A.5.17, A.8.5 |
| AC-06 | Privileged access restricted to administrators | DSS05.04 | A.8.2 |
| CM-01 | Changes approved before deployment | BAI06.01 | A.8.32 |
| CM-02 | Developers do not deploy their own changes | BAI06.01 | A.8.31, A.5.3 |
| CM-03 | Changes tested before deployment | BAI07.04 | A.8.29 |
| CM-04 | Emergency changes reviewed within 5 days | BAI06.02 | A.8.32 |
| OP-01 | HSM key ceremonies use dual control | DSS05.03 | A.8.24 |

## How it works

- `audit/generate.py` produces the evidence (HR roster, account listings, change tickets, key ceremony log,
  configuration export) with exceptions planted on purpose.
- `audit/controls.py` tests each control over the **whole population** and concludes Effective / Partially
  effective / Ineffective based on the risk of what it finds.
- `tests/` proves every control's logic on hand-built positive and negative cases (including the 90-day and
  5-day boundaries) before trusting it on the evidence, and checks the evidence is complete and in period.
- `tools/build_dashboard.py` writes the audit report with findings sorted by risk and agreed management actions.

```bash
pip install -r requirements.txt
python -m pytest && python tools/build_dashboard.py
```

## Part of a case study

The IT Auditor lens on the **Arunika Bank payment-security programme**: it audits the HSM platform the
[SDET project](https://artysficial.github.io/hsm-api-security-lab/) tests and the SAP system the
[procure-to-pay project](https://artysficial.github.io/sap-p2p-analytics/) analyses.

Built by [Rahmadani Tyas Ningrum](https://artysficial.github.io/) · MIT licence
