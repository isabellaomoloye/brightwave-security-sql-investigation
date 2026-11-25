# brightwave-security-sql-investigation
# Insider Risk, Data Access & Phishing Response Investigation (MySQL)

![MySQL](https://img.shields.io/badge/Database-MySQL%208.0%2B-4479A1?style=flat&logo=mysql&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Security%20%26%20Risk%20Analytics-2E8B57?style=flat)
![Period](https://img.shields.io/badge/Audit%20Period-Aug%203%E2%80%9330%2C%202026-555555?style=flat)

## Overview
An end-to-end SQL security investigation for **Brightwave Logistics** covering one month of operational logs (**3–30 August 2026**). Triggered by management concerns over potential client pricing data exposure, over-provisioned user permissions, targeted phishing against Finance and HR, and a growing backlog of unresolved security incidents, this project audits five relational tables (`employees`, `systems`, `access_logs`, `email_security_events`, and `incidents`) in **MySQL 8.0+**.

---

## Database Schema & Data Quality Audit
The investigation evaluates 5 relational tables while preserving raw source tables untouched and querying standardized views/CTEs:

| Table | Raw Rows | Data-Quality & Cleaning Issues Identified |
| :--- | :---: | :--- |
| `employees` | 20 | 1 missing `clearance_level` (`employee_id = 1011`); inconsistent department casing/whitespace (`finance`, `Legal `) |
| `systems` | 10 | Clean schema and classification levels (`Public`, `Internal`, `Confidential`, `Restricted`) |
| `access_logs` | 254 | 3 exact duplicate activity pairs (6 rows); 1 orphan `employee_id` (`1099`); 1 negative `records_accessed` (`-5`); 2 `NULL` counts; `granted` casing |
| `email_security_events` | 119 | 1 impossible timestamp where `action_timestamp` preceded `received_timestamp` (`email_id = 7031`) |
| `incidents` | 20 | 1 impossible timestamp where `closed_timestamp` preceded `reported_timestamp` (`incident_id = 9012`); `high` severity casing |

---

## Key Analytical Findings

### 1. Data Access & Privilege Risk
Across **251 deduplicated access events**, **233 (92.83%)** were granted and **18 (7.17%)** were denied, with **27 events (10.76%)** occurring outside business hours (`Mon–Fri 08:00–17:59`). Granted downloads and exports moved **27,349 records** overall.

| System Name | Data Classification | Granted Records Moved |
| :--- | :--- | :---: |
| Customer Database | Confidential | 21,504 |
| Backup Server | Restricted | 3,447 |
| Ticketing System | Internal | 687 |
| Company Intranet | Public | 548 |
| Contract Archive | Confidential | 352 |
| Remaining 4 Systems (Inventory, HR, Payroll, Finance) | Internal / Restricted | 794 |

* **Top Record Movers:** **Victor Eze** (Sales) moved **18,734 records** (peaking at a 4,750-record remote export on `2026-08-28 00:47`), followed by **Yusuf Abdullahi** (IT) with **3,523 records** and **Patrick Ude** (Sales) with **3,110 records**.
* **Above-Clearance Access Granted:** **8 events** were granted to `Level 2` employees accessing `Confidential`/`Restricted` systems—**Hauwa Idris** (4 events on *Finance Ledger*), **Kelechi Umeh** (3 edits on *Source Code Repository*), and **Esther Ogunleye** (1 download of 86 records from *HR Records*).
* **Post-Termination Access:** Terminated Sales employee **Patrick Ude** (terminated `2026-08-14`) recorded **6 granted sessions** on the *Customer Database* between `2026-08-15` and `2026-08-27`, downloading/exporting **3,110 records**.

### 2. Phishing & Email Security
Out of **119 emails**, **63 (52.94%)** were malicious (`57 Phishing` and `6 Malware`), generating a **39.68% (25 / 63)** overall click/attachment-open rate.

| Department | Malicious Emails | Clicked / Opened | Click / Open Rate | Reported | Report Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Finance | 14 | 9 | 64.29% | 1 | 7.14% |
| Customer Service | 4 | 2 | 50.00% | 2 | 50.00% |
| Sales | 10 | 5 | 50.00% | 0 | 0.00% |
| HR | 7 | 3 | 42.86% | 3 | 42.86% |
| Operations | 11 | 4 | 36.36% | 0 | 0.00% |
| Legal | 6 | 1 | 16.67% | 3 | 50.00% |
| IT | 11 | 1 | 9.09% | 9 | 81.82% |

* **Response Speed Gap:** Employees clicked or opened malicious emails in an average of **43.9 minutes** (`5–85` mins), whereas reporting took an average of **204.6 minutes** (`9–485` mins).
* **Repeat Interactions:** Six employees interacted with malicious emails multiple times—led by **Halima Garba** (5) and **Hauwa Idris** (4) in Finance, and **Musa Lawal** (3) in Operations.

### 3. Incident Response & SLA Performance
Of **20 logged incidents**, **13 are Closed**, **4 are In Progress**, and **3 are Open** (with all **3 Critical** and **2 High** incidents remaining unresolved as of `2026-08-31 00:00`).

| Severity | Time-Valid Incidents | SLA Target | SLA Breaches | Avg. Elapsed Hours |
| :--- | :---: | :---: | :---: | :---: |
| Critical | 3 | 24h | 3 | 119.1h |
| High | 6 | 72h | 4 | 144.2h |
| Medium | 5 | 120h | 1 | 84.4h |
| Low | 5 | 240h | 1 | 135.7h |

---

## SQL Techniques Demonstrated
* **Data Validation & Cleaning:** Multi-column `GROUP BY ... HAVING COUNT(*) > 1` duplicate checks, `LEFT JOIN ... IS NULL` orphan key detection, chronological timestamp checks, and `TRIM()`/`UPPER()` standardization.
* **Window Functions & CTEs:** Departmental ranking with `DENSE_RANK() OVER (PARTITION BY ...)`, week-over-week/day-over-day comparisons via `LAG()`, cumulative export totals using `SUM() OVER (... ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)`, and multi-CTE employee risk scoring (`0–100`).
* **Reusable Reporting:** `CREATE VIEW vw_employee_security_summary` consolidating access, phishing, and incident metrics across four tables.

---

## Recommendations & Limitations
* **Access & Offboarding Controls:** Immediately revoke active credentials for Patrick Ude, align system permissions with employee clearance levels, and review high-volume remote/off-hours exports from Confidential and Restricted systems.
* **Phishing Defense & Incident Triage:** Run targeted anti-phishing training for Finance, Sales, and Operations, streamline one-click email reporting, and escalate the 5 open/in-progress Critical and High incidents.
* **Analytical Limitations:** Log anomalies serve as risk indicators for human review rather than proof of malicious intent; legitimate workflows (e.g., scheduled IT backups or month-end Sales reporting) require operational context outside the database[cite: 1, 3, 4, 5, 8].
