# azure-honeypot-detection-lab


# Azure Honeypot & Detection Lab

A hands-on cloud security project built on Microsoft Azure to simulate real-world attack surfaces, implement defense-in-depth hardening, and operationalize threat detection with Sentinel and KQL.

---

## Objective

Design a publicly reachable Ubuntu VM in Azure, observe brute-force and unauthorized access attempts in real time, and progressively harden the environment using only native Azure security tools and Linux controls. The end state is a minimal-attack-surface VM with centralized logging, custom detection rules, and key-only administration.

---

## Architecture & Tools

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Compute | Azure VM (Ubuntu 22.04 LTS) | Target workload / "honeypot" |
| Network | Azure NSG | Edge access control |
| SIEM / SOAR | Microsoft Sentinel | Log ingestion, detection engineering, incident creation |
| Data Source | Syslog via Azure Monitor Agent | Authentication telemetry |
| OS Hardening | OpenSSH, PAM, sshd_config | Local authentication & session controls |

---

## Phase 1 — Baseline Deployment

- Deployed standard Ubuntu VM with a public IP and default NSG rules.
- Enabled boot diagnostics and serial console for break-glass recovery.
- Documented initial exposure: port 22 open to `0.0.0.0/0` with password authentication enabled.

---

## Phase 2 — Telemetry & Visibility

1. **Connected the VM to a Log Analytics workspace** using the Azure Monitor Agent.
2. **Configured the Syslog data connector** in Sentinel for the `authpriv` facility.
3. Validated log flow by querying raw authentication events:

```kusto
Syslog
| where Facility == "authpriv"
| where SyslogMessage contains "Failed password"
| extend AttackerIP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize Attempts = count() by AttackerIP, bin(TimeGenerated, 5m)
| order by Attempts desc
```

**Result:** Identified hundreds of distributed brute-force attempts within the first 24 hours from global IP ranges.

---

## Phase 3 — Detection Engineering (Sentinel Analytics Rules)

Built two custom scheduled analytics rules to operationalize the data:

| Rule | Logic | Severity |
|------|-------|----------|
| **Brute-Force Detection** | ≥ 5 failed SSH attempts from a single IP in 5 minutes | Medium |
| **Successful Auth Anomaly** | Any `Accepted publickey` event (post-hardening baseline) | High |

**Brute-Force KQL:**
```kusto
let threshold = 5;
Syslog
| where Facility == "authpriv"
| where SyslogMessage contains "Failed password"
| extend AttackerIP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize Attempts = count() by AttackerIP, Computer, bin(TimeGenerated, 5m)
| where Attempts >= threshold
| project AttackerIP, Attempts, Computer, TimeGenerated
```

Rules auto-create Sentinel incidents and map to the **MITRE ATT&CK** techniques:
- *T1110 — Brute Force*
- *T1078 — Valid Accounts*

---

## Phase 4 — Defense-in-Depth Hardening

Applied controls in order of criticality:

| Control | Implementation | Impact |
|---------|---------------|--------|
| **Network Segmentation** | Replaced default NSG rule with a source-IP-restricted rule (`/32`) for port 22; added explicit Deny rule | Eliminated unauthorized network reachability |
| **Key-Based Authentication** | Generated Ed25519 key pair locally; injected public key to VM | Removed password dependency |
| **Disable Password Auth** | Updated `sshd_config` and cloud-init include files (`sshd_config.d/*.conf`) to set `PasswordAuthentication no`; restarted sshd | Closed brute-force vector entirely |
| **PAM Hardening** | Disabled `ChallengeResponseAuthentication` | Prevented fallback auth mechanisms |

**Verification:** Confirmed that password-only connections return `Permission denied (publickey)` and key-based sessions succeed without interactive credentials.

---

## Phase 5 — Continuous Monitoring

- **Microsoft Defender for Cloud** (Foundational CSPM — free tier) enabled for secure-score tracking and compliance posture.
- **Sentinel Workbooks** considered for future visual geolocation mapping of attacker IPs.

---

## Key Takeaways

- **Visibility first:** Without Syslog ingestion, brute-force activity was invisible noise. Centralized logging turned it into actionable signal.
- **Least privilege at the edge:** The NSG source-IP rule provided the highest ROI of any control—zero cost, immediate risk reduction.
- **Config persistence matters:** Ubuntu cloud images store SSH defaults in `sshd_config.d/` include files; hardening requires checking override files, not just the main config.
- **Detection as code:** KQL analytics rules allow version-controlled, repeatable detection logic that maps directly to incident response workflows.

---

## Skills Demonstrated

- Azure Compute, Networking, and IAM
- SIEM engineering (Sentinel: data connectors, analytics rules, incident management)
- KQL (Kusto Query Language) for threat hunting
- Linux system hardening (SSH/PAM/OpenSSH)
- Network security group (NSG) policy design
- MITRE ATT&CK framework mapping
- Cloud security posture management (CSPM)

---

## Future Enhancements

- [ ] Implement **Just-in-Time (JIT) VM Access** via Defender for Servers to remove persistent port 22 exposure.
- [ ] Deploy a second VM in a private subnet with Azure Bastion for admin access, eliminating public SSH entirely.
- [ ] Build a Sentinel Playbook (Logic Apps) to auto-add brute-force IPs to an NSG deny list.
- [ ] Capture and analyze malware samples or shell commands from a dedicated Cowrie honeypot container (isolated VLAN).

---

*Built using Azure free/student credits. No production data or sensitive credentials are stored in this repository.*
