# Home SOC Lab — Threat Detection & Incident Response with Wazuh SIEM

A virtualized Security Operations Center built with the open-source **Wazuh** SIEM/XDR platform. A **Kali Linux** attacker VM runs real attacks (SSH brute force, port scanning, failed Windows logins, file tampering, rogue user creation) against monitored **Ubuntu** and **Windows** endpoints. I wrote custom detection rules, mapped alerts to **MITRE ATT&CK**, configured automated response (IP blocking), and documented each attack as a formal incident report.

> **Scope note:** Every VM in this lab is isolated on a host-only/NAT network and owned by me. No attacks were run against anything outside this lab.

---

## Table of Contents

- [Skills Demonstrated](#skills-demonstrated)
- [Architecture](#architecture)
- [Lab Environment](#lab-environment)
- [Attacks & Detections](#attacks--detections)
- [Results](#results)
- [Detection Gap: Port Scanning](#detection-gap-port-scanning)
- [Custom Detection Rule & Automated Response](#custom-detection-rule--automated-response)
- [Repo Structure](#repo-structure)
- [Setup](#setup)
- [Incident Reports](#incident-reports)
- [Lessons Learned](#lessons-learned)
- [Stretch Goals / Future Work](#stretch-goals--future-work)

---

## Skills Demonstrated

Linux administration, SSH, networking, log analysis, SIEM/endpoint monitoring, detection engineering, MITRE ATT&CK mapping, incident documentation, Active Response configuration.

---

## Architecture

![architecture](architecture.png)

```
                 Isolated Host-Only / NAT Network (192.168.56.0/24)

   +-------------+        attacks        +--------------------+
   | Kali Linux  | --------------------> | Ubuntu Server      |
   | (Attacker)  |                       | Wazuh Agent        |
   +-------------+        attacks        +--------------------+
          |         ------------------->  +--------------------+
          |                               | Windows 10/11      |
          |                               | Wazuh Agent        |
          |                               +--------------------+
          |                                        |
          |                 logs/events            v
          |                               +--------------------+
          +-----------------------------> | Wazuh Server       |
              (also visible to manager)   | Manager+Indexer+   |
                                          | Dashboard          |
                                          +--------------------+
```

---

## Lab Environment

| VM | Role | RAM | CPU | Notes |
|----|------|-----|-----|-------|
| Wazuh Server (Ubuntu 22.04) | SIEM manager, indexer, dashboard | 4 GB | 2 | All-in-one install |
| Ubuntu Server | Victim 1 — Linux endpoint | 1–2 GB | 1 | Wazuh agent + SSH enabled |
| Windows 10/11 | Victim 2 — Windows endpoint | 4 GB | 2 | Omitted if host RAM ≤ 8 GB |
| Kali Linux | Attacker | 2 GB | 1–2 | Hydra, nmap preinstalled |

Setup steps (VM creation, network config, Wazuh install, agent deployment) are in [setup-guide.md](setup-guide.md).

---

## Attacks & Detections

| # | Attack | Tool | MITRE Technique | Victim |
|---|--------|------|------------------|--------|
| 1 | SSH brute force | Hydra | T1110 – Brute Force | Ubuntu |
| 2 | Port scan (SYN, version, full) | nmap | T1046 – Network Service Discovery | Ubuntu |
| 3 | Repeated failed logins | Manual / RDP | T1110 – Brute Force | Windows |
| 4 | Rogue user, cron persistence, file tampering | Manual | T1136, T1053.003 | Ubuntu |

Attack scripts are in [`attacks/`](attacks/). Full writeups for each are in [`incident-reports/`](incident-reports/).

---

## Results

| # | Attack | Tool | MITRE Technique | Detected? | Rule ID(s) | Response |
|---|--------|------|-----------------|-----------|------------|----------|
| 1 | SSH brute force | Hydra | T1110 | Yes | 100001 (base 5760) | IP block via Active Response |
| 2 | Port scan | nmap | T1046 | No | — | Gap documented, Suricata recommended |
| 3 | Windows failed logons | Manual/RDP | T1110 | Yes | <fill in from your run> | — |
| 4 | Rogue user + cron + file edits | Manual | T1136, T1053.003 | Yes | <fill in from your run> | FIM alerts |

> Fill in real rule IDs from your own Threat Hunting view — don't ship placeholder numbers.

---

## Detection Gap: Port Scanning

Wazuh (host-based) did **not** detect the nmap scans in this lab. This is expected and documented honestly rather than hidden: a host agent reads log files on the endpoint, it doesn't inspect raw network traffic, so a scan that never produces a log entry on the victim is invisible to it.

**What would close this gap:** a network IDS such as **Suricata**, placed inline or spanning the network, or reviewing firewall/router logs for connection attempts across many ports in a short window. This is listed as a stretch goal below.

---

## Custom Detection Rule & Automated Response

**Custom rule** — `detection-rules/local_rules.xml`, appended to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh server:

```xml
<group name="local,sshd,">
  <rule id="100001" level="12" frequency="5" timeframe="60">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>Custom: 5+ SSH authentication failures from same IP within 60s</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

**Active Response** — appended to `/var/ossec/etc/ossec.conf` on the Wazuh server:

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100001</rules_id>
  <timeout>600</timeout>
</active-response>
```

Verified by re-running the Hydra attack and confirming rule 100001 fired and the attacker's IP was dropped for 10 minutes.

**Known risk:** automatic IP blocking can affect legitimate users behind a shared NAT IP, or be abused by an attacker to cause a denial-of-service against a spoofed/shared address. Worth knowing cold for interviews.

---

## Repo Structure

```
wazuh-soc-lab/
├── README.md
├── architecture.png
├── setup-guide.md
├── attacks/
│   ├── 01_ssh_bruteforce.sh
│   ├── 02_port_scan.sh
│   └── 03_persistence.sh
├── detection-rules/
│   └── local_rules.xml
├── incident-reports/
│   ├── IR-001-ssh-bruteforce.md
│   ├── IR-002-port-scan.md
│   ├── IR-003-windows-failed-logons.md
│   └── IR-004-persistence-fim.md
└── screenshots/
```

---

## Setup

Full step-by-step VM creation, networking, Wazuh install, and agent deployment: see [setup-guide.md](setup-guide.md).

---

## Incident Reports

Each attack has a full incident report with timeline, evidence, MITRE mapping, analysis and remediation recommendations:

- [IR-001 — SSH Brute Force](incident-reports/IR-001-ssh-bruteforce.md)
- [IR-002 — Port Scan (Detection Gap)](incident-reports/IR-002-port-scan.md)
- [IR-003 — Windows Failed Logons](incident-reports/IR-003-windows-failed-logons.md)
- [IR-004 — Persistence & File Tampering](incident-reports/IR-004-persistence-fim.md)

---

## Lessons Learned

- Host-based SIEM detection depends entirely on what gets logged on the endpoint — it has blind spots for anything purely at the network layer.
- Custom correlation rules (`frequency` + `timeframe` + `same_source_ip`) are far more useful than relying on default rule severity alone.
- Active Response is powerful but comes with real operational risk (false-positive blocking); it should be scoped and time-limited, as done here (600s timeout).
- Writing incident reports after each attack — not just screenshotting alerts — is what actually builds the muscle memory for a SOC analyst interview.

---

## Stretch Goals / Future Work

- Add **Suricata** as a network IDS and re-run the port scan to close the T1046 detection gap.
- Integrate **VirusTotal** with Wazuh for file-hash checks.
- Add an **nginx** web server and detect SQL-injection attempts from its logs — a step toward application-security work.
- Build a simple Wazuh dashboard view summarizing all four attacks for the README screenshot.

---

**Tools:** Wazuh, Kali Linux, Ubuntu, Windows, Hydra, nmap, MITRE ATT&CK
**Author:** Arnav Tambe