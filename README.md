# RedForge — Active Directory Red-Team Laboratory

**RedForge** is a modular Active Directory security laboratory for **authorized penetration testing, adversary emulation, security research, and cybersecurity education**.

It combines network discovery, Active Directory enumeration, attack-path visualization, security validation, evidence collection, MITRE ATT&CK mapping, and reporting in a single platform.

> ⚠️ **Authorized Use Only:** Designed for isolated labs, CTFs, research environments, and systems where explicit authorization has been granted.

## ✨ Features

* 🛡️ **Scope Guard** — CIDR-based target validation and boundary enforcement
* 🌐 **Host Discovery** — Lab network discovery and connectivity testing
* 🔎 **Port & Service Enumeration** — TCP scanning and service identification
* 🖥️ **SMB Assessment** — SMB dialect and signing analysis
* 📂 **Active Directory** — LDAP-based directory and domain assessment
* 🕸️ **Attack Graph** — Visualize AD relationships and potential attack paths
* 🔐 **Kerberos Assessment** — AS-REP and Kerberoasting security checks
* ⚡ **Privilege Assessment** — ACL, delegation, and replication-permission analysis
* 🔄 **Lateral Movement** — Controlled lab-based validation workflows
* 🧾 **Evidence Vault** — SHA-256 integrity and artifact tracking
* 🎯 **MITRE ATT&CK** — Technique and tactic mapping
* 📋 **Findings Management** — Finding lifecycle and remediation tracking
* 📡 **Real-Time Telemetry** — Task states and SSE output streaming
* 🧪 **Lab Health Center** — Verify required security tools and dependencies
* 📊 **Reporting** — Structured penetration-testing reports

## 🏗️ Architecture

```text
┌───────────────────┐
│   React / TS UI   │
└─────────┬─────────┘
          │ REST / SSE
┌─────────▼─────────┐
│ Express.js Server │
├───────────────────┤
│ Scope Guard       │
│ Task Runner       │
│ Assessment Engine │
│ Evidence Manager  │
│ Audit Logger      │
└─────────┬─────────┘
          │
    ┌─────▼─────┐
    │ AD Lab    │
    │ DC / PCs  │
    │ SMB/LDAP  │
    │ Kerberos  │
    └───────────┘
```

## 🔬 REAL LAB / DEMO

RedForge clearly separates:

* **REAL LAB** — genuine authorized network/tool execution
* **DEMO / SIMULATION** — synthetic training data with no live interaction

This prevents simulated results from being presented as real security findings.

## 🛠️ Tech Stack

**Frontend:** React, TypeScript
**Backend:** Node.js, Express.js
**Protocols:** LDAP, SMB, Kerberos
**Telemetry:** REST API, SSE
**Security:** Scope Guard, SHA-256, audit logging
**Tooling:** Nmap, Impacket, SMB utilities
**Framework:** MITRE ATT&CK

## 🚧 Status

RedForge is actively being developed from a simulated prototype toward a **real, scope-controlled Active Directory security laboratory**.

### Roadmap

* [ ] Hardened CIDR Scope Guard
* [ ] Real host discovery
* [ ] Real port/service enumeration
* [ ] SMB negotiation assessment
* [ ] Live LDAP integration
* [ ] Interactive AD attack graph
* [ ] Controlled task execution
* [ ] SSE telemetry
* [ ] Persistent evidence and audit storage
* [ ] Automated security reporting

## ⚠️ Responsible Use

Use RedForge only against systems you own or have explicit authorization to assess.

**RedForge — Discover. Assess. Validate. Report.**
📜 License

Choose a license appropriate for your intended distribution model.

For example:

MIT License

or a more restrictive license if you want to limit redistribution or commercial use.
