# An Interactive Active Directory Attack-Path Modeling and Security Assessment Framework — Active Directory Red-Team Laboratory

**An Interactive Active Directory Attack-Path Modeling and Security Assessment Framework** is a modular Active Directory security laboratory for **authorized penetration testing, adversary emulation, security research, and cybersecurity education**.

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
* 🧪 **Lab Health Center** — Security-tool and dependency verification
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

RedForge separates operational data into two modes:

* **REAL LAB** — genuine authorized network/tool execution
* **DEMO / SIMULATION** — synthetic training data without live interaction

This distinction helps prevent simulated results from being presented as real security findings.

## 🛠️ Tech Stack

**Frontend:** React, TypeScript
**Backend:** Node.js, Express.js
**Protocols:** LDAP, SMB, Kerberos
**Telemetry:** REST API, SSE
**Security:** Scope Guard, SHA-256, Audit Logging
**Tooling:** Nmap, Impacket, SMB utilities
**Framework:** MITRE ATT&CK

## 🚧 Development Status

An Interactive Active Directory Attack-Path Modeling and Security Assessment Framework is being developed from a simulated prototype toward a **real, scope-controlled Active Directory security laboratory**.

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

Use An Interactive Active Directory Attack-Path Modeling and Security Assessment Framework only against systems you own or have explicit authorization to assess.

## 📄 License

An Interactive Active Directory Attack-Path Modeling and Security Assessment Framework is released under the **MIT License**.

See the [`LICENSE`](LICENSE) file for the full license text.

**An Interactive Active Directory Attack-Path Modeling and Security Assessment Framework — Discover. Assess. Validate. Report.**
