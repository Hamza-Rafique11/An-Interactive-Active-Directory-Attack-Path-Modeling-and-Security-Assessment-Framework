# RedForge — Active Directory Red-Team Laboratory

**RedForge** is a modular Active Directory security laboratory and validation platform designed for **authorized penetration testing, adversary emulation, security research, and cybersecurity education**.

It provides a controlled environment for discovering lab hosts, enumerating services, assessing Active Directory security, modeling attack paths, collecting evidence, mapping findings to MITRE ATT&CK, and generating structured security reports.

> **⚠️ Authorized Lab Use Only**
>
> RedForge is intended for isolated labs, CTF environments, security research, and systems for which the operator has explicit authorization. The platform is designed around scope enforcement and controlled execution to reduce the risk of accidental activity outside the approved assessment boundary.

---

## 🚀 Overview

RedForge combines Active Directory reconnaissance, security assessment, attack-path modeling, evidence collection, telemetry, and reporting into a single operator-focused platform.

The architecture is designed around a simple principle:

> **Every operation must be identifiable as REAL LAB execution or DEMO / SIMULATION.**

This distinction allows the platform to be used both as a hands-on penetration-testing laboratory and as an educational simulation environment without presenting synthetic results as real telemetry.

### Core Capabilities

* 🔐 Scope-controlled security assessments
* 🌐 Lab host discovery
* 🔎 TCP port and service enumeration
* 🖥️ SMB security assessment
* 📂 LDAP / Active Directory enumeration
* 🕸️ Active Directory relationship and attack-path modeling
* 🎫 Kerberos security assessments
* 🔑 Credential exposure assessment
* 🛡️ Privilege escalation and ACL analysis
* 🔄 DCSync security assessment
* ↔️ Lateral movement simulation / controlled execution
* 🧾 Evidence collection and artifact integrity
* 📋 Findings lifecycle management
* 🕵️ Audit logging and operator telemetry
* 🎯 MITRE ATT&CK technique mapping
* 📊 Executive penetration-testing reporting
* ⚙️ Controlled command execution
* 📡 Real-time task output through SSE
* 🧪 Lab health and dependency verification
* 💾 Persistent assessment state

---

# 🏗️ Architecture

```text
┌─────────────────────────────────────────────┐
│                 RedForge UI                 │
│                                             │
│  Dashboard • Discovery • AD • Findings     │
│  Attack Graph • Evidence • Reports          │
└──────────────────────┬──────────────────────┘
                       │
                       │ REST API / SSE
                       ▼
┌─────────────────────────────────────────────┐
│              Express.js Backend             │
│                                             │
│  Scope Guard                                │
│  Assessment Routes                          │
│  Task Manager                               │
│  Audit Logger                               │
│  Evidence Manager                           │
│  Persistence Layer                          │
└──────────────┬───────────────┬──────────────┘
               │               │
               ▼               ▼
       ┌──────────────┐  ┌───────────────┐
       │ Real Lab     │  │ Demo Engine   │
       │ Execution    │  │ Simulation    │
       └──────┬───────┘  └───────────────┘
              │
              ▼
┌─────────────────────────────────────────────┐
│              Authorized Lab                 │
│                                             │
│  Domain Controller                          │
│  Windows Clients                            │
│  Servers                                    │
│  SMB / LDAP / Kerberos Services             │
└─────────────────────────────────────────────┘
```

---

# 🛡️ Scope Guard

Scope enforcement is a core security component of RedForge.

All assessment operations are intended to pass through a centralized scope-validation layer before network activity or controlled execution occurs.

### Scope Guard responsibilities

* IPv4 address validation
* CIDR-based scope validation
* Excluded-host validation
* Centralized middleware enforcement
* Standardized out-of-scope responses
* Operator action logging
* Immutable scope-rejection audit events

Example rejection:

```text
TARGET_OUT_OF_SCOPE
```

The default laboratory network may be configured as:

```text
192.168.56.0/24
```

This is a **configuration example**, not a hard-coded operational limitation. Authorized environments can define their own assessment boundaries.

---

# 🔬 REAL LAB vs DEMO / SIMULATION

RedForge explicitly distinguishes between live assessment data and synthetic laboratory data.

| Mode                | Description                                                                    |
| ------------------- | ------------------------------------------------------------------------------ |
| `REAL LAB`          | Performs genuine authorized network probes or security-tool execution          |
| `DEMO / SIMULATION` | Uses synthetic or deterministic data without interacting with external systems |

Every security-sensitive module should expose its current execution mode.

Example:

```text
┌─────────────────────────────┐
│ HOST DISCOVERY              │
│                             │
│ MODE: REAL LAB              │
│ TARGET: 192.168.56.10       │
│ STATUS: COMPLETED           │
└─────────────────────────────┘
```

or:

```text
┌─────────────────────────────┐
│ HOST DISCOVERY              │
│                             │
│ MODE: DEMO / SIMULATION     │
│ DATASET: TRAINING-LAB       │
│ STATUS: COMPLETED           │
└─────────────────────────────┘
```

This prevents simulated findings from being misrepresented as observations from a real environment.

---

# 🧩 Modules

## 1. Scope & Boundary Management

Provides centralized authorization boundaries for assessment targets.

**Planned capabilities:**

* IPv4/CIDR validation
* Include/exclude rules
* Middleware enforcement
* Scope configuration
* Rejection logging
* Assessment boundary verification

---

## 2. Host Discovery

Discovers systems within the authorized laboratory network.

### Real Lab Mode

Potential discovery mechanisms include:

* ICMP reachability checks
* TCP connectivity checks
* Common Windows service ports
* Host metadata collection

Common Windows-related ports include:

```text
135   RPC
139   NetBIOS Session Service
445   SMB
```

### Demo Mode

Uses deterministic training-lab datasets without sending network traffic.

---

## 3. Port & Service Enumeration

RedForge supports controlled TCP service enumeration.

Capabilities include:

* TCP connectivity testing
* Port state detection
* Service identification
* Banner collection where available
* Optional system `nmap` integration
* Structured scan results
* Raw tool output preservation

Example:

```text
TARGET
192.168.56.10

PORT     STATE       SERVICE
53       OPEN        DNS
88       OPEN        Kerberos
135      OPEN        RPC
139      OPEN        NetBIOS
389      OPEN        LDAP
445      OPEN        SMB
464      OPEN        Kerberos Password
636      OPEN        LDAPS
```

---

# 🖥️ SMB Security Assessment

The SMB assessment module is designed to determine security characteristics observed during SMB negotiation.

Potential assessment data includes:

* SMB dialect
* SMB2/SMB3 support
* Signing configuration
* Signing-required status
* Negotiation metadata

Results should distinguish between:

```text
OBSERVED
INFERRED
UNKNOWN
```

rather than treating incomplete protocol information as definitive evidence.

---

# 📂 Active Directory & LDAP

RedForge provides an Active Directory assessment layer capable of connecting to an authorized Domain Controller.

Configuration can include:

```text
LDAP Host
LDAP Port
Base DN
Bind Username
Bind Password
TLS / LDAPS
Connection Timeout
```

Supported environments may use:

```text
LDAP   : 389
LDAPS  : 636
```

Sensitive directory attributes should be masked or minimized in the UI and stored evidence.

---

# 🕸️ Active Directory Attack Graph

The attack graph models relationships between Active Directory objects and security findings.

Possible node types:

```text
Users
Groups
Computers
Domain Controllers
Service Accounts
High-Value Targets
```

Relationships can represent concepts such as:

```text
MemberOf
AdminTo
CanRDP
CanPSRemote
HasSession
GenericAll
GenericWrite
WriteDACL
DCSync
```

The graph is intended to provide an explainable representation of potential attack paths rather than simply displaying disconnected findings.

---

# 🎫 Kerberos Security Assessment

RedForge includes controlled workflows for evaluating common Active Directory Kerberos security weaknesses.

Assessment areas include:

* AS-REP roasting exposure
* Service Principal Name discovery
* Kerberoasting exposure
* Account configuration analysis
* Controlled ticket-related testing

Sensitive ticket or credential material should be:

* Masked by default
* Stored only when required
* Associated with an assessment ID
* Integrity-protected
* Clearly labeled according to execution mode

---

# 🔐 Privilege Escalation & ACL Analysis

The platform separates security findings into distinct stages:

```text
DETECTED
   ↓
VALIDATED
   ↓
EXPLOITED
```

This prevents a theoretical attack path from being represented as a successfully exploited vulnerability.

Assessment areas may include:

* Active Directory ACLs
* Delegated privileges
* Group memberships
* Replication permissions
* Administrative relationships
* Privilege delegation weaknesses

---

# 🔄 DCSync Assessment

DCSync testing follows a controlled two-stage workflow.

```text
1. Replication Permission Assessment
              ↓
2. Operator-Confirmed Test
```

The assessment verifies relevant replication permissions before any controlled extraction test is considered.

Sensitive credential material is masked by default.

---

# ↔️ Lateral Movement

RedForge provides a controlled framework for evaluating lateral-movement scenarios such as:

* Pass-the-Hash
* WMI-based administration
* Windows remote management scenarios

Operations are intended to use:

```text
Scope Validation
      ↓
Authorization
      ↓
Task Creation
      ↓
Execution
      ↓
Telemetry
      ↓
Evidence
```

Real execution and simulation must remain explicitly distinguishable.

---

# ⚙️ Controlled Command Runner

RedForge avoids treating arbitrary terminal input as an unrestricted execution mechanism.

The planned execution architecture uses:

* Allowlisted tools
* Argument validation
* Structured command definitions
* Child-process isolation
* Execution timeouts
* Task identifiers
* State tracking
* stdout/stderr capture
* Scope validation

Example task lifecycle:

```text
QUEUED
  ↓
RUNNING
  ↓
COMPLETED
```

Failure state:

```text
FAILED
```

---

# 📡 Real-Time Telemetry

Long-running operations are represented as asynchronous tasks.

RedForge uses Server-Sent Events (SSE) for real-time task output.

Example:

```text
Client
  │
  │ POST /api/task
  ▼
Backend
  │
  ├── QUEUED
  ├── RUNNING
  │
  ├── stdout
  ├── stderr
  │
  └── COMPLETED
          │
          ▼
      SSE Stream
```

Example API:

```text
GET /api/tasks/stream
```

---

# 🧾 Evidence Vault

Security findings should be backed by reproducible evidence wherever possible.

Evidence metadata includes:

```text
Assessment ID
Artifact ID
Timestamp
Operator
MIME Type
Payload Size
SHA-256
Source
Execution Mode
```

Artifact integrity uses genuine cryptographic hashing:

```text
SHA-256(payload)
```

rather than pseudo-random identifiers.

Example:

```text
Artifact: smb-negotiation.json
Size:      4.8 KB
SHA-256:   <cryptographic digest>
Status:    VERIFIED
```

---

# 📋 Findings Management

RedForge provides a lifecycle for security findings.

```text
OPEN
  ↓
VALIDATED
  ↓
REMEDIATION
  ↓
REMEDIATED
```

Additional states may include:

```text
ACCEPTED
FALSE_POSITIVE
```

Findings can be associated with:

* Evidence
* Affected hosts
* Services
* Attack paths
* MITRE ATT&CK techniques
* Risk scoring
* Remediation guidance
* Assessment sessions

---

# 🎯 MITRE ATT&CK Mapping

Findings can be mapped to the MITRE ATT&CK framework.

Each mapping should contain:

```text
Technique
Tactic
Assessment Status
Observed Evidence
Affected Asset
Rationale
Remediation
```

Example:

```text
Technique:
T1003 — OS Credential Dumping

Tactic:
Credential Access

Status:
Validated

Evidence:
artifact-0042

Remediation:
Restrict credential access and review privileged
authentication paths.
```

---

# 🕵️ Audit Logging

Operator actions and security-relevant events are recorded in the audit layer.

Examples include:

```text
SCOPE_CHECK
SCAN_STARTED
SCAN_COMPLETED
TARGET_REJECTED
FINDING_CREATED
EVIDENCE_CREATED
COMMAND_EXECUTED
TASK_FAILED
CONFIG_CHANGED
```

Each event can contain:

```text
Timestamp
Operator
Action
Target
Assessment ID
Result
Execution Mode
```

Persistent storage prevents audit history from disappearing after a server restart.

---

# 🧪 Lab Health Center

RedForge can verify the local assessment environment before running lab operations.

Potential checks include:

```text
nmap
python3
ping
smbclient
```

Example:

```text
┌────────────────────────────────────┐
│ LAB HEALTH                         │
├────────────────────────────────────┤
│ nmap       ✓ Installed             │
│ python3    ✓ Installed             │
│ ping       ✓ Available             │
│ smbclient  ✓ Installed             │
│ permissions ✓ Verified             │
└────────────────────────────────────┘
```

Version information and execution availability can also be displayed.

---

# 💾 Persistence

Assessment state is designed to survive application restarts.

Example storage structure:

```text
data/
└── redforge-store.json
```

Persisted information may include:

```text
Targets
Findings
Evidence
Audit Logs
Assessment Sessions
Configuration
Task Metadata
```

The application can maintain an in-memory representation for fast access while synchronizing changes to persistent storage.

---

# 📊 Executive Reporting

RedForge generates structured penetration-testing reports containing:

* Executive summary
* Assessment scope
* Scope attestation
* Methodology
* Assets assessed
* Findings summary
* Severity distribution
* Evidence references
* MITRE ATT&CK mapping
* Attack-path analysis
* Remediation recommendations
* Assessment limitations
* REAL LAB / DEMO status

The goal is to ensure that reports clearly distinguish observed evidence from simulated or inferred information.

---

# 📁 Project Structure

A conceptual project structure:

```text
redforge/
│
├── src/
│   ├── components/
│   │   ├── HeaderScopeBar.tsx
│   │   ├── ScopeVerificationView.tsx
│   │   ├── HostDiscoveryView.tsx
│   │   ├── PortEnumerationView.tsx
│   │   ├── ActiveDirectoryView.tsx
│   │   ├── AttackGraphPreview.tsx
│   │   ├── CredentialsValidationView.tsx
│   │   ├── PrivilegeEscalationView.tsx
│   │   ├── LateralMovementView.tsx
│   │   ├── EvidenceVaultView.tsx
│   │   ├── AuditLogView.tsx
│   │   ├── FindingsSummaryWidget.tsx
│   │   ├── ExecutiveReportView.tsx
│   │   └── TerminalWidget.tsx
│   │
│   └── ...
│
├── server.ts
│
├── data/
│   └── redforge-store.json
│
├── routes/
│   ├── assessment/
│   ├── lateral/
│   ├── tasks/
│   └── ...
│
├── services/
│   ├── scopeGuard/
│   ├── discovery/
│   ├── enumeration/
│   ├── ldap/
│   ├── smb/
│   ├── taskRunner/
│   ├── evidence/
│   ├── audit/
│   └── persistence/
│
├── package.json
└── README.md
```

---

# 🔐 Security Architecture

RedForge follows a defense-in-depth approach.

```text
                  Incoming Request
                         │
                         ▼
                ┌─────────────────┐
                │ Authentication  │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ Scope Guard     │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ Authorization   │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ Task Validation │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ Controlled      │
                │ Execution       │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ Telemetry       │
                └────────┬────────┘
                         ▼
                ┌─────────────────┐
                │ Evidence +      │
                │ Audit Log       │
                └─────────────────┘
```

Important controls include:

* Centralized scope enforcement
* Explicit execution modes
* Input validation
* Command allowlisting
* Operator authorization
* Sensitive-data masking
* Cryptographic artifact integrity
* Persistent audit records
* Task state tracking

---

# 🧰 Technology Stack

| Layer              | Technology                             |
| ------------------ | -------------------------------------- |
| Frontend           | React / TypeScript                     |
| Backend            | Node.js / Express.js                   |
| API                | REST                                   |
| Real-Time Events   | Server-Sent Events                     |
| Networking         | Node.js networking APIs                |
| Directory Services | LDAP / LDAPS                           |
| Windows Services   | SMB / RPC / Kerberos                   |
| Security Tooling   | Optional Nmap / Impacket / SMB tooling |
| Persistence        | JSON / file-backed storage             |
| Integrity          | SHA-256                                |
| Visualization      | Interactive graph-based modeling       |
| Security Framework | MITRE ATT&CK                           |

---

# ⚙️ Operational Modes

RedForge supports two fundamental operating modes.

### REAL LAB

Used when RedForge is connected to an authorized laboratory environment.

```text
REAL LAB
```

Real network observations and tool outputs are collected.

### DEMO / SIMULATION

Used for:

* Demonstrations
* Development
* UI testing
* Training
* Offline presentations

```text
DEMO / SIMULATION
```

No claim should be made that simulated data represents an actual network observation.

---

# 🗺️ Development Roadmap

## Phase 1 — Security Foundation

* [ ] Bitwise IPv4/CIDR Scope Guard
* [ ] Excluded-target validation
* [ ] Centralized scope middleware
* [ ] Persistent audit logging
* [ ] Operator context
* [ ] Persistent state store

## Phase 2 — Real Network Telemetry

* [ ] TCP host discovery
* [ ] ICMP discovery
* [ ] TCP port scanner
* [ ] Service detection
* [ ] Nmap integration
* [ ] SMB negotiation probe
* [ ] Lab Health Center

## Phase 3 — Active Directory

* [ ] LDAP configuration
* [ ] LDAP connectivity
* [ ] Directory enumeration
* [ ] AD relationship extraction
* [ ] Interactive attack graph
* [ ] Kerberos assessment workflows

## Phase 4 — Controlled Validation

* [ ] Privilege/ACL validation
* [ ] DCSync permission assessment
* [ ] Controlled lateral movement
* [ ] Safe command runner
* [ ] Background task execution
* [ ] SSE telemetry

## Phase 5 — Evidence & Reporting

* [ ] Cryptographic artifact hashing
* [ ] Evidence metadata
* [ ] Finding lifecycle
* [ ] MITRE ATT&CK matrix
* [ ] Risk calculation
* [ ] Executive report generator
* [ ] Printable/PDF-ready reports

---

# 📈 Implementation Status

The current implementation contains a mixture of functional infrastructure, simulated laboratory data, and planned real-execution components.

| Area                 | Current State          |
| -------------------- | ---------------------- |
| Scope Guard          | 🟡 Partial             |
| Host Discovery       | 🟡 Partial / Simulated |
| Port Enumeration     | 🟡 Partial / Simulated |
| SMB Assessment       | 🟡 Partial / Simulated |
| LDAP / AD            | 🟡 Partial / Simulated |
| Attack Graph         | 🟡 Partial / Simulated |
| Kerberos Assessment  | 🟡 Partial / Simulated |
| Privilege Escalation | 🟡 Partial / Simulated |
| DCSync               | 🟡 Partial / Simulated |
| Lateral Movement     | 🔴 Mocked              |
| Evidence Vault       | 🟡 Partial             |
| Audit Logging        | 🟡 Partial             |
| MITRE Mapping        | 🟡 Partial             |
| Findings Engine      | 🟡 Partial             |
| Reporting            | 🟡 Partial             |
| Command Runner       | 🟡 Partial             |
| SSE Telemetry        | 🔴 Planned             |
| Lab Health Center    | 🔴 Planned             |
| Authentication       | 🔴 Planned             |
| Persistence          | 🟡 Partial             |
| REAL/DEMO Badging    | 🔴 Planned             |

---

# 🎓 Project Goals

RedForge is intended to demonstrate practical understanding of:

* Active Directory security
* Network reconnaissance
* Windows security protocols
* Authentication and authorization
* Attack-path analysis
* Security automation
* Secure command execution
* Evidence handling
* Security telemetry
* MITRE ATT&CK
* Penetration-testing methodology
* Security-focused application architecture

The project emphasizes **validation and observability**, rather than presenting simulated attack results as genuine compromises.

---

# ⚠️ Responsible Use

RedForge can interact with network infrastructure and security tooling when configured for real laboratory operation.

Use it only against:

* Systems you own
* Dedicated cybersecurity laboratories
* CTF environments
* Authorized penetration-testing targets
* Systems covered by explicit written authorization

Never use the platform to scan, exploit, authenticate against, or laterally move through systems without authorization.

---

# 📜 License

Choose a license appropriate for your intended distribution model.

For example:

```text
MIT License
```

or a more restrictive license if you want to limit redistribution or commercial use.

---

# 👨‍💻 Project

**RedForge — Active Directory Red-Team Laboratory**

A modular platform for:

```text
DISCOVER
    ↓
ENUMERATE
    ↓
ASSESS
    ↓
MODEL
    ↓
VALIDATE
    ↓
COLLECT EVIDENCE
    ↓
MAP
    ↓
REPORT
```

**Built for authorized cybersecurity research, hands-on laboratories, and security education.**
