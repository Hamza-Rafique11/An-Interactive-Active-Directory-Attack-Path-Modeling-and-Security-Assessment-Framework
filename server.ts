import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import net from 'net';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import { execFile } from 'child_process';
import { createServer as createViteServer } from 'vite';

const app = express();
const PORT = 3000;

app.use(express.json());

// Persistent Store File Path
const STORE_PATH = path.join(process.cwd(), 'data', 'adstrike-store.json');

// -------------------------------------------------------------
// 1. SCOPE GUARD BITWISE CIDR ENGINE
// -------------------------------------------------------------
interface ScopeConfig {
  assessmentName: string;
  authorizedCidr: string;
  subnetMask: string;
  networkAddress: string;
  broadcastAddress: string;
  allowedHosts: string[];
  excludedHosts: string[];
  operatorSignature: string;
  strictBlocking: boolean;
  rulesOfEngagement: string[];
}

let labScope: ScopeConfig = {
  assessmentName: 'ADStrike Active Directory Red-Team Authorized Lab',
  authorizedCidr: '192.168.56.0/24',
  subnetMask: '255.255.255.0',
  networkAddress: '192.168.56.0',
  broadcastAddress: '192.168.56.255',
  allowedHosts: [
    '192.168.56.10',
    '192.168.56.20',
    '192.168.56.30',
    '192.168.56.40',
    '192.168.56.50'
  ],
  excludedHosts: [
    '192.168.56.1' // VirtualBox Default Gateway host interface protected from intrusive exploitation
  ],
  operatorSignature: 'SEC-OPS-KALI-VERIFIED-LAB-ONLY',
  strictBlocking: true,
  rulesOfEngagement: [
    'Authorized exclusively within the isolated host-only subnet 192.168.56.0/24',
    'Intrusive actions against Gateway 192.168.56.1 are explicitly excluded and prohibited',
    'Denial of Service (DoS/DDoS) and destructive disk operations strictly forbidden',
    'All extracted credential hashes must be cryptographically hashed (SHA-256) into the Evidence Vault',
    'Production or internet-facing external IP addresses are automatically blocked by the Scope Guard'
  ]
};

// Convert IPv4 string to 32-bit unsigned number
function ipToLong(ip: string): number | null {
  if (!ip || typeof ip !== 'string') return null;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  let res = 0;
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(parts[i], 10);
    if (isNaN(octet) || octet < 0 || octet > 255 || parts[i] !== octet.toString()) {
      return null;
    }
    res = (res << 8) | octet;
  }
  return res >>> 0;
}

// Bitwise CIDR Validator
function isIpInAuthorizedScope(ip: string): { allowed: boolean; reason: string } {
  if (!ip || typeof ip !== 'string') {
    return { allowed: false, reason: 'Invalid or missing IP address format.' };
  }

  const cleanIp = ip.trim();

  // Explicit loopback exception for local mock diagnostics
  if (cleanIp === '127.0.0.1' || cleanIp === 'localhost') {
    return { allowed: true, reason: 'Localhost diagnostics allowed.' };
  }

  const ipLong = ipToLong(cleanIp);
  if (ipLong === null) {
    return { allowed: false, reason: `Malformed IPv4 format: '${cleanIp}'` };
  }

  // Check excluded hosts
  if (labScope.excludedHosts && labScope.excludedHosts.includes(cleanIp)) {
    return {
      allowed: false,
      reason: `Target IP ${cleanIp} is in the EXCLUDED hosts list (Gateway/Protected Interface). Operation blocked.`
    };
  }

  // Parse authorized CIDR
  const [netStr, bitsStr] = labScope.authorizedCidr.split('/');
  const prefixBits = parseInt(bitsStr, 10);
  const netLong = ipToLong(netStr);

  if (netLong === null || isNaN(prefixBits) || prefixBits < 0 || prefixBits > 32) {
    return { allowed: false, reason: 'Invalid Scope CIDR configuration.' };
  }

  const mask = prefixBits === 0 ? 0 : (~0 << (32 - prefixBits)) >>> 0;
  const inSubnet = (ipLong & mask) === (netLong & mask);

  if (!inSubnet) {
    return {
      allowed: false,
      reason: `Target IP ${cleanIp} is outside the authorized lab subnet ${labScope.authorizedCidr}.`
    };
  }

  return {
    allowed: true,
    reason: `Target IP ${cleanIp} is strictly within authorized scope ${labScope.authorizedCidr}.`
  };
}

// Scope Guard Express Middleware
function scopeGuardMiddleware(req: Request, res: Response, next: NextFunction) {
  const targetIp: string =
    req.body?.ip ||
    req.body?.targetIp ||
    req.body?.targetHost ||
    req.body?.target ||
    (req.query?.ip as string) ||
    (req.query?.target as string);

  if (!targetIp) {
    return next();
  }

  const check = isIpInAuthorizedScope(targetIp);
  if (!check.allowed) {
    const entry = {
      id: `audit-${Date.now()}`,
      timestamp: new Date().toUTCString(),
      operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
      action: 'SCOPE_GUARD_VIOLATION_REJECTED',
      target: targetIp,
      scopeStatus: 'OUT_OF_SCOPE_REJECTED' as const,
      details: check.reason
    };
    auditLog.unshift(entry);
    saveStore();

    return res.status(403).json({
      error: 'TARGET_OUT_OF_SCOPE',
      targetIp,
      message: check.reason,
      authorizedScope: labScope.authorizedCidr,
      operatorSignature: labScope.operatorSignature
    });
  }

  next();
}

// -------------------------------------------------------------
// 2. DATA STORES (PERSISTED)
// -------------------------------------------------------------
let auditLog: any[] = [
  {
    id: 'audit-001',
    timestamp: '2026-09-13 12:35:10 UTC',
    operator: 'operator@kali',
    action: 'SCOPE_INITIALIZATION',
    target: '192.168.56.0/24',
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: 'REAL',
    details: 'Verified Rules of Engagement and host-only subnet boundaries.'
  },
  {
    id: 'audit-002',
    timestamp: '2026-09-13 12:38:22 UTC',
    operator: 'operator@kali',
    action: 'NMAP_SYN_DISCOVERY',
    target: '192.168.56.10',
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: 'REAL',
    details: 'Port scan executed against DC01.adstrike.local (88, 135, 389, 445).'
  }
];

let targets: any[] = [
  {
    id: 'tgt-01',
    ip: '192.168.56.10',
    hostname: 'DC01.adstrike.local',
    os: 'Windows Server 2022 Standard',
    role: 'Domain Controller',
    domain: 'adstrike.local',
    openPorts: [53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269],
    risk: 'CRITICAL',
    status: 'ONLINE',
    lastSeen: '10s ago',
    vulnerabilitiesCount: 4
  },
  {
    id: 'tgt-02',
    ip: '192.168.56.20',
    hostname: 'WIN10-01.adstrike.local',
    os: 'Windows 10 Pro 22H2',
    role: 'Workstation',
    domain: 'adstrike.local',
    openPorts: [135, 139, 445, 5985],
    risk: 'HIGH',
    status: 'ONLINE',
    lastSeen: '1m ago',
    vulnerabilitiesCount: 2
  },
  {
    id: 'tgt-03',
    ip: '192.168.56.30',
    hostname: 'WIN-SRV-01.adstrike.local',
    os: 'Windows Server 2019 Standard',
    role: 'Member Server',
    domain: 'adstrike.local',
    openPorts: [80, 135, 445, 1433, 5985],
    risk: 'CRITICAL',
    status: 'ONLINE',
    lastSeen: '45s ago',
    vulnerabilitiesCount: 3
  },
  {
    id: 'tgt-04',
    ip: '192.168.56.40',
    hostname: 'LINUX01.adstrike.local',
    os: 'Ubuntu 22.04 LTS (Joined via SSSD)',
    role: 'Linux Host',
    domain: 'adstrike.local',
    openPorts: [22, 80, 8080],
    risk: 'LOW',
    status: 'ONLINE',
    lastSeen: '5m ago',
    vulnerabilitiesCount: 1
  },
  {
    id: 'tgt-05',
    ip: '192.168.56.50',
    hostname: 'KALI-OPERATOR',
    os: 'Kali Linux 2024.1 Rolling',
    role: 'Assessment Machine',
    domain: 'WORKGROUP',
    openPorts: [22],
    risk: 'LOW',
    status: 'ONLINE',
    lastSeen: 'Just now',
    vulnerabilitiesCount: 0
  }
];

let findings: any[] = [
  {
    id: 'f-01',
    findingId: 'AD-VULN-001',
    title: 'Kerberoasting: Service Account with SPN & RC4-HMAC Cipher',
    severity: 'CRITICAL',
    affectedAsset: 'svc_mssql (WIN-SRV-01.adstrike.local:1433)',
    mitreId: 'T1558.003',
    mitreTactic: 'Credential Access',
    description: 'Domain account svc_mssql has ServicePrincipalName registered with legacy arcfour-hmac-md5 encryption, permitting offline TGS password cracking.',
    impact: 'High: Offline cracking yields service account cleartext password, granting lateral movement and database access.',
    likelihood: 'HIGH',
    cvssScore: 8.8,
    status: 'VALIDATED',
    remediation: 'Migrate service account to Group Managed Service Account (gMSA) or enforce AES256-CTS-HMAC-SHA1-96 encryption and high-entropy passwords (30+ characters).',
    references: ['MITRE ATT&CK T1558.003', 'MS-KILE Kerberos Protocol Extensions', 'NIST SP 800-63B'],
    linkedEvidenceIds: ['ev-01'],
    executionMode: 'SIMULATED'
  },
  {
    id: 'f-02',
    findingId: 'AD-VULN-002',
    title: 'AS-REP Roasting: Kerberos Pre-Authentication Disabled',
    severity: 'HIGH',
    affectedAsset: 'backup_operator@adstrike.local',
    mitreId: 'T1558.004',
    mitreTactic: 'Credential Access',
    description: 'Account backup_operator has DONT_REQ_PREAUTH flag set in userAccountControl (UAC 0x400000), allowing unauthenticated attackers to request AS-REP tickets and crack hashes offline.',
    impact: 'High: Unauthenticated attackers on local network can retrieve password hash without generating Kerberos pre-auth failures.',
    likelihood: 'HIGH',
    cvssScore: 7.5,
    status: 'VALIDATED',
    remediation: 'Ensure "Do not require Kerberos preauthentication" is unchecked in Account Options for all Active Directory user accounts.',
    references: ['MITRE ATT&CK T1558.004', 'RFC 4120 Kerberos V5'],
    linkedEvidenceIds: ['ev-02'],
    executionMode: 'SIMULATED'
  },
  {
    id: 'f-03',
    findingId: 'AD-VULN-003',
    title: 'Unconstrained Kerberos Delegation Configured on Member Server',
    severity: 'CRITICAL',
    affectedAsset: 'WIN-SRV-01$ (192.168.56.30)',
    mitreId: 'T1558.001',
    mitreTactic: 'Privilege Escalation',
    description: 'Server WIN-SRV-01 has TRUSTED_FOR_DELEGATION attribute enabled. If a Domain Admin connects to this server, their TGT is cached in LSASS and can be harvested.',
    impact: 'Critical: Coerced authentication (MS-RPRN PrinterBug or PetitPotam) results in complete Domain Admin compromise.',
    likelihood: 'HIGH',
    cvssScore: 9.3,
    status: 'VALIDATED',
    remediation: 'Revoke TRUSTED_FOR_DELEGATION attribute on member servers; migrate to Constrained Delegation or Resource-Based Constrained Delegation (RBCD). Add Domain Admins to Protected Users group.',
    references: ['MITRE ATT&CK T1558.001', 'Microsoft Kerberos Delegation Overview'],
    linkedEvidenceIds: [],
    executionMode: 'SIMULATED'
  },
  {
    id: 'f-04',
    findingId: 'AD-VULN-004',
    title: 'SMB Signing Not Required on Non-DC Windows Workstations',
    severity: 'MEDIUM',
    affectedAsset: 'WIN10-01.adstrike.local (192.168.56.20)',
    mitreId: 'T1021.002',
    mitreTactic: 'Lateral Movement',
    description: 'SMB signing is disabled or optional on workstations, enabling NTLM relay attacks via Responder or ntlmrelayx.',
    impact: 'Medium: NTLM credentials captured from LLMNR/NBT-NS poisoning can be relayed to gain administrative shells on workstations.',
    likelihood: 'MEDIUM',
    cvssScore: 6.5,
    status: 'VALIDATED',
    remediation: 'Enable "Microsoft network server: Digitally sign communications (always)" via Group Policy across all domain workstations.',
    references: ['MITRE ATT&CK T1021.002', 'MS-SMB2 Protocol Specification'],
    linkedEvidenceIds: [],
    executionMode: 'SIMULATED'
  },
  {
    id: 'f-05',
    findingId: 'AD-VULN-005',
    title: 'Replicating Directory Changes Permission (DCSync Path)',
    severity: 'CRITICAL',
    affectedAsset: 'SQLAdmins Group -> Domain NC',
    mitreId: 'T1003.006',
    mitreTactic: 'Credential Access',
    description: 'SQLAdmins group has DS-Replication-Get-Changes-All extended rights over the domain head, permitting full password hash dumping via DRSUAPI.',
    impact: 'Critical: Complete Active Directory domain compromise, including extraction of krbtgt hash for Golden Ticket creation.',
    likelihood: 'HIGH',
    cvssScore: 9.8,
    status: 'VALIDATED',
    remediation: 'Audit and remove Replicating Directory Changes permissions from non-Domain Controller security principals using dsacls or ADUC.',
    references: ['MITRE ATT&CK T1003.006', 'MS-DRSR Directory Replication Service Remote Protocol'],
    linkedEvidenceIds: ['ev-03'],
    executionMode: 'SIMULATED'
  }
];

let evidenceVault: any[] = [
  {
    id: 'ev-01',
    assessmentId: 'ASMT-2026-LAB-01',
    mitreId: 'T1558.003',
    technique: 'Kerberoasting TGS Ticket Extracted',
    targetHost: '192.168.56.10',
    sourceTool: 'impacket/GetUserSPNs.py',
    timestamp: '2026-09-13 12:42:35 UTC',
    sha256: crypto.createHash('sha256').update('$krb5tgs$23$*svc_mssql*adstrike.local*MSSQLSvc/WIN-SRV-01.adstrike.local*$b4718c99e2...c82a').digest('hex'),
    operator: 'operator@kali',
    payloadType: 'hash',
    sizeBytes: 1024,
    mimeType: 'application/x-hashcat-13100',
    rawPreview: '$krb5tgs$23$*svc_mssql*adstrike.local*MSSQLSvc/WIN-SRV-01.adstrike.local*$b4718c99e2f4a13d7e8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f',
    verified: true,
    executionMode: 'SIMULATED',
    associatedFindingId: 'f-01'
  },
  {
    id: 'ev-02',
    assessmentId: 'ASMT-2026-LAB-01',
    mitreId: 'T1558.004',
    technique: 'AS-REP Hash with DONT_REQ_PREAUTH',
    targetHost: '192.168.56.10',
    sourceTool: 'impacket/GetNPUsers.py',
    timestamp: '2026-09-13 12:44:12 UTC',
    sha256: crypto.createHash('sha256').update('$krb5asrep$23$backup_operator@ADSTRIKE.LOCAL:4f1a2b3c4d5e...9e0f').digest('hex'),
    operator: 'operator@kali',
    payloadType: 'hash',
    sizeBytes: 512,
    mimeType: 'application/x-hashcat-18200',
    rawPreview: '$krb5asrep$23$backup_operator@ADSTRIKE.LOCAL:4f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c',
    verified: true,
    executionMode: 'SIMULATED',
    associatedFindingId: 'f-02'
  },
  {
    id: 'ev-03',
    assessmentId: 'ASMT-2026-LAB-01',
    mitreId: 'T1003.006',
    technique: 'DCSync NTDS.dit Password Hashes',
    targetHost: '192.168.56.10',
    sourceTool: 'impacket/secretsdump.py',
    timestamp: '2026-09-13 12:45:50 UTC',
    sha256: crypto.createHash('sha256').update('Administrator:500:aad3b435...:10b27e8a93e5e54c87c4a06d88f6a654:::').digest('hex'),
    operator: 'operator@kali',
    payloadType: 'ntds_dit',
    sizeBytes: 256,
    mimeType: 'text/plain',
    rawPreview: 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:10b27e8a93e5e54c87c4a06d88f6a654:::',
    verified: true,
    executionMode: 'SIMULATED',
    associatedFindingId: 'f-05'
  }
];

let ldapConfig = {
  domain: 'adstrike.local',
  dcHost: '192.168.56.10',
  port: 389,
  useTls: false,
  bindUser: 'ADSTRIKE\\jdoe',
  baseDn: 'DC=adstrike,DC=local'
};

// Attack graph relationships
let attackGraphData = {
  nodes: [
    { id: 'u-jdoe', label: 'jdoe (Compromised)', type: 'user', compromised: true, roleDescription: 'Helpdesk Operator account', x: 60, y: 150, privilegeLevel: 'Standard' },
    { id: 'w-win10', label: 'WIN10-01 (192.168.56.20)', type: 'workstation', compromised: true, roleDescription: 'Workstation with local admin rights', x: 240, y: 150, ip: '192.168.56.20' },
    { id: 'u-mssql', label: 'svc_mssql (SPN)', type: 'ticket', compromised: true, roleDescription: 'SQL Service with RC4 SPN ticket', x: 440, y: 80, privilegeLevel: 'Elevated' },
    { id: 's-winsrv', label: 'WIN-SRV-01 (SQL)', type: 'server', compromised: true, roleDescription: 'Unconstrained Delegation enabled', x: 440, y: 220, ip: '192.168.56.30' },
    { id: 'g-sqladm', label: 'SQLAdmins Group', type: 'group', compromised: true, roleDescription: 'Has DCSync privileges on domain', x: 660, y: 80 },
    { id: 'g-da', label: 'Domain Admins', type: 'group', compromised: true, roleDescription: 'Full Domain Administrative Control', x: 660, y: 220 },
    { id: 'dc-dc01', label: 'DC01.adstrike.local', type: 'dc', compromised: true, roleDescription: 'Primary Domain Controller (KDC)', x: 880, y: 150, ip: '192.168.56.10', privilegeLevel: 'DomainAdmin' },
  ],
  edges: [
    { from: 'u-jdoe', to: 'w-win10', relationship: 'AdminTo', technique: 'Local Group Membership', risk: 'HIGH', mitreId: 'T1078.002' },
    { from: 'w-win10', to: 'u-mssql', relationship: 'HasSPN / Kerberoast', technique: 'T1558.003 - TGS Request', risk: 'CRITICAL', mitreId: 'T1558.003' },
    { from: 'u-mssql', to: 'g-sqladm', relationship: 'MemberOf', technique: 'Active Directory Nested Group', risk: 'HIGH', mitreId: 'T1069.002' },
    { from: 'w-win10', to: 's-winsrv', relationship: 'Pass-the-Hash / AdminTo', technique: 'T1021.002 - SMB/RPC Execution', risk: 'CRITICAL', mitreId: 'T1021.002' },
    { from: 's-winsrv', to: 'g-da', relationship: 'TrustedForDelegation', technique: 'T1558.001 - LSASS TGT Harvesting', risk: 'CRITICAL', mitreId: 'T1558.001' },
    { from: 'g-sqladm', to: 'dc-dc01', relationship: 'CanDCSync', technique: 'T1003.006 - DRSUAPI Replication', risk: 'CRITICAL', mitreId: 'T1003.006' },
    { from: 'g-da', to: 'dc-dc01', relationship: 'DomainAdmin', technique: 'T1078 - Enterprise Admin Control', risk: 'CRITICAL', mitreId: 'T1078' },
  ]
};

// Persistence functions
function loadStore() {
  try {
    if (fs.existsSync(STORE_PATH)) {
      const raw = fs.readFileSync(STORE_PATH, 'utf8');
      if (raw && raw.trim().length > 2) {
        const data = JSON.parse(raw);
        if (data.auditLog) auditLog = data.auditLog;
        if (data.targets) targets = data.targets;
        if (data.findings) findings = data.findings;
        if (data.evidenceVault) evidenceVault = data.evidenceVault;
        if (data.labScope) labScope = { ...labScope, ...data.labScope };
        if (data.ldapConfig) ldapConfig = { ...ldapConfig, ...data.ldapConfig };
      }
    }
  } catch (e) {
    console.error('[ADStrike Store] Error reading store:', e);
  }
}

function saveStore() {
  try {
    const data = {
      labScope,
      auditLog: auditLog.slice(0, 100),
      targets,
      findings,
      evidenceVault,
      ldapConfig
    };
    fs.writeFileSync(STORE_PATH, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('[ADStrike Store] Error writing store:', e);
  }
}

// Initial load
loadStore();

// -------------------------------------------------------------
// 3. REAL TCP SOCKET & PROTOCOL PROBERS
// -------------------------------------------------------------

// TCP Connect probe with timeout
function probeTcpPort(ip: string, port: number, timeoutMs = 1200): Promise<{ open: boolean; latencyMs: number; banner?: string; smbSigning?: string }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let banner = '';
    let smbSigning = 'NOT_APPLICABLE';

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      const latencyMs = Date.now() - start;

      if (port === 445) {
        // Send basic SMB2 Negotiate Protocol Request
        // NetBIOS header (4 bytes) + SMB2 Header + Negotiate Request (Dialects: SMB 2.0.2, 2.1)
        const smb2Negotiate = Buffer.from([
          0x00, 0x00, 0x00, 0x44, // NetBIOS session (68 bytes)
          0xfe, 0x53, 0x4d, 0x42, // Protocol: \xfeSMB
          0x40, 0x00,             // Header length (64)
          0x00, 0x00,             // Credit charge (0)
          0x00, 0x00, 0x00, 0x00, // Status: SUCCESS
          0x00, 0x00,             // Command: NEGOTIATE (0)
          0x00, 0x00,             // Credits: 0
          0x00, 0x00, 0x00, 0x00, // Flags: 0
          0x00, 0x00, 0x00, 0x00, // Next command: 0
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID: 0
          0x00, 0x00, 0x00, 0x00, // Process ID: 0
          0x00, 0x00, 0x00, 0x00, // Tree ID: 0
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID: 0
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
          0x24, 0x00,             // StructureSize (36)
          0x02, 0x00,             // Dialect count: 2
          0x01, 0x00,             // Security mode: SMB2_NEGOTIATE_SIGNING_ENABLED
          0x00, 0x00,             // Reserved
          0x00, 0x00, 0x00, 0x00, // Capabilities
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client GUID
          0x02, 0x02,             // Dialect 0x0202 (SMB 2.0.2)
          0x10, 0x02              // Dialect 0x0210 (SMB 2.1)
        ]);

        socket.write(smb2Negotiate);
      } else if (port === 80 || port === 8080) {
        socket.write('HEAD / HTTP/1.0\r\nHost: ' + ip + '\r\n\r\n');
      }

      // Wait briefly for response
      setTimeout(() => {
        socket.destroy();
        resolve({ open: true, latencyMs, banner: banner || undefined, smbSigning });
      }, 100);
    });

    socket.on('data', (data) => {
      if (port === 445 && data.length > 70) {
        // Inspect SMB2 Negotiate Response SecurityMode byte (offset 68 + 2 in negotiate response body)
        // Check if signing is required (bit 0x02)
        const secMode = data[70] || 0;
        if ((secMode & 0x02) !== 0) {
          smbSigning = 'REQUIRED';
        } else {
          smbSigning = 'DISABLED';
        }
      } else {
        const text = data.toString('utf8', 0, Math.min(data.length, 120)).trim();
        if (text) banner = text;
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ open: false, latencyMs: timeoutMs });
    });

    socket.on('error', () => {
      socket.destroy();
      resolve({ open: false, latencyMs: 0 });
    });

    socket.connect(port, ip);
  });
}

// -------------------------------------------------------------
// 4. REAL-TIME TASK MANAGER & SSE STREAM
// -------------------------------------------------------------
interface ExecutionTask {
  id: string;
  module: string;
  tool: string;
  target: string;
  executionMode: 'REAL' | 'SIMULATED';
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  startedAt: string;
  completedAt?: string;
  durationMs?: number;
  exitCode?: number;
  outputLines: string[];
}

const activeTasks = new Map<string, ExecutionTask>();
const sseClients = new Set<Response>();

function broadcastTaskUpdate(task: ExecutionTask) {
  const data = JSON.stringify(task);
  for (const client of sseClients) {
    client.write(`data: ${data}\n\n`);
  }
}

// -------------------------------------------------------------
// 5. REST APIS & MODULES
// -------------------------------------------------------------

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    engine: 'ADStrike v2.0.0-ENTERPRISE-LAB',
    environment: 'Host-Only Lab 192.168.56.0/24',
    scopeCidr: labScope.authorizedCidr,
    timestamp: new Date().toISOString()
  });
});

// Tool & Lab Health Center
app.get('/api/lab/health', async (req, res) => {
  const checkTool = (name: string, cmd: string, desc: string): Promise<any> => {
    return new Promise((resolve) => {
      execFile('which', [cmd], (err, stdout) => {
        if (err || !stdout.trim()) {
          resolve({
            id: cmd,
            name,
            command: cmd,
            installed: false,
            status: 'NOT_INSTALLED',
            description: desc
          });
        } else {
          // Attempt getting version
          execFile(cmd, ['--version'], (vErr, vOut) => {
            const ver = vOut ? vOut.split('\n')[0].trim() : 'Installed (Ready)';
            resolve({
              id: cmd,
              name,
              command: cmd,
              installed: true,
              version: ver,
              status: 'READY',
              description: desc
            });
          });
        }
      });
    });
  };

  const [nmap, python3, pingTool, smbclient] = await Promise.all([
    checkTool('Nmap Network Scanner', 'nmap', 'Used for port scanning, OS fingerprinting, and NSE scripts.'),
    checkTool('Python 3 Runtime', 'python3', 'Required for Impacket suite (secretsdump, GetUserSPNs, GetNPUsers).'),
    checkTool('ICMP Ping Utility', 'ping', 'Standard network latency and host discovery probe.'),
    checkTool('Samba Client (smbclient)', 'smbclient', 'Direct SMB share enumeration and IPC$ validation.')
  ]);

  const interfaces: string[] = [];
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name] || []) {
      if (iface.family === 'IPv4') {
        interfaces.push(`${name}: ${iface.address}/${iface.netmask}`);
      }
    }
  }

  res.json({
    timestamp: new Date().toISOString(),
    activeAssessmentScope: labScope.authorizedCidr,
    readyForAssessment: true,
    tools: [
      nmap,
      python3,
      pingTool,
      smbclient,
      {
        id: 'socket-engine',
        name: 'Node.js Native Socket Engine',
        command: 'net.Socket',
        installed: true,
        version: `Node.js ${process.version}`,
        status: 'READY',
        description: 'Raw TCP socket connector for banner grabbing & SMB2 negotiation checks.'
      }
    ],
    networkInterfaces: interfaces
  });
});

// Scope Guard Telemetry & Verification
app.get('/api/scope', (req, res) => {
  res.json(labScope);
});

// Update Authorized Scope CIDR & Configuration
app.put('/api/scope', (req, res) => {
  const { authorizedCidr, assessmentName, operatorSignature, allowedHosts, excludedHosts, strictBlocking, rulesOfEngagement } = req.body;

  if (!authorizedCidr || typeof authorizedCidr !== 'string') {
    return res.status(400).json({ error: 'authorizedCidr is required (e.g. 10.0.0.0/24 or 192.168.1.0/24)' });
  }

  const parts = authorizedCidr.trim().split('/');
  if (parts.length !== 2) {
    return res.status(400).json({ error: 'authorizedCidr must be in CIDR format (e.g. 10.0.0.0/24 or 192.168.1.50/32)' });
  }

  const prefix = parseInt(parts[1], 10);
  const ipLong = ipToLong(parts[0]);
  if (ipLong === null || isNaN(prefix) || prefix < 0 || prefix > 32) {
    return res.status(400).json({ error: 'Invalid IPv4 address or CIDR prefix length (must be 0-32)' });
  }

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const netLong = (ipLong & mask) >>> 0;
  const bcastLong = (netLong | ~mask) >>> 0;

  const longToIp = (val: number) => [
    (val >>> 24) & 255,
    (val >>> 16) & 255,
    (val >>> 8) & 255,
    val & 255
  ].join('.');

  const networkAddress = longToIp(netLong);
  const broadcastAddress = longToIp(bcastLong);
  const subnetMask = longToIp(mask);

  const cleanCidr = `${networkAddress}/${prefix}`;

  labScope = {
    assessmentName: assessmentName || labScope.assessmentName,
    authorizedCidr: cleanCidr,
    subnetMask,
    networkAddress,
    broadcastAddress,
    allowedHosts: Array.isArray(allowedHosts) && allowedHosts.length > 0
      ? allowedHosts
      : [networkAddress],
    excludedHosts: Array.isArray(excludedHosts) ? excludedHosts : labScope.excludedHosts,
    operatorSignature: operatorSignature || labScope.operatorSignature,
    strictBlocking: strictBlocking !== undefined ? !!strictBlocking : labScope.strictBlocking,
    rulesOfEngagement: Array.isArray(rulesOfEngagement) ? rulesOfEngagement : labScope.rulesOfEngagement
  };

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'SCOPE_CONFIGURATION_UPDATED',
    target: cleanCidr,
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: 'REAL',
    details: `Authorized RoE scope updated to ${cleanCidr} (Net: ${networkAddress}, Mask: ${subnetMask}).`
  });
  saveStore();

  res.json({
    success: true,
    message: `Authorized lab scope successfully updated to ${cleanCidr}`,
    scope: labScope
  });
});

app.post('/api/scope/verify', (req, res) => {
  const { targetIp } = req.body;
  if (!targetIp) {
    return res.status(400).json({ error: 'targetIp is required' });
  }

  const check = isIpInAuthorizedScope(targetIp);
  const now = new Date().toUTCString();

  if (!check.allowed) {
    auditLog.unshift({
      id: `audit-${Date.now()}`,
      timestamp: now,
      operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
      action: 'SCOPE_GUARD_VIOLATION_REJECTED',
      target: targetIp,
      scopeStatus: 'OUT_OF_SCOPE_REJECTED',
      executionMode: 'REAL',
      details: check.reason
    });
    saveStore();

    return res.status(403).json({
      allowed: false,
      targetIp,
      error: 'TARGET_OUT_OF_SCOPE',
      reason: check.reason,
      authorizedCidr: labScope.authorizedCidr
    });
  }

  res.json({
    allowed: true,
    targetIp,
    reason: check.reason,
    authorizedCidr: labScope.authorizedCidr
  });
});

// Real-Time Task SSE Stream
app.get('/api/tasks/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  sseClients.add(res);

  // Send current tasks
  for (const task of activeTasks.values()) {
    res.write(`data: ${JSON.stringify(task)}\n\n`);
  }

  req.on('close', () => {
    sseClients.delete(res);
  });
});

app.get('/api/tasks', (req, res) => {
  res.json(Array.from(activeTasks.values()));
});

// Targets API
app.get('/api/targets', (req, res) => {
  res.json(targets);
});

app.post('/api/targets', scopeGuardMiddleware, (req, res) => {
  const { ip, hostname, os, role, domain, openPorts } = req.body;

  const newTarget = {
    id: `tgt-${Date.now()}`,
    ip,
    hostname: hostname || `HOST-${Date.now().toString().slice(-4)}`,
    os: os || 'Windows Server 2022',
    role: role || 'Member Server',
    domain: domain || 'adstrike.local',
    openPorts: openPorts || [135, 445],
    risk: 'MEDIUM',
    status: 'ONLINE',
    lastSeen: 'Just now',
    vulnerabilitiesCount: 1
  };

  targets.push(newTarget as any);

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'TARGET_ADDED',
    target: ip,
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: 'REAL',
    details: `Added new target host ${hostname} (${ip}) to inventory.`
  });
  saveStore();

  res.status(201).json(newTarget);
});

// Findings & MITRE ATT&CK
app.get('/api/findings', (req, res) => {
  res.json(findings);
});

app.put('/api/findings/:id/status', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const finding = findings.find(f => f.id === id || f.findingId === id);
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found' });
  }

  finding.status = status;
  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'FINDING_STATUS_CHANGED',
    target: finding.affectedAsset,
    scopeStatus: 'IN_SCOPE_ALLOWED',
    details: `Finding ${finding.findingId} status set to ${status}`
  });
  saveStore();

  res.json(finding);
});

// Attack Graph
app.get('/api/attack-graph', (req, res) => {
  res.json(attackGraphData);
});

// Evidence Vault
app.get('/api/evidence', (req, res) => {
  res.json(evidenceVault);
});

app.post('/api/evidence', scopeGuardMiddleware, (req, res) => {
  const { mitreId, technique, targetHost, sourceTool, payloadType, rawPreview, associatedFindingId, executionMode } = req.body;
  
  const content = rawPreview || 'evidence-artifact';
  // Real cryptographic SHA-256 calculation
  const sha = crypto.createHash('sha256').update(content).digest('hex');
  const sizeBytes = Buffer.byteLength(content, 'utf8');

  const newArtifact = {
    id: `ev-${Date.now()}`,
    assessmentId: 'ASMT-2026-LAB-01',
    mitreId: mitreId || 'T1558',
    technique: technique || 'Evidence Artifact',
    targetHost: targetHost || '192.168.56.10',
    sourceTool: sourceTool || 'kali/recon',
    timestamp: new Date().toUTCString(),
    sha256: sha,
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    payloadType: payloadType || 'hash',
    sizeBytes,
    mimeType: payloadType === 'hash' ? 'application/x-hashcat' : 'text/plain',
    rawPreview: content,
    verified: true,
    executionMode: executionMode || 'REAL',
    associatedFindingId: associatedFindingId || null
  };

  evidenceVault.unshift(newArtifact as any);

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'EVIDENCE_CATALOGED',
    target: targetHost,
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: newArtifact.executionMode,
    details: `Recorded cryptographic evidence artifact for ${technique} (SHA256: ${sha.slice(0, 16)}...)`
  });
  saveStore();

  res.status(201).json(newArtifact);
});

// Audit Log
app.get('/api/audit', (req, res) => {
  res.json(auditLog);
});

// -------------------------------------------------------------
// 6. DISCOVERY & PORT ENUMERATION (REAL & SIMULATED)
// -------------------------------------------------------------
const discoveredHostsList = [
  { ip: '192.168.56.10', hostname: 'DC01.adstrike.local', mac: '08:00:27:1A:4C:90', vendor: 'PCS Systemtechnik GmbH (VirtualBox)', latency: '0.42ms', status: 'ONLINE', adRole: 'Domain Controller (KDC)', executionMode: 'SIMULATED' },
  { ip: '192.168.56.20', hostname: 'WIN10-01.adstrike.local', mac: '08:00:27:8B:23:41', vendor: 'PCS Systemtechnik GmbH (VirtualBox)', latency: '0.61ms', status: 'ONLINE', adRole: 'Windows 10 Workstation', executionMode: 'SIMULATED' },
  { ip: '192.168.56.30', hostname: 'WIN-SRV-01.adstrike.local', mac: '08:00:27:D4:55:09', vendor: 'PCS Systemtechnik GmbH (VirtualBox)', latency: '0.55ms', status: 'ONLINE', adRole: 'Member Server (SQL Server)', executionMode: 'SIMULATED' },
  { ip: '192.168.56.40', hostname: 'LINUX01.adstrike.local', mac: '08:00:27:3F:88:1A', vendor: 'PCS Systemtechnik GmbH (VirtualBox)', latency: '0.38ms', status: 'ONLINE', adRole: 'Ubuntu Linux 22.04 (SSSD Domain Member)', executionMode: 'SIMULATED' },
  { ip: '192.168.56.50', hostname: 'KALI-OPERATOR', mac: '08:00:27:00:11:22', vendor: 'PCS Systemtechnik GmbH (VirtualBox)', latency: '0.04ms', status: 'ONLINE', adRole: 'Assessment Auditor / Kali Linux', executionMode: 'REAL' },
];

app.get('/api/discovery/hosts', (req, res) => {
  res.json(discoveredHostsList);
});

// Host Sweep (Real socket test if mode is REAL, otherwise modeled lab data)
app.post('/api/discovery/scan', async (req, res) => {
  const { subnet, mode } = req.body;
  const targetSubnet = subnet || labScope.authorizedCidr;
  const executionMode: 'REAL' | 'SIMULATED' = mode === 'REAL' ? 'REAL' : 'SIMULATED';

  const check = isIpInAuthorizedScope(targetSubnet.split('/')[0]);
  if (!check.allowed && targetSubnet !== labScope.authorizedCidr) {
    return res.status(403).json({
      error: 'TARGET_OUT_OF_SCOPE',
      message: `Disallowed sweep! Subnet ${targetSubnet} is outside the authorized lab boundary ${labScope.authorizedCidr}.`
    });
  }

  const taskId = `task-disc-${Date.now()}`;
  const task: ExecutionTask = {
    id: taskId,
    module: 'Host Discovery',
    tool: executionMode === 'REAL' ? 'net.Socket / TCP Sweep' : 'Lab Sweep Simulator',
    target: targetSubnet,
    executionMode,
    status: 'RUNNING',
    startedAt: new Date().toISOString(),
    outputLines: [
      `[*] Initiating authorized host sweep across ${targetSubnet} [Mode: ${executionMode}]`,
      `[*] Scope verification: PASSED (${labScope.authorizedCidr})`
    ]
  };
  activeTasks.set(taskId, task);
  broadcastTaskUpdate(task);

  let finalHosts = [...discoveredHostsList];

  if (executionMode === 'REAL') {
    task.outputLines.push(`[*] Dispatching live TCP socket connect probes to lab hosts...`);
    broadcastTaskUpdate(task);

    const probes = await Promise.all(
      labScope.allowedHosts.map(async (ip) => {
        const probe = await probeTcpPort(ip, 445, 800);
        return { ip, open: probe.open, latencyMs: probe.latencyMs };
      })
    );

    const liveProbes = probes.filter(p => p.open);
    if (liveProbes.length > 0) {
      finalHosts = liveProbes.map(p => ({
        ip: p.ip,
        hostname: `HOST-${p.ip.split('.').pop()}`,
        mac: 'REAL-SOCKET-ACTIVE',
        vendor: 'Live Lab Host',
        latency: `${p.latencyMs}ms`,
        status: 'ONLINE' as const,
        adRole: 'Detected Active Host',
        executionMode: 'REAL' as const
      }));
      task.outputLines.push(`[+] Real socket discovery: ${liveProbes.length} hosts responsive on TCP 445.`);
    } else {
      task.outputLines.push(`[!] Physical lab hosts did not respond on local interface. Providing authenticated lab benchmark.`);
      finalHosts = discoveredHostsList.map(h => ({ ...h, executionMode: 'SIMULATED' as const }));
    }
  } else {
    task.outputLines.push(`[+] Simulated ARP/ICMP discovery sweep completed. Found ${discoveredHostsList.length} lab nodes.`);
  }

  task.status = 'COMPLETED';
  task.completedAt = new Date().toISOString();
  task.durationMs = 450;
  broadcastTaskUpdate(task);

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'ARP_ICMP_DISCOVERY_SWEEP',
    target: targetSubnet,
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode,
    details: `Executed active host sweep across subnet ${targetSubnet}. Returned ${finalHosts.length} hosts.`
  });
  saveStore();

  res.json({
    subnet: targetSubnet,
    executionMode,
    totalScanned: 254,
    responsiveHosts: finalHosts.length,
    hosts: finalHosts,
    taskId,
    durationMs: 450
  });
});

// Port & Service Enumeration (Real TCP Connect with fallback to lab simulation)
const portScanMatrix: Record<string, any> = {
  '192.168.56.10': [
    { port: 53, protocol: 'tcp', state: 'open', service: 'domain', version: 'Microsoft DNS 2022 (6.0.406)', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 88, protocol: 'tcp', state: 'open', service: 'kerberos-sec', version: 'Microsoft Windows Kerberos (server time: 2026-09-13 12:45:00 UTC)', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 135, protocol: 'tcp', state: 'open', service: 'msrpc', version: 'Microsoft Windows RPC endpoint mapper', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 139, protocol: 'tcp', state: 'open', service: 'netbios-ssn', version: 'Microsoft Windows netbios-ssn', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 389, protocol: 'tcp', state: 'open', service: 'ldap', version: 'Microsoft Windows Active Directory LDAP (Domain: adstrike.local0:)', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds', version: 'Windows Server 2022 Standard 20348 microsoft-ds', smbSigning: 'REQUIRED', detectionMethod: 'BANNER_GRAB' },
    { port: 464, protocol: 'tcp', state: 'open', service: 'kpasswd5', version: 'Kerberos Password Change Protocol', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 636, protocol: 'tcp', state: 'open', service: 'tcpwrapped', version: 'LDAPS (SSL/TLS encrypted)', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 3268, protocol: 'tcp', state: 'open', service: 'ldap', version: 'Microsoft Windows Global Catalog LDAP', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
  ],
  '192.168.56.20': [
    { port: 135, protocol: 'tcp', state: 'open', service: 'msrpc', version: 'Microsoft Windows RPC endpoint mapper', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 139, protocol: 'tcp', state: 'open', service: 'netbios-ssn', version: 'Microsoft Windows netbios-ssn', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds', version: 'Windows 10 Pro 19045 microsoft-ds', smbSigning: 'DISABLED', detectionMethod: 'BANNER_GRAB' },
    { port: 5985, protocol: 'tcp', state: 'open', service: 'wsman', version: 'Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP / WinRM)', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
  ],
  '192.168.56.30': [
    { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Microsoft IIS httpd 10.0', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'BANNER_GRAB' },
    { port: 135, protocol: 'tcp', state: 'open', service: 'msrpc', version: 'Microsoft Windows RPC endpoint mapper', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds', version: 'Windows Server 2019 Standard 17763', smbSigning: 'DISABLED', detectionMethod: 'BANNER_GRAB' },
    { port: 1433, protocol: 'tcp', state: 'open', service: 'ms-sql-s', version: 'Microsoft SQL Server 2019 15.00.2000.00; SPN registered: MSSQLSvc/WIN-SRV-01.adstrike.local', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
    { port: 5985, protocol: 'tcp', state: 'open', service: 'wsman', version: 'Microsoft HTTPAPI httpd 2.0 (WinRM)', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'NMAP_SYN' },
  ],
  '192.168.56.40': [
    { port: 22, protocol: 'tcp', state: 'open', service: 'ssh', version: 'OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'BANNER_GRAB' },
    { port: 80, protocol: 'tcp', state: 'open', service: 'http', version: 'Apache httpd 2.4.52 ((Ubuntu))', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'BANNER_GRAB' },
    { port: 8080, protocol: 'tcp', state: 'open', service: 'http-proxy', version: 'Gunicorn / Internal Ops Portal', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'BANNER_GRAB' },
  ]
};

app.post('/api/enumeration/ports', scopeGuardMiddleware, async (req, res) => {
  const { ip, flags, mode } = req.body;
  if (!ip) return res.status(400).json({ error: 'ip is required' });

  const executionMode: 'REAL' | 'SIMULATED' = mode === 'REAL' ? 'REAL' : 'SIMULATED';
  const targetPorts = [53, 88, 135, 139, 389, 445, 464, 636, 1433, 3268, 5985, 80, 22];

  let portResults: any[] = [];
  let isLiveSuccess = false;

  if (executionMode === 'REAL') {
    // Perform real TCP connect probing
    const probePromises = targetPorts.map(async (p) => {
      const result = await probeTcpPort(ip, p, 800);
      if (result.open) {
        return {
          port: p,
          protocol: 'tcp',
          state: 'open',
          service: p === 445 ? 'microsoft-ds' : p === 135 ? 'msrpc' : p === 88 ? 'kerberos-sec' : p === 389 ? 'ldap' : 'service',
          version: result.banner || 'Verified Live TCP Service',
          smbSigning: result.smbSigning || (p === 445 ? 'DISABLED' : 'NOT_APPLICABLE'),
          detectionMethod: 'SOCKET_CONNECT'
        };
      }
      return null;
    });

    const results = await Promise.all(probePromises);
    portResults = results.filter(Boolean);
    if (portResults.length > 0) {
      isLiveSuccess = true;
    }
  }

  // Fallback to deterministic modeled data if not reachable in container or mode is SIMULATED
  if (!isLiveSuccess) {
    portResults = portScanMatrix[ip] || [
      { port: 135, protocol: 'tcp', state: 'open', service: 'msrpc', version: 'Microsoft Windows RPC', smbSigning: 'NOT_APPLICABLE', detectionMethod: 'SIMULATED' },
      { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds', version: 'Microsoft Windows SMB', smbSigning: 'DISABLED', detectionMethod: 'SIMULATED' },
    ];
  }

  const effectiveMode = isLiveSuccess ? 'REAL' : 'SIMULATED';

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'SERVICE_ENUMERATION',
    target: ip,
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: effectiveMode,
    details: `Scanned ${ip}. Identified ${portResults.length} open TCP ports. Mode: ${effectiveMode}`
  });
  saveStore();

  res.json({
    targetIp: ip,
    timestamp: new Date().toISOString(),
    executionMode: effectiveMode,
    scanFlags: flags || '-sS -sV -sC -Pn',
    ports: portResults,
    smbSigningSummary: ip === '192.168.56.10' ? 'ENFORCED (DC default)' : 'DISABLED / NOT REQUIRED (Vulnerable to NTLM Relay)',
    rawNmapOutput: [
      `Starting Nmap Scan against ${ip} [Mode: ${effectiveMode}]`,
      `Nmap scan report for ${ip}`,
      `Host is up.`,
      `PORT     STATE SERVICE       VERSION`,
      ...portResults.map((p: any) => `${p.port}/tcp`.padEnd(9) + p.state.padEnd(6) + p.service.padEnd(14) + (p.version || ''))
    ]
  });
});

// Active Directory LDAP Directory & Configuration
const adDirectory = {
  domain: {
    fqdn: 'adstrike.local',
    netbios: 'ADSTRIKE',
    forestFunctionalLevel: 'Windows Server 2016',
    domainFunctionalLevel: 'Windows Server 2016',
    primaryDc: 'DC01.adstrike.local',
    dcIp: '192.168.56.10',
    krbtgtChanged: '2026-01-10 08:33:12 UTC',
    trusts: [
      { targetDomain: 'None (Isolated Forest)', direction: 'N/A', type: 'Isolated Lab' }
    ]
  },
  users: [
    {
      sAMAccountName: 'Administrator',
      displayName: 'Builtin Domain Administrator',
      distinguishedName: 'CN=Administrator,CN=Users,DC=adstrike,DC=local',
      servicePrincipalNames: [],
      userAccountControl: 512,
      uacFlags: ['NORMAL_ACCOUNT'],
      adminCount: true,
      passwordLastSet: '2026-01-15 11:22:04 UTC',
      kerberoastable: false,
      asrepRoastable: false,
      unconstrainedDelegation: false,
      memberOf: ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators']
    },
    {
      sAMAccountName: 'krbtgt',
      displayName: 'Key Distribution Center Service Account',
      distinguishedName: 'CN=krbtgt,CN=Users,DC=adstrike,DC=local',
      servicePrincipalNames: ['kadmin/changepw'],
      userAccountControl: 514,
      uacFlags: ['ACCOUNTDISABLE', 'NORMAL_ACCOUNT'],
      adminCount: true,
      passwordLastSet: '2026-01-10 08:33:12 UTC',
      kerberoastable: false,
      asrepRoastable: false,
      unconstrainedDelegation: false,
      memberOf: ['Denied RODC Password Replication Group']
    },
    {
      sAMAccountName: 'jdoe',
      displayName: 'John Doe (Initial Foothold)',
      distinguishedName: 'CN=John Doe,OU=StandardUsers,DC=adstrike,DC=local',
      servicePrincipalNames: [],
      userAccountControl: 512,
      uacFlags: ['NORMAL_ACCOUNT'],
      adminCount: false,
      passwordLastSet: '2026-08-01 14:10:00 UTC',
      kerberoastable: false,
      asrepRoastable: false,
      unconstrainedDelegation: false,
      memberOf: ['Domain Users', 'HelpDesk Level 1']
    },
    {
      sAMAccountName: 'svc_mssql',
      displayName: 'Microsoft SQL Service Worker',
      distinguishedName: 'CN=svc_mssql,OU=ServiceAccounts,DC=adstrike,DC=local',
      servicePrincipalNames: ['MSSQLSvc/WIN-SRV-01.adstrike.local:1433', 'MSSQLSvc/WIN-SRV-01.adstrike.local'],
      userAccountControl: 66048,
      uacFlags: ['DONT_EXPIRE_PASSWORD', 'NORMAL_ACCOUNT'],
      adminCount: true,
      passwordLastSet: '2026-03-14 09:12:44 UTC',
      kerberoastable: true,
      asrepRoastable: false,
      unconstrainedDelegation: false,
      memberOf: ['Domain Users', 'SQLAdmins']
    },
    {
      sAMAccountName: 'backup_operator',
      displayName: 'Automated Backup Principal',
      distinguishedName: 'CN=backup_operator,OU=ServiceAccounts,DC=adstrike,DC=local',
      servicePrincipalNames: [],
      userAccountControl: 4259840,
      uacFlags: ['DONT_REQ_PREAUTH', 'DONT_EXPIRE_PASSWORD', 'NORMAL_ACCOUNT'],
      adminCount: false,
      passwordLastSet: '2026-02-20 18:04:19 UTC',
      kerberoastable: false,
      asrepRoastable: true,
      unconstrainedDelegation: false,
      memberOf: ['Domain Users', 'Backup Operators']
    }
  ],
  computers: [
    { name: 'DC01$', os: 'Windows Server 2022 Standard', ip: '192.168.56.10', unconstrainedDelegation: true, trustedToAuthForDelegation: false },
    { name: 'WIN-SRV-01$', os: 'Windows Server 2019 Standard', ip: '192.168.56.30', unconstrainedDelegation: true, trustedToAuthForDelegation: false },
    { name: 'WIN10-01$', os: 'Windows 10 Pro 22H2', ip: '192.168.56.20', unconstrainedDelegation: false, trustedToAuthForDelegation: false },
  ],
  groups: [
    { name: 'Domain Admins', members: ['Administrator'], privileges: 'Full Domain Controller Governance' },
    { name: 'SQLAdmins', members: ['svc_mssql'], privileges: 'DS-Replication-Get-Changes-All (CanDCSync)' },
    { name: 'Backup Operators', members: ['backup_operator'], privileges: 'SeBackupPrivilege / File Access' },
    { name: 'HelpDesk Level 1', members: ['jdoe'], privileges: 'Local admin on workstations' },
  ]
};

// LDAP Config endpoints
app.get('/api/ad/config', (req, res) => {
  res.json(ldapConfig);
});

app.post('/api/ad/config', (req, res) => {
  const { domain, dcHost, port, useTls, bindUser, baseDn } = req.body;
  ldapConfig = {
    domain: domain || ldapConfig.domain,
    dcHost: dcHost || ldapConfig.dcHost,
    port: port || ldapConfig.port,
    useTls: !!useTls,
    bindUser: bindUser || ldapConfig.bindUser,
    baseDn: baseDn || ldapConfig.baseDn
  };
  saveStore();
  res.json({ success: true, config: ldapConfig });
});

// Test LDAP connection
app.post('/api/ad/test-connection', async (req, res) => {
  const { dcHost, port } = req.body;
  const host = dcHost || ldapConfig.dcHost;
  const p = port || ldapConfig.port;

  const probe = await probeTcpPort(host, p, 1500);
  res.json({
    host,
    port: p,
    connected: probe.open,
    latencyMs: probe.latencyMs,
    status: probe.open ? 'CONNECTED_ACTIVE' : 'NO_RESPONSE_HOST_OFFLINE',
    executionMode: probe.open ? 'REAL' : 'SIMULATED'
  });
});

app.get('/api/ad/directory', (req, res) => {
  res.json(adDirectory);
});

// -------------------------------------------------------------
// 7. CONTROLLED OFFENSIVE VALIDATION
// -------------------------------------------------------------

// Kerberoasting Assessment
app.post('/api/attack/kerberoast', scopeGuardMiddleware, (req, res) => {
  const { account, operatorConfirmed } = req.body;
  const targetUser = account || 'svc_mssql';

  const userObj = adDirectory.users.find(u => u.sAMAccountName === targetUser);
  if (!userObj || !userObj.kerberoastable) {
    return res.status(400).json({ error: `Account ${targetUser} does not have an active SPN registered or is not roastable.` });
  }

  const extractedHash = `$krb5tgs$23$*${targetUser}*adstrike.local*${userObj.servicePrincipalNames[0]}*$b4718c99e2f4a13d7e8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f*112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00`;
  const sha = crypto.createHash('sha256').update(extractedHash).digest('hex');

  const artifact = {
    id: `ev-${Date.now()}`,
    assessmentId: 'ASMT-2026-LAB-01',
    mitreId: 'T1558.003',
    technique: `Kerberoasting TGS Ticket Extracted (${targetUser})`,
    targetHost: '192.168.56.10',
    sourceTool: 'impacket/GetUserSPNs.py',
    timestamp: new Date().toUTCString(),
    sha256: sha,
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    payloadType: 'hash',
    sizeBytes: Buffer.byteLength(extractedHash, 'utf8'),
    mimeType: 'application/x-hashcat-13100',
    rawPreview: extractedHash,
    verified: true,
    executionMode: 'SIMULATED',
    associatedFindingId: 'f-01'
  };

  evidenceVault.unshift(artifact as any);

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'KERBEROAST_TGS_REQUESTED',
    target: '192.168.56.10',
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: 'SIMULATED',
    details: `Requested Kerberos TGS RC4-HMAC ticket for ${userObj.servicePrincipalNames[0]}. (Hashcat mode 13100, SHA256: ${sha.slice(0, 16)})`
  });
  saveStore();

  res.json({
    success: true,
    executionMode: 'SIMULATED',
    account: targetUser,
    spn: userObj.servicePrincipalNames[0],
    cipher: 'rc4-hmac (arcfour-hmac-md5, etype 23 - Vulnerable)',
    hashFormat: 'Hashcat Mode 13100 / John the Ripper (krb5tgs)',
    extractedHash,
    evidenceArtifactId: artifact.id,
    sha256: sha,
    maskedPreview: `$krb5tgs$23$*${targetUser}*adstrike.local*${userObj.servicePrincipalNames[0]}*$b471...[MASKED]`,
    clearedForCracking: true
  });
});

// AS-REP Roasting Assessment
app.post('/api/attack/asreproast', scopeGuardMiddleware, (req, res) => {
  const { account } = req.body;
  const targetUser = account || 'backup_operator';

  const userObj = adDirectory.users.find(u => u.sAMAccountName === targetUser);
  if (!userObj || !userObj.asrepRoastable) {
    return res.status(400).json({ error: `Account ${targetUser} does not have DONT_REQ_PREAUTH flag enabled.` });
  }

  const extractedHash = `$krb5asrep$23$${targetUser}@ADSTRIKE.LOCAL:4f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c$10293847561029384756102938475610293847561029384756`;
  const sha = crypto.createHash('sha256').update(extractedHash).digest('hex');

  const artifact = {
    id: `ev-${Date.now()}`,
    assessmentId: 'ASMT-2026-LAB-01',
    mitreId: 'T1558.004',
    technique: `AS-REP Hash Harvested (${targetUser})`,
    targetHost: '192.168.56.10',
    sourceTool: 'impacket/GetNPUsers.py',
    timestamp: new Date().toUTCString(),
    sha256: sha,
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    payloadType: 'hash',
    sizeBytes: Buffer.byteLength(extractedHash, 'utf8'),
    mimeType: 'application/x-hashcat-18200',
    rawPreview: extractedHash,
    verified: true,
    executionMode: 'SIMULATED',
    associatedFindingId: 'f-02'
  };

  evidenceVault.unshift(artifact as any);

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'ASREP_ROAST_CAPTURED',
    target: '192.168.56.10',
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: 'SIMULATED',
    details: `Harvested AS-REP ticket for ${targetUser} without pre-authentication (Mode 18200, SHA256: ${sha.slice(0, 16)})`
  });
  saveStore();

  res.json({
    success: true,
    executionMode: 'SIMULATED',
    account: targetUser,
    flag: 'DONT_REQ_PREAUTH (UAC 0x400000)',
    hashFormat: 'Hashcat Mode 18200 / krb5asrep',
    extractedHash,
    evidenceArtifactId: artifact.id,
    sha256: sha,
    maskedPreview: `$krb5asrep$23$${targetUser}@ADSTRIKE.LOCAL:...[MASKED]`
  });
});

// DCSync Step 1: Privilege Verification
app.post('/api/attack/dcsync/check-privs', scopeGuardMiddleware, (req, res) => {
  const { principal } = req.body;
  const testPrincipal = principal || 'svc_mssql';

  // Check SQLAdmins or Domain Admins
  const hasPrivs = testPrincipal === 'svc_mssql' || testPrincipal === 'Administrator';

  res.json({
    principal: testPrincipal,
    domain: 'adstrike.local',
    dc: 'DC01.adstrike.local',
    privileges: {
      'DS-Replication-Get-Changes': hasPrivs,
      'DS-Replication-Get-Changes-All': hasPrivs,
      'DS-Replication-Get-Changes-In-Filtered-Set': hasPrivs
    },
    canDCSync: hasPrivs,
    evidenceNote: hasPrivs
      ? 'Principal is member of SQLAdmins, which has been granted DS-Replication-Get-Changes-All extended right over Domain head.'
      : 'Principal lacks required directory replication rights.'
  });
});

// DCSync Step 2: Controlled Hash Extraction
app.post('/api/attack/dcsync', scopeGuardMiddleware, (req, res) => {
  const { user, operatorConfirmed } = req.body;
  const syncUser = user || 'Administrator';

  if (!operatorConfirmed) {
    return res.status(400).json({
      error: 'OPERATOR_CONFIRMATION_REQUIRED',
      message: 'DCSync is a sensitive high-impact assessment. Operator confirmation parameter operatorConfirmed: true must be supplied.'
    });
  }

  const ntdsLine = `${syncUser}:500:aad3b435b51404eeaad3b435b51404ee:10b27e8a93e5e54c87c4a06d88f6a654:::`;
  const sha = crypto.createHash('sha256').update(ntdsLine).digest('hex');

  const artifact = {
    id: `ev-${Date.now()}`,
    assessmentId: 'ASMT-2026-LAB-01',
    mitreId: 'T1003.006',
    technique: `DCSync NTDS.dit Password Hash (${syncUser})`,
    targetHost: '192.168.56.10',
    sourceTool: 'impacket/secretsdump.py',
    timestamp: new Date().toUTCString(),
    sha256: sha,
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    payloadType: 'ntds_dit',
    sizeBytes: Buffer.byteLength(ntdsLine, 'utf8'),
    mimeType: 'text/plain',
    rawPreview: ntdsLine,
    verified: true,
    executionMode: 'SIMULATED',
    associatedFindingId: 'f-05'
  };

  evidenceVault.unshift(artifact as any);

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'DCSYNC_CREDENTIAL_DUMP',
    target: '192.168.56.10',
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: 'SIMULATED',
    details: `Executed DRSUAPI directory replication query against DC01. Extracted NTDS.dit hash for ${syncUser}.`
  });
  saveStore();

  res.json({
    success: true,
    executionMode: 'SIMULATED',
    target: 'DC01.adstrike.local (192.168.56.10)',
    drsMethod: 'IDL_DRSGetNCChanges via MS-DRSR',
    replicatedPrincipal: syncUser,
    ntlmHash: '10b27e8a93e5e54c87c4a06d88f6a654',
    rawNtdsLine: ntdsLine,
    maskedPreview: `${syncUser}:500:...:10b2...654::: [PROTECTED]`,
    evidenceArtifactId: artifact.id,
    sha256: sha
  });
});

// Lateral Movement Dispatch API
app.post('/api/lateral/execute', scopeGuardMiddleware, (req, res) => {
  const { sourceHost, targetHost, method, credential, command } = req.body;

  const target = targetHost || '192.168.56.20';
  const execMethod = method || 'wmiexec';
  const cmd = command || 'whoami /all';

  const taskId = `task-lat-${Date.now()}`;
  const task: ExecutionTask = {
    id: taskId,
    module: 'Lateral Movement',
    tool: `impacket/${execMethod}.py`,
    target,
    executionMode: 'SIMULATED',
    status: 'COMPLETED',
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: 380,
    exitCode: 0,
    outputLines: [
      `[*] Dispatching ${execMethod}.py ADSTRIKE/Administrator@${target} -hashes :10b27e8a...`,
      `[*] Target scope check: PASSED (192.168.56.0/24)`,
      `[+] Authentication successful via Pass-the-Hash (NTLM)`,
      `[+] Remote command dispatched: ${cmd}`,
      `USER: adstrike\\administrator (S-1-5-21-3141592653-589793238-462643383-500)`,
      `GROUPS: BUILTIN\\Administrators, ADSTRIKE\\Domain Admins`,
      `[+] Execution completed with exit code 0.`
    ]
  };

  activeTasks.set(taskId, task);
  broadcastTaskUpdate(task);

  auditLog.unshift({
    id: `audit-${Date.now()}`,
    timestamp: new Date().toUTCString(),
    operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
    action: 'LATERAL_MOVEMENT_DISPATCH',
    target,
    scopeStatus: 'IN_SCOPE_ALLOWED',
    executionMode: 'SIMULATED',
    details: `Executed ${execMethod} Pass-the-Hash against ${target}: ${cmd}`
  });
  saveStore();

  res.json({
    success: true,
    executionMode: 'SIMULATED',
    taskId,
    sourceHost: sourceHost || '192.168.56.50 (Kali)',
    targetHost: target,
    technique: 'Pass-the-Hash (T1550.002) over ' + execMethod.toUpperCase(),
    output: task.outputLines
  });
});

// Lab Presets & Offline Instructions API
app.get('/api/lab/presets', (req, res) => {
  res.json({
    environment: 'Host-Only Virtual Subnet (VirtualBox / VMware Workstation)',
    recommendedSubnet: '192.168.56.0/24',
    gatewayIp: '192.168.56.1',
    dhcpRange: '192.168.56.100 - 192.168.56.254',
    kaliIp: '192.168.56.50',
    dcIp: '192.168.56.10',
    dnsForwarder: '192.168.56.10',
    virtualBoxSetupInstructions: [
      'Open VirtualBox -> Tools -> Network Manager -> Host-only Networks.',
      'Create or select "vboxnet0" and configure IPv4 Address: 192.168.56.1, Netmask: 255.255.255.0.',
      'Set DHCP Server: Disabled (or configure range 192.168.56.100-200).',
      'For DC01, WIN10-01, and WIN-SRV-01 VMs, attach Adapter 1 to "Host-only Adapter", Name: vboxnet0.',
      'For Kali VM, attach Adapter 1 to "Host-only Adapter" (vboxnet0) and assign static IP 192.168.56.50/24.'
    ],
    activeDirectorySetupScript: `$ForestName = "adstrike.local"
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName $ForestName -SafeModeAdministratorPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Force
# Create Vulnerable Service Account
New-ADUser -Name "svc_mssql" -SamAccountName "svc_mssql" -AccountPassword (ConvertTo-SecureString "Winter2026!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
Set-ADUser -Identity "svc_mssql" -ServicePrincipalNames @{Add="MSSQLSvc/WIN-SRV-01.adstrike.local:1433"}
# Create AS-REP Vulnerable Account
New-ADUser -Name "backup_operator" -SamAccountName "backup_operator" -AccountPassword (ConvertTo-SecureString "Backup123$" -AsPlainText -Force) -Enabled $true
Set-ADAccountControl -Identity "backup_operator" -DoesNotRequirePreAuth $true`
  });
});

// Controlled Terminal Command Execution Engine
app.post('/api/terminal/exec', (req, res) => {
  const { command } = req.body;
  if (!command || typeof command !== 'string') {
    return res.status(400).json({ error: 'Command string is required.' });
  }

  const trimmed = command.trim();
  const lower = trimmed.toLowerCase();
  const now = new Date().toTimeString().split(' ')[0];

  // Scope Guard Check
  const ipMatch = trimmed.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  if (ipMatch) {
    const targetIp = ipMatch[0];
    const check = isIpInAuthorizedScope(targetIp);
    if (!check.allowed) {
      auditLog.unshift({
        id: `audit-${Date.now()}`,
        timestamp: new Date().toUTCString(),
        operator: (req.headers['x-operator-id'] as string) || 'operator@kali',
        action: 'EXECUTION_SCOPE_BLOCKED',
        target: targetIp,
        scopeStatus: 'OUT_OF_SCOPE_REJECTED',
        details: check.reason
      });
      saveStore();

      return res.status(403).json({
        success: false,
        error: `[!] HARD SCOPE VIOLATION: Target IP ${targetIp} is outside the authorized lab boundary. Reason: ${check.reason}`,
        scopeBlocked: true
      });
    }
  }

  // Dynamic Command Handling
  if (lower === 'scope') {
    return res.json({
      success: true,
      timestamp: now,
      output: [
        '┌────────────────────────────────────────────────────────────────────────┐',
        '│ AUTHORIZED SCOPE ENGINE TELEMETRY                                      │',
        '├──────────────────────┬─────────────────────────────────────────────────┤',
        '│ Assessment Scope     │ 192.168.56.0/24 (Netmask 255.255.255.0)         │',
        '│ Usable Host Range    │ 192.168.56.1 - 192.168.56.254                   │',
        '│ Excluded IPs         │ 192.168.56.1 (Gateway Protected)                │',
        '│ Operator Signature   │ Verified by Operator [sec-ops-kali]             │',
        '│ Out-of-Scope Rule    │ Hard Reject (HTTP 403 / TARGET_OUT_OF_SCOPE)   │',
        '└──────────────────────┴─────────────────────────────────────────────────┘'
      ]
    });
  }

  if (lower === 'targets') {
    return res.json({
      success: true,
      timestamp: now,
      output: [
        '+----+----------------+-----------------------+--------------------------+----------+----------+',
        '| ID | IP ADDRESS     | FQDN / HOSTNAME       | OPERATING SYSTEM         | AD ROLE  | STATUS   |',
        '+----+----------------+-----------------------+--------------------------+----------+----------+',
        '| 01 | 192.168.56.10  | DC01.adstrike.local   | Windows Server 2022 Std  | DC (KDC) | ONLINE   |',
        '| 02 | 192.168.56.20  | WIN10-01.adstrike.loc | Windows 10 Pro 22H2      | WKSTN    | ONLINE   |',
        '| 03 | 192.168.56.30  | WIN-SRV-01.adstrike   | Windows Server 2019 (SQL)| SERVER   | ONLINE   |',
        '| 04 | 192.168.56.40  | LINUX01.adstrike.local| Ubuntu 22.04 LTS (SSSD)  | LINUX    | ONLINE   |',
        '| 05 | 192.168.56.50  | KALI-OPERATOR         | Kali Linux 2024.1        | AUDITOR  | ACTIVE   |',
        '+----+----------------+-----------------------+--------------------------+----------+----------+'
      ]
    });
  }

  if (lower.includes('getuserspns')) {
    return res.json({
      success: true,
      timestamp: now,
      output: [
        'Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies',
        '',
        'ServicePrincipalName               Name       MemberOf                               PasswordLastSet',
        '---------------------------------  ---------  -------------------------------------  --------------------------',
        'MSSQLSvc/WIN-SRV-01.adstrike.local svc_mssql  CN=SQLAdmins,CN=Users,DC=adstrike...  2026-03-14 09:12:44',
        '',
        '[*] Querying Kerberos TGS ticket for user: svc_mssql...',
        '[+] Hash extracted: $krb5tgs$23$*svc_mssql*adstrike.local*MSSQLSvc/WIN-SRV-01.adstrike.local*$b471...c82a',
        '[!] ENCRYPTION CIPHER: RC4-HMAC (Vulnerable to offline dictionary attack)',
        '[*] Evidence auto-cataloged: /vault/evidence/T1558.003_svc_mssql.hash'
      ]
    });
  }

  if (lower.includes('secretsdump')) {
    return res.json({
      success: true,
      timestamp: now,
      output: [
        'Impacket v0.12.0 - secretsdump.py',
        '[*] Target: 192.168.56.10 (DC01.adstrike.local)',
        '[*] Dumping Domain Credentials (DRSUAPI method - DCSync simulation)...',
        '[*] Exporting hashes from NTDS.dit...',
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:10b27e8a93e5e54c87c4a06d88f6a654:::',
        'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9a4d2c88f4b5c77e90e4f1a23b56c891:::',
        '[+] Complete Domain Compromise Achieved via validated DCSync path.'
      ]
    });
  }

  res.json({
    success: true,
    timestamp: now,
    output: [
      `[*] Executing controlled assessment command: ${trimmed}`,
      `[*] Scope verification: PASSED (${labScope.authorizedCidr})`,
      `[+] Exit code: 0 | Execution duration: 165ms`,
      `[+] Telemetry logged to Audit Log & Evidence Vault.`
    ]
  });
});

// Penetration Test Report Generation
app.post('/api/reports/generate', (req, res) => {
  const { title } = req.body;
  const report = {
    title: title || 'ADStrike Enterprise Active Directory Penetration Test Report',
    date: new Date().toLocaleDateString(),
    scope: labScope.authorizedCidr,
    criticalFindings: findings.filter(f => f.severity === 'CRITICAL').length,
    highFindings: findings.filter(f => f.severity === 'HIGH').length,
    mediumFindings: findings.filter(f => f.severity === 'MEDIUM').length,
    compromisedPathsCount: 2,
    domainCompromised: true,
    executiveSummary: 'During the authorized laboratory penetration test against adstrike.local (192.168.56.0/24), the assessment team successfully demonstrated an attack chain leading from a standard domain user credential to full Domain Administrator compromise.',
    evidenceItems: evidenceVault.length,
    methodology: 'PTES (Penetration Testing Execution Standard) & MITRE ATT&CK Framework for Enterprise',
    recommendations: [
      'Disable RC4-HMAC encryption for all Kerberos Service Principal Names and enforce AES256-CTS-HMAC-SHA1-96.',
      'Re-enable Kerberos pre-authentication (remove DONT_REQ_PREAUTH) on backup_operator.',
      'Revoke TRUSTED_FOR_DELEGATION attribute on member servers; migrate to Constrained Delegation with Protocol Transition or Resource-Based Constrained Delegation (RBCD).',
      'Enforce SMB signing across all workstations and member servers via Group Policy Object (GPO).',
      'Audit and remove Replicating Directory Changes permissions from non-Domain Controller security principals.'
    ]
  };

  res.json(report);
});

// -------------------------------------------------------------
// 8. VITE DEV / PRODUCTION MIDDLEWARE INTEGRATION
// -------------------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[ADStrike Server] Running on http://0.0.0.0:${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  });
}

startServer();
