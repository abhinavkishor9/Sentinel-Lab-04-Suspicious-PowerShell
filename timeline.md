# Timeline — Sentinel Lab 04

## Investigation Timeline

| Time | Activity | Result |
|---|---|---|
| 09:00 | Lab environment validated | Sentinel workspace available |
| 09:05 | Synthetic telemetry prepared | Three PowerShell events created |
| 09:10 | Initial PowerShell query executed | Three executions identified |
| 09:15 | User and host reviewed | Two execution contexts observed |
| 09:20 | Parent processes analyzed | `explorer.exe` vs `winword.exe` identified |
| 09:25 | Command lines reviewed | `Bypass` and `EncodedCommand` identified |
| 09:30 | Suspicious event isolated | `user1` event selected |
| 09:35 | Detection logic created | One event matched |
| 09:40 | Evidence assessment performed | Suspicious indicators confirmed |
| 09:45 | Evidence gaps reviewed | Follow-on telemetry unavailable |
| 09:50 | False-positive considerations reviewed | Legitimate explanations considered |
| 10:00 | Final verdict assigned | Suspicious — Potentially Malicious PowerShell Execution |

---

## Key Event Sequence

    10:00 UTC
    admin → explorer.exe → powershell.exe
    Get-Process

    10:05 UTC
    admin → explorer.exe → powershell.exe
    Get-Service

    10:10 UTC
    user1 → winword.exe → powershell.exe
    ExecutionPolicy Bypass + EncodedCommand

---

## Investigation Milestones

### Initial Review

Three PowerShell executions were identified.

### Context Analysis

The first two events appeared consistent with administrative activity based on the available evidence.

### Suspicious Activity

The third event contained multiple suspicious characteristics:

- `winword.exe` as parent process
- `-ExecutionPolicy Bypass`
- `-EncodedCommand`

### Detection

A KQL filter successfully isolated the suspicious event.

### Evidence Assessment

The suspicious execution was confirmed, but malicious intent and compromise could not be confirmed from the available telemetry.

---

## Final Assessment

**Verdict:** Suspicious — Potentially Malicious PowerShell Execution

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Primary Evidence:**

    winword.exe → powershell.exe

with:

    -ExecutionPolicy Bypass
    -EncodedCommand

**Evidence Gap:**

No PowerShell Script Block, network, file, child-process, or endpoint-security telemetry was available.

**Final SOC Principle:**

> **Follow the evidence, not the assumption.**
