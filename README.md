# Sentinel Lab 04 — Suspicious PowerShell

## Overview

This lab investigates potentially suspicious **PowerShell execution** using Microsoft Sentinel and KQL.

PowerShell is a legitimate Windows administration and automation tool, but it can also be abused to execute commands, bypass security controls, or run encoded content. Therefore, detecting `powershell.exe` alone is not enough to determine malicious activity.

The investigation focuses on **command-line parameters, parent process, user, host, and execution context** to determine whether the activity requires further investigation.

> **Investigation principle:** Follow the evidence, not the assumption.

---

## Investigation Scenario

A Windows system shows multiple PowerShell executions. Two executions appear consistent with normal administrative activity, while another PowerShell process is launched by `winword.exe` and uses both `-ExecutionPolicy Bypass` and `-EncodedCommand`.

The objective is to determine whether this execution represents normal PowerShell usage or suspicious activity requiring further investigation.

---

## Lab Objectives

- Understand why PowerShell is relevant to SOC investigations.
- Identify PowerShell execution events using KQL.
- Review PowerShell command-line activity.
- Analyze the parent process associated with PowerShell.
- Identify suspicious PowerShell execution parameters.
- Compare normal and suspicious PowerShell activity.
- Develop basic detection logic using KQL.
- Assess the evidence without automatically treating PowerShell as malicious.
- Document evidence gaps and appropriate follow-up actions.

---

## Environment

| Component | Details |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `Microsoft-Sentinel-Workspace` |
| Query Language | KQL |
| Data Type | Synthetic telemetry |
| Host | `DESKTOP-LAB01` |
| Investigation Date | 2026-09-14 |

---

## Data Source

Persistent endpoint telemetry was not available for this investigation.

Therefore, the lab uses a temporary KQL `datatable()` containing synthetic process execution data.

The dataset includes:

- `TimeGenerated`
- `Computer`
- `User`
- `ParentProcess`
- `Process`
- `CommandLine`

The synthetic data is used for investigation and detection-learning purposes and does not represent production telemetry.

---

## Synthetic Dataset

The dataset contains three PowerShell executions:

| Time | User | Parent Process | Command | Initial Assessment |
|---|---|---|---|---|
| 10:00 UTC | admin | explorer.exe | `Get-Process` | Likely benign |
| 10:05 UTC | admin | explorer.exe | `Get-Service` | Likely benign |
| 10:10 UTC | user1 | winword.exe | `-ExecutionPolicy Bypass -EncodedCommand` | Suspicious |

---

## Investigation Workflow

The investigation followed these stages:

1. Load the synthetic process telemetry.
2. Identify PowerShell executions.
3. Review the users and host.
4. Examine parent processes.
5. Review command-line parameters.
6. Compare normal and suspicious executions.
7. Create detection logic.
8. Assess the strongest finding.
9. Review evidence gaps and false positives.
10. Assign an evidence-based verdict.

---

## Step 1 — Review PowerShell Executions

The initial query filtered for PowerShell processes and displayed the execution context.

    | where Process =~ "powershell.exe"
    | project TimeGenerated, Computer, User, ParentProcess, CommandLine
    | order by TimeGenerated asc

### Observed Results

Three PowerShell executions were identified.

The first two were launched by `explorer.exe` under the `admin` account and used:

    powershell.exe -NoProfile -Command Get-Process

    powershell.exe -NoProfile -Command Get-Service

The third execution was different:

- User: `user1`
- Parent process: `winword.exe`
- Process: `powershell.exe`
- Execution policy: `Bypass`
- Command type: `EncodedCommand`

This became the primary investigation target.

---

## Step 2 — Review the Command Line

The suspicious event contained:

    -ExecutionPolicy Bypass

and:

    -EncodedCommand

These characteristics require additional attention.

### ExecutionPolicy Bypass

`-ExecutionPolicy Bypass` changes the PowerShell execution-policy behavior for that process.

Its presence is not automatically malicious, but it can increase suspicion when combined with other unusual execution characteristics.

### EncodedCommand

`-EncodedCommand` allows PowerShell commands to be supplied in encoded form.

Encoding can have legitimate uses, but attackers may also use it to make command-line content less immediately visible during investigation.

---

## Step 3 — Analyze the Parent Process

The suspicious PowerShell process was launched by:

    winword.exe

The two comparison events were launched by:

    explorer.exe

The `winword.exe` to PowerShell relationship is therefore an important contextual indicator.

---

## Step 4 — Create Detection Logic

The following KQL identifies PowerShell executions containing suspicious command-line indicators:

    | where Process =~ "powershell.exe"
    | where CommandLine has_any ("-EncodedCommand", "-ExecutionPolicy Bypass")
    | project TimeGenerated, Computer, User, ParentProcess, CommandLine

### Detection Result

Only one event matched:

| User | Parent Process | Suspicious Indicators |
|---|---|---|
| user1 | winword.exe | `-ExecutionPolicy Bypass`, `-EncodedCommand` |

The detection successfully separated the suspicious event from the two comparison events.

---

## Primary Finding

The strongest finding was:

**2026-09-14 10:10 UTC — `user1` on `DESKTOP-LAB01`**

PowerShell was launched by `winword.exe` with:

    -ExecutionPolicy Bypass
    -EncodedCommand

This combination is suspicious and warrants further investigation.

---

## Investigation Verdict

**Verdict: Suspicious — Potentially Malicious PowerShell Execution**

The available evidence supports treating the activity as suspicious.

However, the evidence does not prove that the host was compromised.

The available telemetry does not show what the encoded command actually executed or whether malicious follow-on activity occurred.

---

## Evidence Assessment

| Evidence | Assessment |
|---|---|
| PowerShell execution | Confirmed |
| `-ExecutionPolicy Bypass` | Confirmed |
| `-EncodedCommand` | Confirmed |
| PowerShell launched by Word | Confirmed |
| Malicious payload | Unknown |
| Successful compromise | Unknown |
| Follow-on network activity | Unknown |
| Persistence | Unknown |

---

## Evidence Gaps

Additional telemetry would be useful to determine the actual impact:

- PowerShell Script Block Logging
- Process creation telemetry
- Network connection events
- File creation events
- Endpoint security alerts
- Child-process activity
- Decoded command content
- User activity surrounding the event

Without this information, the investigation should remain at **suspicious**, rather than confirmed malicious.

---

## False-Positive Considerations

Possible legitimate explanations include:

- Administrative automation
- Authorized scripts
- Software deployment
- Enterprise document workflows
- Security testing
- Application compatibility requirements

The parent process and command-line context should therefore be investigated together with the user, host, and surrounding activity.

---

## MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The observed activity involves execution through PowerShell.

The ATT&CK mapping describes the technique associated with PowerShell execution; it does not by itself prove malicious activity.

---

## Key SOC Lesson

A strong PowerShell investigation does not stop at:

    powershell.exe

Instead, the analyst should ask:

> Who executed it, what launched it, what parameters were used, and what happened afterward?

In this case, the combination of:

    winword.exe → powershell.exe → ExecutionPolicy Bypass → EncodedCommand

provides a stronger suspicious signal than PowerShell execution alone.

---

## Lab Outcome

This lab demonstrated how Microsoft Sentinel and KQL can be used to:

- Identify PowerShell executions.
- Compare normal and suspicious process activity.
- Analyze parent-child process relationships.
- Detect suspicious command-line parameters.
- Build focused detection logic.
- Avoid treating a single indicator as proof of compromise.
- Document evidence gaps and investigation limitations.

---

## Conclusion

The investigation identified one suspicious PowerShell execution launched from `winword.exe` with `-ExecutionPolicy Bypass` and `-EncodedCommand`.

The activity is **suspicious and potentially malicious**, but the available synthetic telemetry is insufficient to confirm compromise. Further endpoint and PowerShell telemetry would be required to determine the actual command execution and impact.
