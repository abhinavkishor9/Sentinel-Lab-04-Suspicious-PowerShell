# Sentinel-Lab-04-Suspicious-PowerShell
## Overview
PowerShell is a legitimate Windows administration and automation tool, but attackers can also abuse it to execute commands, perform reconnaissance, download payloads, or modify systems.

From a SOC perspective, the presence of powershell.exe alone is not enough to classify activity as malicious. The investigation should examine the command line, user, host, parent process, execution time, and surrounding events.

This lab investigates potentially suspicious **PowerShell execution** using Microsoft Sentinel and KQL.

PowerShell is a legitimate Windows administration and automation tool, but it can also be abused to execute commands, bypass security controls, or run encoded content. Therefore, detecting `powershell.exe` alone is not enough to determine malicious activity.

The investigation focuses on **command-line parameters, parent process, user, host, and execution context** to determine whether the activity requires further investigation.

> **Investigation principle:** Follow the evidence, not the assumption.

---

## Investigation Scenario

A SOC analyst is reviewing process execution telemetry from a Windows endpoint after several PowerShell events were observed. PowerShell is commonly used by administrators, but the same interpreter can be abused to execute commands and conceal activity.

The investigation compares multiple PowerShell executions to determine whether any event has characteristics that warrant closer attention.

The analyst focuses on:

- User and endpoint context associated with each execution.
- Parent process responsible for launching PowerShell.
- PowerShell command-line parameters.
- Use of -ExecutionPolicy Bypass.
- Use of -EncodedCommand.
- Differences between routine administrative activity and unusual execution chains.

One event shows Microsoft Word launching PowerShell with both -ExecutionPolicy Bypass and -EncodedCommand. This combination becomes the primary investigation lead.

The available telemetry is limited, so the analyst must determine whether the evidence supports a benign, suspicious, or inconclusive assessment without assuming that malicious activity or compromise has been confirmed.

---

## Lab Objectives

- Understand how PowerShell execution can be investigated from a SOC perspective.
- Identify PowerShell processes and examine their execution context.
- Analyze parent-child process relationships for suspicious execution chains.
- Examine command-line parameters for potentially risky PowerShell behavior.
- Differentiate routine administrative PowerShell activity from activity requiring investigation.
- Build a focused KQL query to identify suspicious PowerShell characteristics.
- Correlate multiple indicators instead of relying on a single suspicious parameter.
- Assess the strength of the available evidence and identify telemetry gaps.
- Determine an appropriate investigation verdict without assuming compromise.
- Identify additional endpoint evidence required for deeper investigation.
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

## MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The observed activity involves execution through PowerShell.

The ATT&CK mapping describes the technique associated with PowerShell execution; it does not by itself prove malicious activity.

---

