# Investigation Notes 

## Evidence Reviewed

The investigation reviewed:

- PowerShell process execution
- User account
- Computer name
- Parent process
- Command-line parameters
- Execution time

---

## Initial Findings

Three PowerShell executions were observed.

Two executions were associated with the `admin` account and were launched by `explorer.exe`:

    powershell.exe -NoProfile -Command Get-Process

    powershell.exe -NoProfile -Command Get-Service

Based on the available synthetic evidence, these events appeared consistent with routine administrative activity.

---

## Suspicious Event

The third event occurred at:

**2026-09-14 10:10 UTC**

Observed context:

| Field | Value |
|---|---|
| Computer | `DESKTOP-LAB01` |
| User | `user1` |
| Parent Process | `winword.exe` |
| Process | `powershell.exe` |
| Parameters | `-ExecutionPolicy Bypass -EncodedCommand` |

This event became the primary investigation target.

---

## Command-Line Analysis

The command line contained:

    -ExecutionPolicy Bypass

and:

    -EncodedCommand

Neither parameter alone proves malicious activity.

However, their combination with an Office application as the parent process increases the level of concern.

---

## Parent Process Analysis

The suspicious PowerShell process was launched by:

    winword.exe

This differs from the comparison events launched by:

    explorer.exe

The Office-to-PowerShell process relationship therefore became an important contextual indicator.

---

## Detection Logic

The following KQL searches for PowerShell executions containing suspicious command-line parameters:

    | where Process =~ "powershell.exe"
    | where CommandLine has_any ("-EncodedCommand", "-ExecutionPolicy Bypass")
    | project TimeGenerated, Computer, User, ParentProcess, CommandLine

### Result

The query returned only the `user1` event.

This demonstrated how command-line filtering can reduce a broader PowerShell dataset to events requiring additional investigation.

---

## Evidence Assessment

### Confirmed

- PowerShell executed.
- The process was launched by `winword.exe`.
- `-ExecutionPolicy Bypass` was present.
- `-EncodedCommand` was present.

### Plausible

- The activity may represent malicious PowerShell execution.
- The Office-to-PowerShell relationship may indicate abnormal execution.

### Unknown

- The actual decoded command.
- Whether a payload was downloaded.
- Whether files were created or modified.
- Whether network communication occurred.
- Whether persistence was established.
- Whether the account or host was compromised.

---

## Investigation Verdict

**Suspicious — Potentially Malicious PowerShell Execution**

The evidence is sufficient to justify additional investigation, but not sufficient to confirm compromise.

---

