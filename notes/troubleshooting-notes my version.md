# Troubleshooting Notes 

## Issue 1 — Persistent PowerShell Telemetry Was Unavailable

### Problem

The Sentinel workspace did not contain the required persistent endpoint process telemetry for this lab.

### Resolution

A temporary KQL `datatable()` was used to simulate PowerShell process events.

This allowed the investigation and detection logic to be tested without presenting synthetic events as real production telemetry.

---

## Issue 2 — Synthetic Data Is Temporary

### Problem

The `datatable()` exists only within the query where it is defined.

It does not create a permanent Sentinel table.

### Resolution

The complete `datatable()` definition must be included whenever another query needs to analyze the synthetic events.

This keeps the lab reproducible while clearly documenting that the telemetry is synthetic.

---

## Issue 3 — PowerShell Alone Is Not Malicious

### Problem

Simply detecting:

    powershell.exe

would generate many legitimate administrative events.

### Resolution

The investigation added contextual analysis using:

- Parent process
- User
- Command line
- Suspicious parameters

This reduced the investigation to the event that required additional attention.

---

## Issue 4 — `-EncodedCommand` Is Not Proof of Malicious Activity

### Problem

Encoded PowerShell commands can be used for legitimate purposes as well as malicious activity.

### Resolution

The parameter was treated as a suspicious indicator, not proof of compromise.

It was correlated with the parent process and `-ExecutionPolicy Bypass`.

---

## Issue 5 — Office Application as Parent Process

### Observation

The suspicious event showed:

    winword.exe → powershell.exe

This was more unusual than:

    explorer.exe → powershell.exe

### Resolution

The process relationship was treated as an investigation lead rather than a standalone verdict.

Additional telemetry would be required to establish what caused the PowerShell execution.

---

## Issue 6 — No Evidence of Follow-On Activity

### Problem

The synthetic dataset did not contain network, file, child-process, or endpoint-security telemetry.

### Resolution

The investigation documented these as evidence gaps instead of inventing additional activity.

Therefore, compromise remains **unknown**.

---

## Issue 7 — Avoiding Overstatement

### Problem

Suspicious PowerShell characteristics can easily lead to an unsupported conclusion such as:

> The system was compromised.

### Resolution

The final verdict was limited to:

**Suspicious — Potentially Malicious PowerShell Execution**

This reflects the available evidence without claiming confirmed compromise.

---

