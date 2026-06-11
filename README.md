# SOC-Investigation-Reports
A collection of security incident investigation reports written in the style of real SOC analyst documentation. Each report follows a consistent structure used in professional incident response: alert triage, log analysis, root cause, timeline, IOCs, and recommendations.
Reports cover both true positives (confirmed incidents) and false positives (where investigation ruled out malicious activity) — because good SOC work means knowing when not to escalate as much as knowing when to act.

## Report Structure ##
Each report follows this template:
Header metadata  (severity, verdict, MITRE mapping)
Executive Summary
1. Alert Triage       — what fired and the 3 investigation goals
2. Investigation      — log sources, pivots, findings
3. Root Cause
4. Timeline
5. Indicators of Compromise
6. Actions Taken
7. Recommendations

## Tools and Log Sources Referenced ##

SIEM: Splunk (correlation rules, search queries)
Windows logs: Security Event Log (4624, 4648, 4663), Sysmon (Event ID 1, 3), PowerShell Operational
Log Correlation: Windows, Powershell, Proxy, Firewall
Threat intel: VirusTotal, URLScan, CyberChef, AbuseIPDB

## Investigation Philosophy ##
Every alert starts with three questions:

How did it get here? — trace the origin, understand the trigger
Who was targeted? — identify the user, asset, and blast radius
Did it succeed? — determine if the attacker achieved their goal

A closed alert with no documentation is a missed opportunity. These reports are written so that the next analyst — or the same analyst six months later — can understand exactly what happened and why the call was made.
