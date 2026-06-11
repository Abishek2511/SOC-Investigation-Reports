# IR-005 — False Positive Investigations

## Overview
This document covers a set of alerts that were investigated and closed as false positives. Each involves a tool that is either a native Windows binary or a legitimate application — but one that attackers also abuse, which is why SIEM rules exist for them. The investigation process for each follows the same discipline as a true positive: understand the alert, trace the origin, verify the user context, and make a documented call.
A false positive closed without proper investigation is just as dangerous as a missed true positive — the next time that alert fires, it might be real.

## Case 1 — CertUtil.exe Executing with Decode Flag
What is this alert?
CertUtil.exe is a legitimate Windows certificate management utility. Attackers abuse it to download files from the internet or decode Base64-encoded payloads using the -decode or -urlcache -split -f flags — a well-documented LOLBin technique. The alert fires when CertUtil is executed with these flags.
### Investigation:
Starting point was the alert fields: timestamp, hostname, the full command line, and the parent process. The command line showed CertUtil being called with -decode on a local file path — no URL, no remote download. Parent process was a named PowerShell script run by an IT admin account.
Checked Sysmon logs in the +/-2 minute window. The PS script was part of a documented certificate deployment task — CertUtil was being used to decode a Base64-encoded certificate file before importing it, which is a standard and legitimate use of the tool. No network connections from CertUtil during execution. No child processes spawned after.
Checked the user — confirmed IT admin with a change ticket open for certificate renewal on that endpoint. Backlog check showed the same script had run on multiple machines that week as part of the same deployment.
Conclusion: False Positive. CertUtil used legitimately for certificate decoding as part of a documented admin task. The -decode flag alone is not sufficient for a true positive — the full command line, parent process, and user context all need to support the malicious interpretation before escalating.

## Case 2 — ADExplorer.exe Execution on Non-Admin Endpoint
What is this alert?
ADExplorer is a legitimate Sysinternals tool used to browse and query Active Directory. Attackers use it for AD reconnaissance — enumerating users, groups, OUs, and domain structure — because it blends in as a known admin utility. The alert fires on any execution outside designated admin machines.
### Investigation:
Alert fields showed the hostname was a standard user workstation, not an admin machine — which is why it fired. Checked Sysmon process creation logs: ADExplorer was launched directly from a USB drive path, not installed on the machine.
Checked the user account — a senior IT consultant who had been onboarded recently. Reached out directly. They confirmed they carry a personal toolkit on USB for AD troubleshooting and had used ADExplorer to verify a group membership query they were working on. Their role and the task were consistent with each other.
Checked what ADExplorer actually queried during the session via process activity — the scope was limited to a single OU relevant to the task. No broad enumeration, no snapshot exports (ADExplorer can save full AD snapshots — that would have been a significant escalation flag).
Conclusion: False Positive. Legitimate use by an authorised IT consultant. However, raised a process recommendation: portable admin tools run from personal USB on corporate endpoints should be pre-approved and logged, even when the intent is legitimate. Flagged to the IT manager.

## Case 3 — Google Chrome Extension Installed from Non-Web Store Source
What is this alert?
The alert fires when a Chrome extension is installed from a source other than the official Chrome Web Store — via a .crx file, developer mode sideload, or an unofficial URL. Malicious extensions are used for credential theft, session hijacking, and browser-based data exfiltration.
### Investigation:
Alert fields showed the hostname, the extension ID, and the install source — a direct .crx file rather than the Web Store. Checked the extension ID against VirusTotal and a quick URLScan of the source URL — no malicious reputation on either.
Looked at what the extension actually was: an internal browser tool built by the company's own development team for a specific workflow, distributed internally via a shared drive because it had not gone through the Web Store publishing process. Confirmed with the IT and development teams — the extension was known, intentional, and used across several machines in the same team.
Checked the extension's manifest and permissions — scoped only to the internal application domain it was built for, no broad host permissions, no access to passwords or clipboard.
Conclusion: False Positive. Legitimate internally developed extension distributed outside the Web Store. Recommended the team register it through the Web Store or manage deployment via Chrome Enterprise policy to avoid repeated alerts and reduce the risk of a malicious .crx being delivered through the same channel in future.

## Case 4 — Mshta.exe Executing an HTA File
What is this alert?
Mshta.exe is a Windows utility for running HTML Application (HTA) files — essentially HTML pages that execute with the privileges of a desktop application, not a browser sandbox. It is heavily abused for malware delivery and is a well-known LOLBin. The alert fires on any execution of mshta.exe.
### Investigation:
Alert fields showed the hostname, the full command line including the HTA file path, and the parent process. The HTA file was located in a known internal application directory, not a temp folder, downloads folder, or user profile path — unusual file paths are a strong signal for malicious HTA use.
Checked Sysmon logs: parent process was a legitimate internal application launcher. The HTA was being used as a UI component for an older legacy internal tool that had not been updated to a modern framework — a known pattern in enterprises that still run legacy applications built before HTA fell out of favour.
Checked the HTA file contents directly — plain HTML and VBScript rendering a form interface, no encoded payloads, no network connections, no process spawning. Confirmed with the application owner that this was expected behaviour.
User was a standard business user — no reason to be running admin tools. The execution came from normal use of the legacy application, not direct invocation.
Conclusion: False Positive. Mshta.exe used legitimately by a legacy internal application. Noted that the continued use of HTA-based legacy tooling creates unavoidable detection noise and recommended the application be flagged for modernisation in the next development cycle.


Closing these quickly without documentation would have left no record for the next analyst. Documenting the reasoning is what turns a closed alert into institutional knowledge.
