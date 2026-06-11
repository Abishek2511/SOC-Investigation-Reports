# IR-002 — Outbound RDP from Native Windows Client

## What is this alert?
This alert fires when mstsc.exe — the native Windows RDP client — establishes an outbound connection on port 3389 to a destination outside the expected internal subnet range. RDP is a common path for lateral movement and remote access, so outbound connections to non-standard destinations get scrutinised regardless of which process initiates them.

## Investigation goals:

Is this a legitimate admin action or an attacker using a built-in tool to blend in?
Where is the connection going — is that destination known and authorised?
Does the user's role and behaviour support or contradict this activity?


## Alert Fields
First thing I looked at: timestamp, source hostname, the process name, destination IP, and port. Business hours, a named admin workstation, and a native Windows binary — already pointing toward legitimate, but that still needed confirming.

## Investigation
First step — alert backlog:
Before opening any logs I checked whether this alert had fired before for the same source and destination. Found prior instances in the last 60 days, all closed as false positives with notes confirming the user manages remote infrastructure. That context shaped my approach but didn't close the investigation — I still needed to verify independently.
#### Windows Sysmon logs on the source host:
Filtered to +/-2 minutes around the alert timestamp. Key fields: Image, Command Line, Parent Image, ProcessGUID, and network connection details.
Two minutes before the RDP session, powershell.exe ran a Test-NetConnection command targeting the same destination IP on port 3389. The script had a proper name, no encoding, no obfuscation — a sysadmin checking if RDP is reachable before opening a session. Completely normal pre-flight behaviour. mstsc.exe then launched from explorer.exe as expected for a user-initiated application — no unusual parent process.
#### PowerShell logs:
Checked PS operational logs in the same window. Clean, readable command — standard connectivity check. Nothing suspicious in the payload. This lowered my suspicion significantly.
#### Proxy logs:
No unusual outbound web traffic from this host in the window. No beaconing, no unexpected destinations.
#### User context:
Confirmed the user is a Systems Administrator with documented authorisation for remote management of the destination subnet. Checked whether this type of activity appeared in their history — yes, regularly. Also found an open change ticket for scheduled maintenance on the destination server that afternoon, which directly explained the session.

## Conclusion
False Positive. Every signal supported legitimate admin activity: a named PS connectivity check ahead of the session, mstsc.exe launched normally, the destination confirmed as a known corporate server, the user's role explicitly authorising this action, and an open change ticket matching the time and target. No indicators of malicious use.
The alert was firing repeatedly because the remote management subnet had not been added to the rule's allowlist — causing the same legitimate activity to generate alerts on a regular basis.

## Actions Taken

Alert closed as false positive with full investigation notes documented
Recommended the remote management subnet be added to the RDP allowlist for admin-designated workstations
Escalated alert tuning request to detection engineering
