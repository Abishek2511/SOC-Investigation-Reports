# IR-001 — Pass-the-Hash Attack via Lateral Movement #

## What is this alert?
Pass-the-Hash (PtH) is an attack where an adversary steals an NTLM password hash from memory and uses it to authenticate as that user — without ever knowing the actual password. The SIEM rule fires when it detects multiple network logons (Type 3) using NTLM from a single workstation, with no prior interactive logon (Type 2) for that account on the same machine. That mismatch is the tell.

## Investigation goals:

How did this activity originate — is there a legitimate explanation?
Who was targeted and what did the attacker access?
Did the attacker succeed — was there lateral movement or data access?


## Alert Fields
First thing I looked at: timestamp, source hostname, the account name, authentication protocol, logon type, and destination hosts. The timestamp was in the early hours — a privileged service account authenticating at that hour with no business justification was the first flag.

## Investigation
#### Starting point — Windows Security and Sysmon logs on the source host:
Filtered to +/-2 minutes around the alert timestamp. Key fields I focused on: Event ID, Account Name, Logon Type, Image, Command Line, and ProcessGUID.
No Type 2 (interactive) logon for the account on this machine in the preceding hours — confirming the account was never actually logged in here. That rules out a user sitting at the desk. I also found a suspicious process accessing LSASS with a name masquerading as a legitimate Windows binary — consistent with a credential dumping tool running just before the lateral movement. Sysmon showed SMB connections to destination hosts following immediately after.
#### PowerShell logs:
Checked PS logs in the same window. Found short, encoded command-line activity just before the connections — no named script, no readable purpose. That raised confidence this was attacker tooling rather than a legitimate admin task.
#### Proxy logs:
No outbound web traffic from the source host in this window. The attacker was focused on internal movement, not reaching out to external infrastructure at this stage. That scoped the blast radius to internal access only.
#### Destination host logs:
Confirmed Type 3 logons accepted under the compromised account and directory enumeration on sensitive shared folders. No confirmed write or copy events — access was read-only.
#### Threat intel:
Submitted the hash of the suspicious process to VirusTotal — flagged as a known credential dumping tool by multiple vendors.
#### User context:
The account was a domain admin service account. The assigned user was on approved annual leave at the time — confirmed via HR. Machine was physically unoccupied, ruling out an insider. Checked 90-day alert history: the same endpoint had triggered a low-severity malware alert 48 hours earlier that was closed without full investigation — almost certainly the initial access event that was missed.

## Conclusion
True Positive. An attacker gained initial access to the endpoint two days prior, dumped NTLM hashes from LSASS using a masqueraded process, and used the hash of a domain admin service account to move laterally to internal file servers. Read-only enumeration occurred on sensitive shares. No confirmed exfiltration. A connection attempt to the domain controller was blocked by additional access controls.
The missed prior alert was the real gap — had it been fully investigated at the time, this intrusion would have been caught before lateral movement occurred.
