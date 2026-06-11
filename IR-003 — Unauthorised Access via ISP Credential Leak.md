# IR-003 — Unauthorised Access via ISP Credential Leak

## What is this alert?
This alert fires when an account logs in outside its established behavioural baseline — specifically a combination of after-hours login and access to resources the account has never previously touched. It is a UEBA rule, not a signature-based detection. It catches threats that don't trigger traditional rules precisely because the attacker is using valid credentials through a legitimate access path.

## Investigation goals:

Was this the legitimate user, or is someone else using their credentials?
What did they access — is there any indication of data theft?
If it is an attacker — how did they obtain the credentials?


## Alert Fields
First thing I looked at: timestamp, the account, login method, and source IP. Two flags stood out immediately — the login was in the early hours outside the user's normal pattern, and the source IP geolocated to a region inconsistent with the user's work location.

## Investigation
#### Starting point — establishing whether this was the real user:
Before touching logs I checked the 90-day VPN login history for the account. Every previous session came from a consistent residential IP range matching the user's location. The session in question was a clear outlier geographically. I checked the source IP on VirusTotal and AbuseIPDB — flagged in threat intel feeds as associated with credential stuffing campaigns. At this point I was already treating this as a compromised account.
#### SSO and application access logs:
The user's normal pattern is accessing a handful of known pages within their own business unit. This session touched several different system areas across the organisation — including HR, a separate business unit's project tool, and an IT admin portal — with multiple access-denied events where the account lacked permissions. That pattern of hitting permission walls across unrelated systems is classic enumeration, not how a Finance Analyst navigates their working day.
#### Sysmon logs on the user's corporate machine:
No activity on the corporate endpoint during the session window. The attacker was operating entirely from their own device over VPN — the corporate laptop was not involved.
#### Proxy logs:
Reviewed outbound traffic under the session. Rapid navigation across internal URLs with no referrers, no large outbound transfers, no connections to external file-sharing services. Consistent with internal enumeration — no exfiltration indicators found.
#### Threat intel:
Source IP confirmed malicious on VirusTotal — associated with account takeover activity. No file hashes to check as this was credential-based access only.
#### User context and outreach:
Contacted the user's line manager — confirmed the user had no reason to be active at that hour. Spoke to the user directly. They had received a breach notification from their home ISP a few weeks prior but had not acted on it. Their personal laptop — on the same home Wi-Fi — had corporate VPN credentials saved in the browser's password manager with sync enabled. The Google account used to sync those credentials shared a password with the home Wi-Fi, which was exposed in the ISP breach. That was the full chain.

## Conclusion
True Positive. The attacker obtained corporate VPN credentials through a chain starting at the home ISP breach — exposed Wi-Fi credentials led to access to a home network where corporate passwords were stored in a synced browser with no MFA protecting the VPN. The attacker authenticated as a valid user, spent time enumerating internal systems, and repeatedly hit permission boundaries without breaking through to sensitive data. No confirmed exfiltration.
The single control that would have stopped this entirely was MFA on VPN access. Valid credentials alone would not have been sufficient.

## Actions Taken

VPN credentials revoked immediately, reissued only after MFA enrolment
All active SSO sessions force-terminated
Source IP added to VPN block list
Relevant teams notified — accessed resources reviewed, no exfiltration confirmed
User advised to change home Wi-Fi credentials and remove corporate passwords from personal device browsers
