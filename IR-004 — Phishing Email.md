# IR-004 — Phishing Email with HTML Credential Harvester

## What is this alert?
A suspicious email was flagged by the email security gateway after being delivered to one employee and forwarded to others within the same business unit. The email carried an HTML file attachment and impersonated an internal business communication — crafted well enough to appear contextually relevant to the recipients. The sending domain was new and unrecognised.

## Investigation goals:

Is this a legitimate email or a phishing attempt?
What does the attachment actually do — is there a payload?
Was any employee tricked into interacting with it?


## Investigation
#### Email header analysis — first thing I checked:

SPF, DKIM, DMARC: Checked authentication results in the email headers. SPF failed — the sending IP did not match the authorised senders for the domain. DKIM was absent. DMARC failed as a result. Three authentication failures on a single email is a strong early indicator of spoofing or a newly stood-up malicious domain.
Mail-From vs From alignment: The Mail-From (envelope sender) and the From header did not match — a common technique to make the display name look legitimate while routing replies elsewhere.
Sending IP vs domain: The IP in the headers did not resolve back to the claimed sending domain. Checked the sending IP on VirusTotal — no prior reputation, but the domain was registered recently (days old at time of send), which is a significant flag on its own.

#### Sender domain analysis:
Checked the domain in VirusTotal and URLScan. The domain had no legitimate web presence — no real website, no business content. For a domain claiming to represent a known company, the absence of any web footprint is telling. URLScan showed the domain had only been queried a handful of times, all recently, consistent with a freshly registered phishing domain.
#### Email content review:
The subject and body were well-crafted — referencing the business unit's context, using appropriate terminology, and mimicking the tone of internal communications. The pretext was a salary-related notification asking the recipient to log in via a link or attachment to view their payslip. Social engineering using payroll themes is effective because it creates urgency and employees are less likely to question a message that appears to come from HR or Finance.
#### Attachment analysis — the HTML file:
Previewed the HTML file in a text editor rather than opening it in a browser. This is the safest way to inspect HTML attachments — you see exactly what the code does without executing it.
I scanned the source for known malicious keywords: atob, document.write, <script>, fetch, XMLHttpRequest, and post. Found the following:

A <script> block content revealed a document.write call rendering a fake login form designed to mimic an internal portal — company branding, familiar layout.
On form submission, the credentials were sent via a POST request — not to any internal server but to a Telegram Bot API endpoint, passing the captured username and password directly to an attacker-controlled Telegram chat ID.
No malware dropped, no exploit — purely a credential harvesting page that exfiltrates via Telegram's legitimate API to avoid network-level detection.

#### Link and URL checks:
Ran all URLs found in the decoded content through VirusTotal and URLScan. The Telegram Bot API URL was legitimate infrastructure (Telegram's own domain) — which is exactly why attackers use it, as it rarely gets blocked. The bot token embedded in the script was the attacker's identifier. Noted the token for the incident record.
#### Recipient scope:
Confirmed the email reached one employee initially and was forwarded internally to others in the same business unit. Checked email gateway logs to determine who received it and whether any recipients had opened the attachment. Found one recipient had opened the file — flagged for immediate follow-up.
#### User outreach:
Contacted the recipient who opened the attachment. They had previewed it in the browser and saw what looked like a login page but had not entered credentials. Advised them to treat their account as potentially compromised as a precaution and reset their password.

## Conclusion
True Positive. A well-targeted spearphishing email carrying an HTML credential harvester was delivered to multiple employees in the same business unit. The attachment rendered a convincing fake login portal and was coded to exfiltrate any entered credentials directly to an attacker via the Telegram Bot API — a deliberate choice to bypass traditional network-based exfiltration detection. The attack was caught before credentials were successfully harvested. One employee opened the file but did not submit credentials.
The quality of the social engineering — business-unit-specific context, payroll pretext, convincing visual design — suggests some prior reconnaissance on the target organisation.

## Actions Taken

Email quarantined and pulled from all recipient mailboxes
Sending domain and IP blocked at the email gateway
HTML attachment hash added to the blocklist
Affected recipient's password reset as a precaution
