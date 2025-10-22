# Phishing Email Analysis (Task 2)

## 📋 Task Overview

Analyze a suspicious Microsoft 365 password‑reset email to identify phishing characteristics via header authentication checks, relay path inspection, URL analysis, and social‑engineering review. Produce a concise report with Indicators of Compromise (IoCs).

---

## 🎯 Objectives

* Validate sender authenticity using **SPF**, **DKIM**, and **DMARC**.
* Trace delivery path through `Received:` headers and compare domains for alignment.
* Identify behavioral red flags (urgency, credential requests) and risky URLs (link mismatch/redirectors).
* Produce a concise verdict, IoCs, and recommended actions.

---

## 🛠 Tools Used

* Header analyzer (MXToolbox or equivalent)
* Manual content inspection (hover/preview with URLs)
* URL/Domain reputation lookups (VirusTotal, urlscan.io) — use defanged URLs for sharing

---

## ⚙️ Methodology (summary)

1. **Email sample:** Microsoft 365 “Password Expiring in 24 Hours”
2. **Header analysis:** Parsed Authentication‑Results, SPF/DKIM/DMARC status, Return‑Path, Message‑ID, and Received hops.
3. **Content review:** Checked salutation, urgency, requests for sensitive data, and branding consistency.
4. **Link inspection:** Analyzed embedded URLs for domain manipulation, absence of HTTPS, URL shorteners hiding true destinations, and presence of suspicious attachments.
5. **Social Engineering Detection:** Detected psychological triggers such as urgency, authority impersonation, fear, and loss aversion.
6. **Reporting:** Compiled all findings, including screenshots and header analysis, into a structured report for submission.

---

## 📝 Analyzed Phishing Email Sample

* **From:** `"Microsoft Account Security"` [no-reply@m1crosoft-security.com](mailto:no-reply@m1crosoft-security.com)
* **Subject:** `Action Required: Microsoft 365 Password Expiring in 24 Hours`
* **Theme:** Urgent deadline to reset password; asks for current password and MFA code; CTA displayed as Microsoft-branded link but resolves to a shortened redirect and ultimately a look-alike domain.
---

## 🔍 Phishing Indicators Detected

|                  Indicator |                               Evidence / Example                               | Severity |
| -------------------------: | :----------------------------------------------------------------------------: | :------: |
|          Look-alike domain |             `m1crosoft-security.com` vs legitimate `microsoft.com`             | Critical |
|    Off-brand sending infra |     Sending host `smtp-out.unrelatedsmtp.net`, sending IP `185.203.110.24`     | Critical |
| SPF authentication failure |        `spf=fail` for connecting IP (not authorized for claimed domain)        | Critical |
|   DKIM absent / not signed |                            No DKIM signature present                           | Critical |
|        DMARC not published |     No DMARC record for look-alike domain — receivers cannot enforce policy    | Critical |
|  Link mismatch / shortener |   Displayed Microsoft URL → `bit.ly` redirect → `m1crosoft-security.com`       | Critical |
|     Sensitive data request | Asks for current password and MFA code via email (never requested by legit MS) | Critical |
|  Urgency / threat language |            “Password expiring in 24 hours” — forces immediate action           |   High   |
|           Generic greeting |                         “Dear User” — not personalized                         |  Medium  |
|  Grammar / branding errors |    Slight branding/formatting inconsistencies (logo/email template oddities)   |  Medium  |

---

## 🔐 Email Header Analysis (highlights)

* **SPF:** Fail — connecting IP is not authorized to send mail for `m1crosoft-security.com`.
* **DKIM:** None — message lacks a valid DKIM signature.
* **DMARC:** No DMARC record published — domain cannot be policy-enforced.
* **Received path:** Hops indicate non-Microsoft MTAs and a delivery path consistent with third-party/outsourced sending.
* **Sending IP / host:** `185.203.110.24` / `smtp-out.unrelatedsmtp.net` (not Microsoft infrastructure).
* **Verdict from headers:** Technical authentication failures + off-brand relay = strong indicator of spoofing.

---

## 🚀 Key Takeaways

* Multiple technical failures (SPF fail, no DKIM, no DMARC) combined with behavioral red flags (urgent timeline, requests for password/MFA) lead to a **high-confidence phishing classification**.
* Always treat password/MFA requests via email as malicious. Legitimate providers never ask for both in email.
* Defang URLs and publish IoCs for detection/hunting rather than for interaction.

---

## 🛡 Recommended Actions

1. **Do not click** any links or reply. Keep all artifacts defanged (e.g., `m1crosoft-security.com`).
2. **Report** the message via organizational phishing reporting channels and mark it as phishing in the mail client.
3. **Block / blacklist** the malicious sending domain and IP at gateway/firewall (verify logs to avoid false positives).
4. **If credentials were submitted:** Immediately change the password at `https://account.microsoft.com` by manually typing the address, revoke sessions, re-enroll MFA, and audit sign-in activity.
5. **Hunt** mail logs for IoCs in `phishingindicators.txt` and remove similar messages.
6. **Educate** users about spotting look-alike domains and never entering MFA or password values in response to email.

---

## 📂 Repository Content

```
cybersecurity-task2-phishing-mail-microsoft/
├── README.md                   # This file (Microsoft analysis)
├── phishingemail.txt           # De-weaponized email body (defanged URLs)
├── phishemailheaders.txt       # Raw headers used for analysis
├── analysisreport.txt          # Full technical + behavioral findings and verdict
├── phishingindicators.txt      # One-line IoCs and red flags (defanged)
└── image.png                   # Screenshots of header analyzer outputs (auth results & hops)
```
