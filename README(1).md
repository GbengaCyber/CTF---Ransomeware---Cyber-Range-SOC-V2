# 🔐 CTF Writeups — Ashford Sterling Recruitment

A collection of CTF challenge writeups focused on threat hunting, incident response, and forensic investigation using KQL and Microsoft Sentinel / Defender XDR.

---

## 📁 Challenges

| # | Challenge | Difficulty | Category | Status |
|---|-----------|------------|----------|--------|
| 1 | [Akira Ransomware — Ashford Sterling](./challenges/akira-ashford-sterling/writeup.md) | 🔴 Advanced | Ransomware / IR | ✅ Complete |

---

## 🔍 Challenge 1 — Akira Ransomware

> *Following the initial compromise investigated in "The Broker", a ransomware affiliate returned to the environment using pre-staged access and deployed Akira ransomware across the network.*

---

### 📄 Ransom Note

The `akira_readme` file was dropped across all encrypted directories. It contains the TOR negotiation address, victim ID, AES-256 encryption claim, and a 72-hour deadline before data publication.

[![Ransom Note](./challenges/akira-ashford-sterling/ransom_note.png)](./challenges/akira-ashford-sterling/ransom_note.png)

---

### 🗂️ Encrypted File Server

The file server share `C:\Shares\` was fully encrypted. All business-critical folders — Backups, Clients, Compliance, Contractors, and Payroll — were hit with the `.akira` extension appended to every file.

[![Encrypted Files](./challenges/akira-ashford-sterling/encrypted_files.png)](./challenges/akira-ashford-sterling/encrypted_files.png)

---

### 💬 Ransom Negotiation

The victim engaged the threat actor via the TOR-hosted **Akira Secure Chat** portal. Initial demand: **£65,000**. Victim counter: **£11,000**. Attacker issued a 48-hour ultimatum — confirming active double-extortion.

[![Akira Negotiation Chat](./challenges/akira-ashford-sterling/akira_chat.png)](./challenges/akira-ashford-sterling/akira_chat.png)

---

## 🧰 Tools & Stack

- **Query Language:** KQL (Kusto Query Language)
- **Platform:** Microsoft Sentinel / Microsoft Defender XDR
- **Frameworks:** MITRE ATT&CK

---

## 📌 Notes

- IOCs and infrastructure from earlier challenges (*The Broker*) carry over — threat actor reused pre-staged access.
- Each challenge folder contains a `writeup.md` with full analysis and KQL.

---

*Writeups are for educational purposes only.*
