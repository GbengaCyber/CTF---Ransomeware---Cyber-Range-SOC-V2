# 🔐 CTF Writeups — Ashford Sterling Recruitment

A collection of CTF challenge writeups focused on threat hunting, incident response, and forensic investigation using KQL and Microsoft Sentinel / Defender XDR.

---

## 📁 Challenges

| # | Challenge | Difficulty | Category | Status | Artefacts |
|---|-----------|------------|----------|--------|-----------|
| 1 | [Akira Ransomware — Ashford Sterling](./challenges/akira-ashford-sterling/writeup.md) | 🔴 Advanced | Ransomware / IR | ✅ Complete | [Ransom Note](./challenges/akira-ashford-sterling/ransom_note.png) · [Encrypted Files](./challenges/akira-ashford-sterling/encrypted_files.png) · [Negotiation Chat](./challenges/akira-ashford-sterling/akira_chat.png) |

---

## 🔍 Challenge Preview — Akira Ransomware

> *Following the initial compromise investigated in "The Broker", a ransomware affiliate returned to the environment using pre-staged access and deployed Akira ransomware across the network.*

### Ransom Note
[![Ransom Note](./challenges/akira-ashford-sterling/ransom_note.png)](./challenges/akira-ashford-sterling/ransom_note.png)

### Encrypted File Server
[![Encrypted Files](./challenges/akira-ashford-sterling/encrypted_files.png)](./challenges/akira-ashford-sterling/encrypted_files.png)

### Akira Negotiation Chat
[![Akira Chat](./challenges/akira-ashford-sterling/akira_chat.png)](./challenges/akira-ashford-sterling/akira_chat.png)

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
