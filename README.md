# Akira Ransomware — Ashford Sterling Recruitment


---

## Challenge Info

| Field | Details |
|-------|---------|
| **Organisation** | Ashford Sterling Recruitment |
| **Difficulty** | 🔴 Advanced |
| **Category** | Ransomware / Incident Response |
| **Linked Challenge** | The Broker (prior compromise — pre-staged access reused) |
| **Threat Actor** | Akira Ransomware Affiliate |
| **Status** | ✅ Complete |

---

## Incident Brief

> *Following the initial compromise investigated in "The Broker", a ransomware affiliate has returned to the environment using pre-staged access. The threat actor has deployed Akira ransomware across the network.*
>
> *Each section must be completed before the next one unlocks. Work through the attack chain in order. This is a hard challenge — take your time.*

---

## Scope of Impact

### Ransom Note

The `akira_readme` file was dropped across all encrypted directories. It contains the TOR negotiation address, victim ID, AES-256 encryption claim, and a 72-hour deadline before data publication.

<img width="600" height="600" alt="image" src="https://github.com/user-attachments/assets/a5b08898-fd0e-464e-9cbd-d6c0865ac22e" />


---

### Encrypted File Server

The file server share `C:\Shares\` was fully encrypted. All business-critical folders — Backups, Clients, Compliance, Contractors, and Payroll — were hit with the `.akira` extension appended to every file. Encryption timestamp: `1/27/2026 22:18 UTC`.


<img width="600" height="600" alt="image" src="https://github.com/user-attachments/assets/c8f24116-b8ff-4abc-9f82-271dde465e97" />

---

### Ransom Negotiation

The victim engaged the threat actor via the TOR-hosted **Akira Secure Chat** portal. Initial demand: **£65,000**. Victim counter: **£11,000**. Attacker issued a 48-hour ultimatum — confirming active double-extortion.
<img width="560" height="500" alt="image" src="https://github.com/user-attachments/assets/87496e35-e69a-4bd5-abc2-ba463921f5ca" />

---

## Investigation

---

### 🚩 Q1 — Threat Actor
**Format:** Group name
**What ransomware group is responsible?**

**Answer:** `Akira`

The ransom note was delivered via a TOR-based chat portal branded **"Akira Secure Chat"**. The portal, initial demand of £65,000, victim counter of £11,000, and negotiation style are consistent with known Akira ransomware affiliate operations. Identified from artefact — no KQL required.

---

### 🚩 Q2 — Negotiation Portal
**Format:** onion address (without http://)
**What is the TOR negotiation address?**

**Answer:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

The TOR address was found in the `akira_readme` ransom note dropped on the victim system. The note also contained a victim-specific Personal ID, AES-256 encryption claim, and a 72-hour deadline before data publication. Identified from artefact — no KQL required.


---

### 🚩 Q3 — Victim ID
**Format:** ID string
**What is the company's unique ID?**

**Answer:** `813R-QWJM-XKIJ`

Found in the `akira_readme` ransom note under `Your personal ID`. Akira uses this identifier to link the victim to their negotiation session on the TOR portal. Identified from artefact — no KQL required.

---

### 🚩 Q4 — Encrypted Extension
**Format:** Extension
**What file extension is added to encrypted files?**

**Answer:** `.akira`

Confirmed from the ransom note and file listing screenshots. Files under `C:\Shares\` all showed Type: **AKIRA File** with the `.akira` extension appended. Encryption timestamp: `1/27/2026 22:18 UTC`.

---

### 🚩 Q5 — Payload Domain
**Format:** Domain
**What domain hosted the payloads?**

**Answer:** `sync.cloud-endpoint.net`

**`1/27/2026  20:22:26 UTC` — `as-pc2` — `david.mitchell`**

`DeviceNetworkEvents` was queried for outbound connections from common download utilities. `wsync.exe` and `powershell.exe` on `as-pc2` made repeated connections to `sync.cloud-endpoint.net` starting from the initial staging date. This domain served as the primary C2 and payload delivery point throughout the attack.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27 20:00:00) .. datetime(2026-01-27 23:00:00 ) )
| where DeviceName == "as-pc2"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessAccountDomain != "nt authority" and isnotempty( RemoteUrl)
| project TimeGenerated, ActionType, RemoteUrl
| order by TimeGenerated asc 
```
<img width="700" height="371" alt="image" src="https://github.com/user-attachments/assets/6ef27cc3-3467-42d1-9ff4-8223f6ed5e2f" />

---

### 🚩 Q6 — Ransomware Staging Domain
**Format:** Domain
**What domain staged the ransomware?**

**Answer:** `cdn.cloud-endpoint.net`

**`1/27/2026 22:18:22.UTC`  `as-srv`**

Reviewing `DeviceNetworkEvents` for C2 infrastructure, a second domain `cdn.cloud-endpoint.net` was identified. Used specifically for staging and delivering the ransomware payload to `as-srv` in the final phase of the attack.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27 20:00:00) .. datetime(2026-01-27 23:00:00 ) )
| where DeviceName == "as-srv"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessAccountDomain != "nt authority" and isnotempty( RemoteUrl)
| project TimeGenerated, ActionType, RemoteUrl
| order by TimeGenerated asc 
```
<img width="700" height="400" alt="image" src="https://github.com/user-attachments/assets/2c753cc3-77c3-4964-8980-7a4102ee7e73" />

---

### 🚩 Q7 — C2 IP Addresses
**Format:** Comma separated, any order
**What are the two C2 IP addresses?**

**Answer:** `104.21.30.237, 172.67.174.46`

Both C2 domains resolved to two IPs throughout the attack. Observed in connection logs across `as-pc2` and `as-srv` during payload delivery and beacon C2 communications.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27 20:00:00) .. datetime(2026-01-27 23:00:00 ) )
| where ActionType == "ConnectionSuccess"
| where DeviceName contains "as-srv"
| where RemoteUrl has_any ("cdn.cloud-endpoint.net", "sync.cloud-endpoint.net")
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```
<img width="699" height="400" alt="image" src="https://github.com/user-attachments/assets/ba0e53e3-d125-4714-8237-a35486f0aba2" />

---

### 🚩 Q8 — Remote Tool Relay
**Format:** Domain
**What domain did the remote access tool route through?**

**Answer:** `relay-0b975d23.net.anydesk.com`

**`1/27/2026 22:08 UTC` — `as-srv`**

AnyDesk relay connections reviewed across all compromised hosts. `relay-0b975d23.net.anydesk.com` was the last relay connection on `as-srv` — active 10 minutes before ransomware deployment, confirming the attacker maintained remote access right up to encryption.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-27 20:00:00) .. datetime(2026-01-27 23:00:00 ) )
| where ActionType == "ConnectionSuccess"
| where RemoteUrl contains "relay"
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP
```
<img width="700" height="348" alt="image" src="https://github.com/user-attachments/assets/66fb556f-f861-418a-9f99-d5b02aceba49" />

---

### 🚩 Q9 — Evasion Script
**Format:** Filename
**What script disabled security?**

**Answer:** `kill.bat`

**`1/27/2026 21:02 UTC` `as-pc2`  `david.mitchell`**

`DeviceFileEvents` queried for `.bat` files on compromised hosts. `kill.bat` was downloaded from `sync.cloud-endpoint.net/kill.bat` via `bitsadmin` and executed to disable Windows Defender and delete shadow copies before ransomware deployment.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27 18:00:00) .. datetime(2026-01-27 23:00:00))
| where DeviceName has_any ("as-pc2", "as-srv")
| where FileName endswith ".bat"
| project TimeGenerated, ActionType, FileName
```
<img width="699" height="347" alt="image" src="https://github.com/user-attachments/assets/96565df9-6319-4842-8eb9-a4afb7e1a1a4" />

---

### 🚩 Q10 — Evasion Hash
**Format:** SHA256 hash
**What is the SHA256 of the evasion script?**

**Answer:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

SHA256 of `kill.bat` retrieved from `DeviceFileEvents`. Dropped by `wsync.exe` on `as-pc2` under `david.mitchell`.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27 18:00:00) .. datetime(2026-01-27 23:00:00))
| where DeviceName has_any ("as-pc2", "as-srv")
| where FileName endswith ".bat"
| project TimeGenerated, ActionType, FileName, SHA256
```
<img width="900" height="361" alt="image" src="https://github.com/user-attachments/assets/2771fb8e-d150-46ba-a59f-04f0c31e4414" />

---

### 🚩 Q11 — Registry Tampering
**Format:** Registry value name
**What registry value disabled Windows Defender?**

**Answer:** `DisableAntiSpyware`

Windows Defender disabled via registry modification setting `DisableAntiSpyware = 1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`. Part of the defence evasion sequence before credential theft and ransomware deployment.

---

### 🚩 Q12 — Registry Timestamp
**Format:** HH:MM:SS (UTC)
**What time was the registry modified?**

**Answer:** `21:03:42`

**`1/27/2026 21:03 UTC` — `as-pc2`**

`DeviceRegistryEvents` filtered for Defender-related registry modifications. `DisableAntiSpyware` set to `1` via `reg add` at `21:03:42` — approximately 75 minutes before encryption.

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-01-27 20:00:00) .. datetime(2026-01-28 23:00:00))
| where DeviceName == "as-pc2"
| where ActionType == "RegistryValueSet"
| where InitiatingProcessAccountName != "nt authority"
| where InitiatingProcessCommandLine has_any ("defender", "exclusion")
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, RegistryValueData, RegistryValueName
| order by TimeGenerated desc
```
<img width="700" height="300" alt="image" src="https://github.com/user-attachments/assets/85310041-4d73-4468-8f9c-f087ebf16c4f" />

---

### 🚩 Q13 — Process Hunt
**Format:** Full command
**What command was used to enumerate processes for credential theft?**

**Answer:** `tasklist | findstr lsass`

**`1/27/2026 21:14 UTC` — `as-pc2` — `david.mitchell`**

`DeviceProcessEvents` queried for process enumeration commands. `wsync.exe` spawned `cmd.exe` which ran `tasklist | findstr lsass` twice — at `21:11` and `21:14` — confirming the attacker was locating LSASS before credential dumping.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27 21:00:00) .. datetime(2026-01-27 22:00:00))
| where DeviceName has_any ("as-pc2", "as-srv")
| where AccountDomain != "nt authority"
| where InitiatingProcessCommandLine has_any ("tasklist", "Get-Process lsass")
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="767" height="435" alt="image" src="https://github.com/user-attachments/assets/990dc838-60f2-49b1-85c6-dbee6833d4bf" />

---

### 🚩 Q14 — Credential Pipe
**Format:** Full pipe path
**What named pipe was accessed during credential theft?**

**Answer:** `\Device\NamedPipe\lsass`

**`1/27/2026 21:42 UTC` — `as-pc2`**

`DeviceEvents` filtered for `NamedPipeEvent` actions referencing `lsass`. The pipe `\Device\NamedPipe\lsass` was accessed on `as-pc2` at `21:42` — following process enumeration at `21:11/21:14` — consistent with credential dumping against LSASS.

```kql
DeviceEvents
| where DeviceName in~ ("as-srv", "as-pc2")
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has_any ("lsass", "samr", "netlogon", "protected_storage")
| project Timestamp, DeviceName, AccountName, AdditionalFields, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="700" height="380" alt="image" src="https://github.com/user-attachments/assets/297cce29-cf4e-48a1-a96e-be1e2d9f1717" />

---

### 🚩 Q15 — Remote Access Tool
**Format:** Tool name
**What remote access tool was used?**

**Answer:** `AnyDesk`

AnyDesk relay connections identified across `as-srv`, `as-pc1`, and `as-pc2`. Pre-staged during *The Broker* compromise and reused 12 days later to re-enter the environment without re-exploitation.


```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15 03:00:00) .. datetime(2026-01-28 23:00:00))
| where DeviceName == "as-pc2" and RequestAccountName == "David.Mitchell"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc

```
---

### 🚩 Q16 — Suspicious Execution Path
**Format:** Full directory path
**What directory was the remote access tool executed from?**

**Answer:** `C:\Users\Public`

**`1/15/2026 04:40 UTC` — `as-pc2`**

`DeviceFileEvents` queried for `AnyDesk.exe`. The binary was dropped into `C:\Users\Public\` — a world-writable directory — rather than the legitimate install path, confirming manual staging by the attacker.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15 03:00:00) .. datetime(2026-01-28 23:00:00))
| where DeviceName == "as-pc2" and RequestAccountName == "David.Mitchell"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="848" height="395" alt="image" src="https://github.com/user-attachments/assets/67297c76-f39c-4c2c-beb7-ce6a570b7d17" />

---

### 🚩 Q17 — Attacker IP
**Format:** IP address
**What is the attacker's external IP?**

**Answer:** `88.97.164.155`

**`1/27/2026 19:29 UTC` — `as-pc2` — `david.mitchell`**

AnyDesk network connections on `as-pc2` reviewed. Most traffic resolved to known AnyDesk relay infrastructure. Two connections had no `RemoteUrl` — raw IP only — indicating inbound connections. Both resolved to `88.97.164.155`, confirming this as the attacker's external IP.

```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15 03:00:00) .. datetime(2026-01-27 23:00:00))
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteIPType == "Public"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, DeviceName
| sort by Timestamp desc
```
<img width="700" height="323" alt="image" src="https://github.com/user-attachments/assets/77e39c31-0e0d-4290-83e5-7df3d67612f4" />

---

### 🚩 Q19 — Primary Beacon
**Format:** Filename
**What new C2 beacon was deployed?**

**Answer:** `wsync.exe`

**`1/27/2026 20:22 UTC` — `as-pc2`**

`DeviceFileEvents` queried for executables dropped into staging directories. `wsync.exe` dropped into `C:\ProgramData\` by `powershell.exe`. Masquerades as a Windows sync utility — responsible for all C2 comms, payload delivery, and spawning attacker commands.

```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FolderPath has_any ("ProgramData", "Temp", "Public", "Downloads")
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="700" height="318" alt="image" src="https://github.com/user-attachments/assets/e00ec500-5c93-4a0d-bdf3-45e83ab93b97" />

---

### 🚩 Q20 — Beacon Location
**Format:** Full directory path
**What directory was the new beacon deployed to?**

**Answer:** `C:\ProgramData`

**`1/27/2026 20:22 UTC` — `as-pc2`**

Confirmed from Q19 query. `wsync.exe` consistently written to `C:\ProgramData\wsync.exe` across all three drop events.


<img width="700" height="318" alt="image" src="https://github.com/user-attachments/assets/743361b1-ca5b-4d65-a184-039d4c756b92" />

---

### 🚩 Q21 — Beacon Hash (Original)
**Format:** SHA256 hash
**What is the SHA256 of the original beacon?**

**Answer:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

**`1/27/2026 20:22 UTC` — `as-pc2`**

Three drops of `wsync.exe` observed. The first at `20:22` carried a different SHA256 — the original beacon that failed to maintain stable C2 communications.

---

### 🚩 Q22 — Beacon Hash (Replacement)
**Format:** SHA256 hash
**What is the SHA256 of the replacement beacon?**

**Answer:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`

**`1/27/2026 20:44 UTC` — `as-pc2`**

Replacement beacon dropped at `20:44` with a different SHA256. This version maintained stable C2 and drove all subsequent attack activity.

```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName == "wsync.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| order by Timestamp asc
```
<img width="900" height="361" alt="image" src="https://github.com/user-attachments/assets/333c7103-3ea1-4613-b411-5882bab95708" />

---

### 🚩 Q23 — Scanner Tool
**Format:** Filename
**What scanner tool was used?**

**Answer:** `scan.exe`

**`1/27/2026 20:17 UTC` — `as-pc2` — `david.mitchell`**

`DeviceFileEvents` filtered for executables in user directories. `scan.exe` downloaded to `C:\Users\david.mitchell\Downloads\` — an NSIS self-extracting installer that unpacked Advanced IP Scanner for network reconnaissance.

```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName contains "scan"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp desc
```
<img width="763" height="274" alt="image" src="https://github.com/user-attachments/assets/db0f7a45-4288-4bcc-b982-53a75a402c27" />

---

### 🚩 Q24 — Scanner Hash
**Format:** SHA256 hash
**What is the SHA256 of the scanner?**

**Answer:** `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b`

SHA256 of `scan.exe` retrieved from `DeviceFileEvents`.

```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName == "scan.exe"
| project Timestamp, DeviceName, FileName, SHA256
| order by Timestamp desc
```
<img width="750" height="340" alt="image" src="https://github.com/user-attachments/assets/d724af60-05ea-40ca-a6f4-d1910fb9e3cd" />

---

### 🚩 Q25 — Scanner Execution Arguments
**Format:** Full arguments as executed
**What arguments were passed to the scanner?**

**Answer:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

**`1/27/2026 20:17 UTC` — `as-pc2` — `david.mitchell`**

`scan.exe` showed no arguments directly. Child process analysis: `scan.exe` → `scan.tmp` (NSIS extractor) → `advanced_ip_scanner.exe` with `/portable` flag — avoiding installation to leave minimal forensic trace.

```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-27T20:15:00Z) .. datetime(2026-01-27T21:00:00Z))
| where FileName =~ "advanced_ip_scanner.exe"
    or InitiatingProcessFileName =~ "advanced_ip_scanner.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="740" height="400" alt="image" src="https://github.com/user-attachments/assets/6ec4feaf-8266-4b4f-b0ba-3c54c73c36bf" />

---

### 🚩 Q26 — Network Enumeration
**Format:** Comma separated, any order
**What two internal IPs were enumerated?**

**Answer:** `10.1.0.154, 10.1.0.183`

**`1/27/2026 22:17 UTC` — `as-srv`**

`DeviceNetworkEvents` filtered for SMB (port 445) connections to internal IPs, excluding bulk scanner traffic. Two targeted connections from `as-srv` at `22:17` — 2 minutes before encryption — identified `as-pc1` (`10.1.0.154`) and `as-pc2` (`10.1.0.183`). Confirmed by `net view` commands in process logs.

```kql
DeviceNetworkEvents
| where DeviceName in~ ("as-srv", "as-pc1", "as-pc2")
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where RemotePort == 445
| where RemoteIP startswith "10."
| where InitiatingProcessFileName !~ "advanced_ip_scanner.exe"
| where InitiatingProcessFileName !~ "ntoskrnl.exe"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="818" height="384" alt="image" src="https://github.com/user-attachments/assets/6846924d-4852-40a9-9e06-311ada0b8faf" />

---

### 🚩 Q27 — Lateral Account
**Format:** Username
**What account was used to authenticate to AS-SRV?**

**Answer:** `as.srv.administrator`

Compromised admin account used for all attacker activity on `as-srv`. 

```kql
DeviceLogonEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27 18:00:00) .. datetime(2026-01-27 23:00:00))
| where ActionType == "LogonSuccess"
| order by TimeGenerated asc
```
<img width="611" height="339" alt="image" src="https://github.com/user-attachments/assets/e6567863-8122-4462-a08c-596f08fb375b" />

---

### 🚩 Q28 — Download Method
**Format:** File name
**What LOLBIN was first used to download tools?**

**Answer:** `bitsadmin.exe`

**`1/27/2026 20:14 UTC` — `as-pc2` — `david.mitchell`**

`DeviceProcessEvents` filtered for LOLBIN download commands. `bitsadmin.exe` failed multiple times — doubled destination path, non-existent `C:\Temp\` — before succeeding on the fourth attempt to `Downloads\`.

```kql
DeviceProcessEvents
| where DeviceName in~ ("as-srv", "as-pc2")
| where TimeGenerated between (datetime(2026-01-27 18:00:00) .. datetime(2026-01-27 23:00:00))
| where ProcessCommandLine has_any ("DownloadFile", "Invoke-WebRequest", "iwr", "bitsadmin", "certutil")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="882" height="232" alt="image" src="https://github.com/user-attachments/assets/b7c592f7-9f04-4abe-a552-f0f98b5d84e6" />

---

### 🚩 Q29 — Fallback Method
**Format:** Cmdlet name
**What PowerShell cmdlet was used as the fallback?**

**Answer:** `Invoke-WebRequest`

After `bitsadmin` issues, the attacker switched to `Invoke-WebRequest`. Used across `as-pc2` and `as-srv` to download `wsync.exe`, `updater.exe`, `st.exe`, and `clean.bat`. URL obfuscation observed — domain splitting, base64 encoding, and variable splitting.

```kql

```

---

### 🚩 Q30 — Staging Tool
**Format:** Filename
**What staging tool compressed the data?**

**Answer:** `st.exe`

**`1/27/2026 22:24:09 UTC` — `as-srv`**

`DeviceFileEvents` queried for archive creation. `st.exe` created `exfil_data.zip` at `C:\Users\Public\` — 6 minutes after encryption — staged for exfiltration.

```kql
DeviceFileEvents
| where DeviceName has_any ("as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName has_any (".rar", ".zip", ".7z")
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```
<img width="792" height="310" alt="image" src="https://github.com/user-attachments/assets/a83e33a5-aa2d-497a-9ad6-f69bae9c3da4" />

---

### 🚩 Q31 — Staging Hash
**Format:** SHA256 hash
**What is the SHA256 of the staging tool?**

**Answer:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

SHA256 of `st.exe` retrieved via `InitiatingProcessSHA256`.

```kql
DeviceFileEvents
| where DeviceName has_any ("as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27 20:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName has_any (".rar", ".zip", ".7z")
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessSHA256
| order by Timestamp desc
```
<img width="900" height="313" alt="image" src="https://github.com/user-attachments/assets/4a653493-22ad-488a-a308-8a19ab837f6e" />

---

### 🚩 Q32 — Exfil Archive
**Format:** Filename
**What archive was created for exfiltration?**

**Answer:** `exfil_data.zip`

**`1/27/2026 22:24:09 UTC` — `as-srv`**

`st.exe` created `exfil_data.zip` in `C:\Users\Public\`. Exfiltrated to `sync.cloud-endpoint.net` via `Invoke-WebRequest` POST at `22:24:55`.

```kql
DeviceFileEvents
| where DeviceName has_any ("as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27 20:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName has_any (".rar", ".zip", ".7z")
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessSHA256
| order by Timestamp desc
```
<img width="789" height="312" alt="image" src="https://github.com/user-attachments/assets/c9a9a5d3-5e41-411f-a76c-fe2cf06d765d" />

---

### 🚩 Q33 — Ransomware Filename
**Format:** Filename
**What is the ransomware filename?**

**Answer:** `updater.exe`

**`1/27/2026 22:18:29 UTC` — `as-srv`**

`DeviceProcessEvents` reviewed around the encryption timestamp. `updater.exe` executed from `C:\ProgramData\` by `powershell.exe`. Named to blend with the legitimate Google Updater process on the same host. Immediately spawned `wevtutil.exe` to clear five Windows event logs.

```kql
DeviceProcessEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27 22:00:00) .. datetime(2026-01-27 23:00:00))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="800" height="334" alt="image" src="https://github.com/user-attachments/assets/e8c578cf-208f-4c1c-9805-39c481d6e414" />

---

### 🚩 Q34 — Ransomware Hash
**Format:** SHA256 hash
**What is the SHA256 of the ransomware?**

**Answer:** `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

SHA256 of `updater.exe` retrieved via `InitiatingProcessSHA256` — confirmed across five `wevtutil.exe` child processes sharing the same parent hash.

```kql
DeviceProcessEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:15:00Z) .. datetime(2026-01-27T22:20:00Z))
| where InitiatingProcessFileName contains "updater.exe"
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, InitiatingProcessSHA256
| order by Timestamp asc
```
<img width="900" height="240" alt="image" src="https://github.com/user-attachments/assets/2132faea-6f95-4533-82ee-88f8bb64cdc0" />

---

### 🚩 Q35 — Ransomware Staging
**Format:** Process name
**What process staged the ransomware on AS-SRV?**

**Answer:** `powershell.exe`

**`1/27/2026 22:15 UTC` — `as-srv`**

`DeviceFileEvents` filtered for `FileCreated` in the encryption window confirmed `powershell.exe` staged `updater.exe` into `C:\ProgramData\` immediately before execution.

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:15:00Z) .. datetime(2026-01-27T22:20:00Z))
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="900" height="300" alt="image" src="https://github.com/user-attachments/assets/4d459357-f296-4750-b466-1cd0a051be6d" />

---

### 🚩 Q36 — Recovery Prevention
**Format:** Full command
**What command was used to delete backup copies?**

**Answer:** `vssadmin  delete shadows /all /quiet`

**`1/27/2026 21:09 UTC` — `as-pc2` — `david.mitchell`**

Three recovery prevention commands executed in rapid succession via `cmd.exe` as part of `kill.bat`: `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, and `bcdedit /set {default} recoveryenabled No`. All shadow copies deleted and Windows Recovery disabled before ransomware deployment.

```kql
DeviceProcessEvents
| where DeviceName in~ ("as-srv", "as-pc2")
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="900" height="350" alt="image" src="https://github.com/user-attachments/assets/a3410af9-79f4-4885-9b42-f1c2a3d7543b" />

---

### 🚩 Q37 — Ransom Note Origin
**Format:** Process name
**What process dropped the ransom note?**

**Answer:** `updater.exe`

**`1/27/2026 22:18:33 UTC` — `as-srv`**

`DeviceFileEvents` filtered for `.txt` creation. `updater.exe` dropped `akira_readme.txt` four times at `22:18:33` — 4 seconds after execution — confirming the ransomware handles both encryption and ransom note delivery.

```kql
DeviceFileEvents
| where DeviceName in~ ("as-srv", "as-pc1", "as-pc2")
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where FileName endswith ".txt"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName
| order by Timestamp asc
```
<img width="833" height="301" alt="image" src="https://github.com/user-attachments/assets/9de598fd-abed-479e-a7bd-ef6092b8def8" />

---

### 🚩 Q38 — Encryption Start
**Format:** HH:MM:SS (UTC)
**What time was the ransom note dropped?**

**Answer:** `22:18:33`

Identified from Q37 query. `akira_readme.txt` first created at `22:18:33 UTC`, 4 seconds after `updater.exe` execution at `22:18:29`.

---

### 🚩 Q39 — Cleanup Script
**Format:** Filename
**What script deleted the ransomware?**

**Answer:** `clean.bat`

**`1/27/2026 22:20:27 UTC` — `as-srv`**

`DeviceProcessEvents` reviewed post-encryption. `powershell.exe` executed `cmd.exe /c C:\ProgramData\clean.bat` at `22:20:27` — 2 minutes after ransomware execution. Downloaded earlier as `kill.bat`, responsible for removing `updater.exe` and other artefacts.

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:18:00Z) .. datetime(2026-01-28T00:00:00Z))
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
<img width="748" height="269" alt="image" src="https://github.com/user-attachments/assets/65413bcc-ce1d-4cc8-a8d2-ea20bc798f26" />

---

### 🚩 Q40 — Affected Hosts
**Format:** Hostnames, comma separated, any order
**What hosts were compromised?**

**Answer:** `as-srv, as-pc2`

`as-pc2` was the primary staging host under `david.mitchell`. `as-srv` was the target — file server where ransomware deployed and `C:\Shares\` encrypted. `as-pc1` showed AnyDesk pre-staging and lateral movement artefacts.

---

## Attack Timeline

### Phase 1 — Initial Compromise (The Broker) — 1/15/2026

| Time (UTC) | Host | Event |
|------------|------|-------|
| `03:47` | as-srv | `cdn.cloud-endpoint.net` contacted — C2 active |
| `04:08` | as-pc1 | AnyDesk downloaded |
| `04:10` | as-pc1 | AnyDesk bootstrap → `37.59.29.33` |
| `04:24` | as-pc1 | `live.sysinternals.com` — Sysinternals tools downloaded |
| `04:39` | as-pc2 | Successful logon from `10.1.0.154` — lateral movement |
| `04:40` | as-pc2 | `AnyDesk.exe` dropped to `C:\Users\Public\` |
| `04:41` | as-pc2 | Attacker connects from `88.97.164.155` via AnyDesk |
| `04:52` | as-pc2 | `sync.cloud-endpoint.net` contacted — C2 beacon active |
| `04:55` | as-srv | Successful logon from `10.1.0.183` — lateral movement to server |
| `04:57` | as-srv | AnyDesk downloaded and bootstrapped |

### Phase 2 — Pre-Ransomware Staging — 1/27/2026

| Time (UTC) | Host | Event |
|------------|------|-------|
| `19:12` | as-pc1 | AnyDesk relay active — attacker re-enters environment |
| `19:21` | as-pc2 | AnyDesk relay active |
| `19:25` | as-srv | AnyDesk relay active — attacker on file server |
| `19:29` | as-pc2 | Attacker inbound from `88.97.164.155` via AnyDesk |
| `20:10` | as-pc2 | `\Device\NamedPipe\lsass` accessed — early recon |
| `20:14` | as-pc2 | `bitsadmin` attempts download of `scan.exe` — fails x3 |
| `20:17` | as-pc2 | `scan.exe` downloaded — Advanced IP Scanner executed |
| `20:22` | as-pc2 | `wsync.exe` v1 dropped to `C:\ProgramData\` (SHA256: `66b876c5...`) |
| `20:44` | as-pc2 | `wsync.exe` v2 deployed (SHA256: `0072ca0d...`) — stable beacon |
| `20:50` | as-pc2 | `kill.bat` downloaded via `bitsadmin` |

### Phase 3 — Defence Evasion & Credential Theft — 1/27/2026

| Time (UTC) | Host | Event |
|------------|------|-------|
| `21:03` | as-pc2 | `DisableAntiSpyware = 1` — Defender disabled via registry |
| `21:09` | as-pc2 | `vssadmin delete shadows /all /quiet` — shadow copies deleted |
| `21:09` | as-pc2 | `wmic shadowcopy delete` — redundant shadow deletion |
| `21:09` | as-pc2 | `bcdedit /set {default} recoveryenabled No` — recovery disabled |
| `21:11` | as-pc2 | `tasklist \| findstr lsass` — lsass enumeration #1 |
| `21:14` | as-pc2 | `tasklist \| findstr lsass` — lsass enumeration #2 |
| `21:42` | as-pc2 | `\Device\NamedPipe\lsass` accessed — credential dump |

### Phase 4 — Ransomware Deployment — 1/27/2026

| Time (UTC) | Host | Event |
|------------|------|-------|
| `22:08` | as-srv | AnyDesk relay active — attacker on file server |
| `22:13` | as-srv | Ransomware payload downloaded via `wsync.exe` |
| `22:15` | as-srv | `updater.exe` downloaded to `C:\ProgramData\` |
| `22:16` | as-srv | `updater.exe` copied to `as-pc1` and `as-pc2` via admin shares |
| `22:17` | as-srv | `net view \\10.1.0.154` + `net view \\10.1.0.183` — share enumeration |
| `22:18:29` | as-srv | **`updater.exe` executes — Akira ransomware deployed** |
| `22:18:33` | as-srv | `akira_readme.txt` dropped across `C:\Shares\` directories |
| `22:18:34` | as-srv | `wevtutil` clears Security, System, Application, PowerShell logs |
| `22:20:27` | as-srv | `clean.bat` executed — ransomware binary deleted |
| `22:24:09` | as-srv | `st.exe` creates `exfil_data.zip` at `C:\Users\Public\` |
| `22:24:55` | as-srv | `exfil_data.zip` exfiltrated to `sync.cloud-endpoint.net` |
| `23:17` | as-srv | `\Device\NamedPipe\lsass` accessed — attacker maintains access |

### Ransom Negotiation

| Detail | Value |
|--------|-------|
| TOR portal | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` |
| Victim ID | `813R-QWJM-XKIJ` |
| Initial demand | £65,000 |
| Victim counter | £11,000 |
| Deadline | 72 hours or data published |

---

## Indicators of Compromise

### Network

| Type | Value | Context |
|------|-------|---------|
| Domain | `sync.cloud-endpoint.net` | C2 / payload delivery |
| Domain | `cdn.cloud-endpoint.net` | Ransomware staging |
| IP | `172.67.174.46` | sync.cloud-endpoint.net |
| IP | `104.21.30.237` | cdn.cloud-endpoint.net |
| IP | `88.97.164.155` | Attacker external IP |
| Onion | `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion` | Ransom negotiation portal |

### Files

| Filename | SHA256 | Path | Purpose |
|----------|--------|------|---------|
| `wsync.exe` v1 | `66b876c5...` | `C:\ProgramData\` | Original C2 beacon |
| `wsync.exe` v2 | `0072ca0d...` | `C:\ProgramData\` | Replacement C2 beacon |
| `kill.bat` | `0e7da57d...` | `C:\Users\David.Mitchell\` | Defence evasion script |
| `AnyDesk.exe` | — | `C:\Users\Public\` | Pre-staged RAT |
| `scan.exe` | `26d5748f...` | `C:\Users\david.mitchell\Downloads\` | Network scanner |
| `updater.exe` | `e609d070...` | `C:\ProgramData\` | Akira ransomware binary |
| `st.exe` | `512a1f4e...` | `C:\ProgramData\` | Data staging tool |
| `clean.bat` | — | `C:\ProgramData\` | Post-encryption cleanup |
| `exfil_data.zip` | — | `C:\Users\Public\` | Exfiltration archive |

### Accounts

| Account | Host | Role |
|---------|------|------|
| `david.mitchell` | as-pc2 | Compromised user — primary attacker workstation |
| `as.srv.administrator` | as-srv | Compromised admin — ransomware deployment |
| `sophie.turner` | as-pc1 | Compromised user — AnyDesk pre-staged |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
|--------|-----------|--------|
| Initial Access | T1133 — External Remote Services | AnyDesk pre-staged from The Broker |
| Execution | T1059.001 — PowerShell | `Invoke-WebRequest`, payload execution |
| Persistence | T1547 — Boot/Logon Autostart | AnyDesk persistent access |
| Defence Evasion | T1562.001 — Disable Security Tools | `DisableAntiSpyware` registry, `kill.bat` |
| Defence Evasion | T1070.001 — Clear Windows Event Logs | `wevtutil cl` across 5 log channels |
| Defence Evasion | T1036 — Masquerading | `updater.exe` mimics Google Updater |
| Credential Access | T1003.001 — LSASS Memory | `\Device\NamedPipe\lsass` access |
| Discovery | T1046 — Network Service Scanning | Advanced IP Scanner across `10.1.0.0/24` |
| Discovery | T1135 — Network Share Discovery | `net view \\10.1.0.154`, `net view \\10.1.0.183` |
| Lateral Movement | T1021.002 — SMB/Windows Admin Shares | `updater.exe` copied via `\\host\C$\` |
| Collection | T1560 — Archive Collected Data | `st.exe` → `exfil_data.zip` |
| Exfiltration | T1041 — Exfiltration Over C2 Channel | `IWR POST` to `sync.cloud-endpoint.net` |
| Impact | T1486 — Data Encrypted for Impact | Akira ransomware, `.akira` extension |
| Impact | T1490 — Inhibit System Recovery | `vssadmin`, `wmic`, `bcdedit` |

---


