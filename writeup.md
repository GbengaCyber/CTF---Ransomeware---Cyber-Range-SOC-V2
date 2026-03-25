# Akira Ransomware — Ashford Sterling Recruitment

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

## Scenario

Following the initial compromise investigated in *The Broker*, a ransomware affiliate returned to the environment using pre-staged access. The threat actor deployed **Akira ransomware** across the network.

Investigation approach: work backwards from impact — identify ransomware execution, trace lateral movement, and correlate back to initial access. IOCs from *The Broker* are relevant.

---

## Investigation

---

### Q1 — Threat Actor
**Answer:** `Akira`

The ransom note was delivered via a TOR-based chat portal branded **"Akira Secure Chat"**. The portal, initial demand of £65,000, victim counter of £11,000, and negotiation style are consistent with known Akira ransomware affiliate operations. Identified from artefact — no KQL required.

---

### Q2 — Negotiation Portal
**Answer:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

The TOR address was found in the `akira_readme` ransom note dropped on the victim system. The note also contained a victim-specific Personal ID, AES-256 encryption claim, and a 72-hour deadline before data publication. Identified from artefact — no KQL required.

> ⚠️ Note: `akiral2iz` — the `l` (lowercase L) is easily misread as `1` in monospace fonts.

---

### Q3 — Victim ID
**Answer:** `813R-QWJM-XKIJ`

Found in the `akira_readme` ransom note under `Your personal ID`. Akira uses this identifier to link the victim to their negotiation session on the TOR portal. Identified from artefact — no KQL required.

---

### Q4 — Encrypted Extension
**Answer:** `.akira`

Confirmed from the ransom note and file listing screenshots. Files under `C:\Shares\` (Backups, Clients, Compliance, Contractors, Payroll) all showed Type: **AKIRA File** with the `.akira` extension appended. Encryption timestamp: `1/27/2026 22:18 UTC`.

---

### Q5 — Payload Domain
**Answer:** `sync.cloud-endpoint.net`

**`1/15/2026 04:52 UTC` — `as-pc2` — `david.mitchell`**

`DeviceNetworkEvents` was queried for outbound connections from common download utilities. `wsync.exe` and `powershell.exe` on `as-pc2` made repeated connections to `sync.cloud-endpoint.net` starting from the initial staging date. This domain served as the primary C2 and payload delivery point throughout the attack.

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-01-27T18:00:00Z) .. datetime(2026-01-27T22:18:00Z))
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe")
| where not(RemoteUrl has_any ("microsoft.com", "windowsupdate.com"))
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q6 — Ransomware Staging Domain
**Answer:** `cdn.cloud-endpoint.net`

**`1/15/2026 05:15 UTC` — `as-srv`**

Reviewing `DeviceNetworkEvents` for C2 infrastructure, a second domain `cdn.cloud-endpoint.net` was identified. This domain was used specifically for staging and delivering the ransomware payload to `as-srv` in the final phase of the attack.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-15 05:15:00) .. datetime(2026-01-28 23:00:00))
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any ("cdn.cloud-endpoint.net", "sync.cloud-endpoint.net")
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```

---

### Q7 — C2 IP Addresses
**Answer:** `104.21.30.237, 172.67.174.46`

Both C2 domains resolved to two IPs throughout the attack. These IPs were observed in connection logs across `as-pc2` and `as-srv` during payload delivery and beacon C2 communications.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-15 05:15:00) .. datetime(2026-01-28 23:00:00))
| where ActionType == "ConnectionSuccess"
| where DeviceName contains "as-pc1"
| where RemoteUrl has_any ("cdn.cloud-endpoint.net", "sync.cloud-endpoint.net")
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```

---

### Q8 — Remote Tool Relay
**Answer:** `relay-0b975d23.net.anydesk.com`

**`1/27/2026 22:08 UTC` — `as-srv`**

AnyDesk relay connections were reviewed across all compromised hosts. The relay domain `relay-0b975d23.net.anydesk.com` was the last relay connection observed on `as-srv` — active just 10 minutes before ransomware deployment, confirming the attacker maintained remote access right up to encryption.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-01-15 05:15:00) .. datetime(2026-01-28 23:00:00))
| where ActionType == "ConnectionSuccess"
| where RemoteUrl contains "relay"
| where InitiatingProcessAccountName != "system"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP
```

---

### Q9 — Evasion Script
**Answer:** `kill.bat`

**`1/27/2026 21:02 UTC` — `as-pc2` — `david.mitchell`**

`DeviceFileEvents` was queried for `.bat` files created on compromised hosts. `kill.bat` was identified as the security evasion script, downloaded from `sync.cloud-endpoint.net/kill.bat` via `bitsadmin` and executed to disable Windows Defender and delete shadow copies before ransomware deployment.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-28 23:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName endswith ".bat"
| project TimeGenerated, ActionType, FileName
```

---

### Q10 — Evasion Hash
**Answer:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

SHA256 of `kill.bat` retrieved from `DeviceFileEvents`. The script was dropped by `wsync.exe` on `as-pc2` under `david.mitchell`.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-28 23:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName endswith ".bat"
| project TimeGenerated, ActionType, FileName, SHA256
```

---

### Q11 — Registry Tampering
**Answer:** `DisableAntiSpyware`

Windows Defender was disabled via a registry modification setting `DisableAntiSpyware = 1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`. This was part of the defence evasion sequence executed before credential theft and ransomware deployment.

---

### Q12 — Registry Timestamp
**Answer:** `21:03:42`

**`1/27/2026 21:03 UTC` — `as-pc2`**

`DeviceRegistryEvents` was filtered for Defender-related registry modifications. The key `DisableAntiSpyware` was set to `1` via `reg add` at `21:03:42`, approximately 75 minutes before encryption.

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

---

### Q13 — Process Hunt
**Answer:** `tasklist | findstr lsass`

**`1/27/2026 21:14 UTC` — `as-pc2` — `david.mitchell`**

`DeviceProcessEvents` was queried for process enumeration commands. `wsync.exe` spawned `cmd.exe` which executed `tasklist | findstr lsass` twice — at `21:11` and `21:14` — confirming the attacker was locating the LSASS process in preparation for credential dumping.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-01-27 21:00:00) .. datetime(2026-01-27 22:00:00))
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where AccountDomain != "nt authority"
| where InitiatingProcessCommandLine has_any ("tasklist", "Get-Process lsass")
| project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
```

---

### Q14 — Credential Pipe
**Answer:** `\Device\NamedPipe\lsass`

**`1/27/2026 21:42 UTC` — `as-pc2`**

`DeviceEvents` was filtered for `NamedPipeEvent` actions referencing `lsass`. The pipe `\Device\NamedPipe\lsass` was accessed on `as-pc2` at `21:42` — following the process enumeration at `21:11/21:14` — consistent with credential dumping activity against LSASS.

```kql
DeviceEvents
| where DeviceName in~ ("as-srv", "as-pc2")
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has_any ("lsass", "samr", "netlogon", "protected_storage")
| project Timestamp, DeviceName, AccountName, AdditionalFields, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q15 — Remote Access Tool
**Answer:** `AnyDesk`

AnyDesk relay connections were identified across `as-srv`, `as-pc1`, and `as-pc2` throughout the attack window. The tool was pre-staged during the initial *The Broker* compromise and reused 12 days later to re-enter the environment without re-exploitation.

---

### Q16 — Suspicious Execution Path
**Answer:** `C:\Users\Public`

**`1/15/2026 04:40 UTC` — `as-pc2`**

`DeviceFileEvents` was queried for `AnyDesk.exe` across the full investigation window. The binary was dropped into `C:\Users\Public\` — a world-writable directory — rather than the legitimate install path `C:\Program Files (x86)\AnyDesk\`, confirming it was manually staged by the attacker.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2026-01-15 03:00:00) .. datetime(2026-01-28 23:00:00))
| where DeviceName == "as-pc2"
| where FileName == "AnyDesk.exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q17 — Attacker IP
**Answer:** `88.97.164.155`

**`1/27/2026 19:29 UTC` — `as-pc2` — `david.mitchell`**

AnyDesk network connections on `as-pc2` were reviewed. Most traffic resolved to known AnyDesk relay infrastructure. Two connections stood out — raw IP only, no `RemoteUrl` — indicating inbound connections rather than outbound relay traffic. Both resolved to `88.97.164.155`, confirming this as the attacker's external IP.

```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-15 03:00:00) .. datetime(2026-01-27 23:00:00))
| where InitiatingProcessFileName =~ "anydesk.exe"
| where RemoteIPType == "Public"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, DeviceName
| sort by Timestamp desc
```

---

### Q19 — Primary Beacon
**Answer:** `wsync.exe`

**`1/27/2026 20:22 UTC` — `as-pc2`**

`DeviceFileEvents` was queried for executables dropped into staging directories. `wsync.exe` was identified as the new C2 beacon, dropped into `C:\ProgramData\` by `powershell.exe`. It masquerades as a Windows sync utility and was responsible for all C2 communication, payload delivery, and spawning attacker commands.

```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FolderPath has_any ("ProgramData", "Temp", "Public", "Downloads")
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

---

### Q20 — Beacon Location
**Answer:** `C:\ProgramData`

**`1/27/2026 20:22 UTC` — `as-pc2`**

Confirmed from the Q19 query. `wsync.exe` was consistently written to `C:\ProgramData\wsync.exe` across all three drop events. `C:\ProgramData` is a common attacker staging path — accessible without user-specific permissions.

---

### Q21 — Beacon Hash (Original)
**Answer:** `66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b`

**`1/27/2026 20:22 UTC` — `as-pc2`**

Three drops of `wsync.exe` were observed. The first at `20:22` carried a different SHA256 from the final version, identifying it as the original beacon that failed to maintain stable C2 communications.

---

### Q22 — Beacon Hash (Replacement)
**Answer:** `0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654`

**`1/27/2026 20:44 UTC` — `as-pc2`**

The replacement beacon was dropped at `20:44` with a different SHA256, confirming the attacker pushed an updated binary after the first version failed. This version maintained stable C2 and drove all subsequent attack activity.

```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName == "wsync.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| order by Timestamp asc
```

---

### Q23 — Scanner Tool
**Answer:** `scan.exe`

**`1/27/2026 20:17 UTC` — `as-pc2` — `david.mitchell`**

`DeviceFileEvents` was filtered for executables in user directories. `scan.exe` was downloaded directly to `C:\Users\david.mitchell\Downloads\` — a direct download artefact. It is an NSIS self-extracting installer that unpacked Advanced IP Scanner for network reconnaissance.

```kql
DeviceFileEvents
| where DeviceName == "as-pc2"
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName contains "scan"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp desc
```

---

### Q24 — Scanner Hash
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

---

### Q25 — Scanner Execution Arguments
**Answer:** `/portable "C:/Users/david.mitchell/Downloads/" /lng en_us`

**`1/27/2026 20:17 UTC` — `as-pc2` — `david.mitchell`**

`scan.exe` showed no arguments directly. Child process analysis revealed `scan.exe` spawned `scan.tmp` (NSIS extractor) which launched `advanced_ip_scanner.exe` with the `/portable` flag — intentionally avoiding installation to leave minimal forensic trace.

```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where Timestamp between (datetime(2026-01-27T20:15:00Z) .. datetime(2026-01-27T21:00:00Z))
| where FileName =~ "advanced_ip_scanner.exe"
    or InitiatingProcessFileName =~ "advanced_ip_scanner.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q26 — Network Enumeration
**Answer:** `10.1.0.154, 10.1.0.183`

**`1/27/2026 22:17 UTC` — `as-srv`**

`DeviceNetworkEvents` was filtered for SMB (port 445) connections to internal IPs, excluding bulk scanner traffic. Two targeted connections from `as-srv` at `22:17` — 2 minutes before encryption — identified `as-pc1` (`10.1.0.154`) and `as-pc2` (`10.1.0.183`) as the enumerated hosts. Confirmed by `net view` commands in process logs.

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

---

### Q27 — Lateral Account
**Answer:** `as.srv.administrator`

The compromised admin account `as.srv.administrator` was used for all attacker activity on `as-srv`. First seen in logon events from `as-pc2` (`10.1.0.183`) on `1/15/2026` during *The Broker* compromise and reused throughout the Akira deployment.

```kql
DeviceLogonEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27 18:00:00) .. datetime(2026-01-27 23:00:00))
| where ActionType == "LogonSuccess"
| order by TimeGenerated asc
```

---

### Q28 — Download Method (LOLBIN)
**Answer:** `bitsadmin.exe`

**`1/27/2026 20:14 UTC` — `as-pc2` — `david.mitchell`**

`DeviceProcessEvents` was filtered for LOLBIN download commands. `bitsadmin.exe` was used to pull tools from `sync.cloud-endpoint.net` but failed multiple times — first with a doubled destination path, then a non-existent `C:\Temp\` — before succeeding on the fourth attempt to `Downloads\`.

```kql
DeviceProcessEvents
| where DeviceName in~ ("as-srv", "as-pc2")
| where Timestamp between (datetime(2026-01-27T18:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where ProcessCommandLine has_any ("DownloadFile", "Invoke-WebRequest", "iwr", "bitsadmin", "certutil")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q29 — Fallback Download Method
**Answer:** `Invoke-WebRequest`

After `bitsadmin` issues, the attacker switched to PowerShell's `Invoke-WebRequest` cmdlet. Used extensively across `as-pc2` and `as-srv` to download `wsync.exe`, `updater.exe`, `st.exe`, and `clean.bat`. URL obfuscation techniques were also observed — domain splitting, base64 encoding, and variable splitting.

```kql
DeviceEvents
| where DeviceName in~ ("as-srv", "as-pc2")
| where Timestamp between (datetime(2026-01-27T18:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where ActionType has "PowerShell"
| project Timestamp, DeviceName, AccountName, ActionType, AdditionalFields
| order by Timestamp asc
```

---

### Q30 — Staging Tool
**Answer:** `st.exe`

**`1/27/2026 22:24:09 UTC` — `as-srv`**

`DeviceFileEvents` was queried for archive file creation. `st.exe` created `exfil_data.zip` at `C:\Users\Public\` on `as-srv` at `22:24:09` — 6 minutes after encryption. The archive was staged for exfiltration.

```kql
DeviceFileEvents
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName has_any (".rar", ".zip", ".7z")
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

---

### Q31 — Staging Hash
**Answer:** `512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015`

SHA256 of `st.exe` retrieved from `DeviceFileEvents` via `InitiatingProcessSHA256`.

```kql
DeviceFileEvents
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where TimeGenerated between (datetime(2026-01-27 03:00:00) .. datetime(2026-01-27 23:00:00))
| where FileName has_any (".rar", ".zip", ".7z")
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessSHA256
| order by Timestamp desc
```

---

### Q32 — Exfil Archive
**Answer:** `exfil_data.zip`

**`1/27/2026 22:24:09 UTC` — `as-srv`**

`st.exe` created `exfil_data.zip` in `C:\Users\Public\` — the same staging directory used for AnyDesk. The archive was exfiltrated to `sync.cloud-endpoint.net` via an `Invoke-WebRequest` POST at `22:24:55`.

---

### Q33 — Ransomware Filename
**Answer:** `updater.exe`

**`1/27/2026 22:18:29 UTC` — `as-srv`**

`DeviceProcessEvents` was reviewed around the encryption timestamp. `updater.exe` was executed from `C:\ProgramData\` by `powershell.exe` at `22:18:29`. Named to blend with the legitimate Google Updater process running on the same host. Immediately spawned `wevtutil.exe` to clear five Windows event logs.

```kql
DeviceProcessEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:15:00Z) .. datetime(2026-01-27T22:20:00Z))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q34 — Ransomware Hash
**Answer:** `e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b`

SHA256 of `updater.exe` retrieved via `InitiatingProcessSHA256` — confirmed across five `wevtutil.exe` child processes all sharing the same parent hash.

```kql
DeviceProcessEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:15:00Z) .. datetime(2026-01-27T22:20:00Z))
| where InitiatingProcessFileName contains "updater.exe"
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, InitiatingProcessSHA256
| order by Timestamp asc
```

---

### Q35 — Ransomware Staging
**Answer:** `powershell.exe`

**`1/27/2026 22:18 UTC` — `as-srv`**

`DeviceFileEvents` filtered for `FileCreated` actions in the encryption window confirmed `powershell.exe` staged `updater.exe` into `C:\ProgramData\` immediately before execution.

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:15:00Z) .. datetime(2026-01-27T22:20:00Z))
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q36 — Recovery Prevention
**Answer:** `vssadmin  delete shadows /all /quiet`

**`1/27/2026 21:09 UTC` — `as-pc2` — `david.mitchell`**

Three recovery prevention commands executed in rapid succession via `cmd.exe` as part of `kill.bat`: `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, and `bcdedit /set {default} recoveryenabled No`. All shadow copies deleted and Windows Recovery disabled before ransomware deployment.

```kql
DeviceProcessEvents
| where DeviceName in~ ("as-srv", "as-pc1", "as-pc2")
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q37 — Ransom Note Origin
**Answer:** `updater.exe`

**`1/27/2026 22:18:33 UTC` — `as-srv`**

`DeviceFileEvents` filtered for `.txt` creation events. `updater.exe` dropped `akira_readme.txt` four times across encrypted directories at `22:18:33` — 4 seconds after execution — confirming the ransomware binary handles both encryption and ransom note delivery.

```kql
DeviceFileEvents
| where DeviceName in~ ("as-srv", "as-pc1", "as-pc2")
| where Timestamp between (datetime(2026-01-27T20:00:00Z) .. datetime(2026-01-28T00:00:00Z))
| where FileName endswith ".txt"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName
| order by Timestamp asc
```

---

### Q38 — Encryption Start
**Answer:** `22:18:33`

Identified from the Q37 query. `akira_readme.txt` was first created at `22:18:33 UTC`, 4 seconds after `updater.exe` execution at `22:18:29`.

---

### Q39 — Cleanup Script
**Answer:** `clean.bat`

**`1/27/2026 22:20:27 UTC` — `as-srv`**

`DeviceProcessEvents` reviewed post-encryption. `powershell.exe` executed `cmd.exe /c C:\ProgramData\clean.bat` at `22:20:27` — 2 minutes after ransomware execution. Downloaded from `sync.cloud-endpoint.net/kill.bat` via `bitsadmin` earlier in the attack, responsible for removing `updater.exe` and other artefacts.

```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where Timestamp between (datetime(2026-01-27T22:18:00Z) .. datetime(2026-01-28T00:00:00Z))
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

---

### Q40 — Affected Hosts
**Answer:** `as-srv, as-pc2`

`as-pc2` was the primary staging host where the attacker operated under `david.mitchell`. `as-srv` was the target — file server where ransomware deployed and `C:\Shares\` encrypted. `as-pc1` showed AnyDesk pre-staging and lateral movement artefacts from `updater.exe` being copied via admin shares.

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

---

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

---

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

---

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

---

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

*Part of the [CTF Writeups](../../README.md) project.*
