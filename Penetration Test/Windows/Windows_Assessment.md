# Windows Assessment

### System Information

- #### Basic system information
  ```
  System Version and Configuration
  ```

- #### Get OS version, architecture, and build number
  ```
  Get-WmiObject -Class Win32_OperatingSystem | Select-Object Version, BuildNumber, OSArchitecture
  ```

- #### Get system uptime
  ```
  (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
  ```

-------------------------------------------------------------------------------------------------
### Installed Hotfixes and Patches

- #### List all installed patches
  ```
  wmic qfe list
  ```

- #### Get specific installed updates
  ```
  Get-HotFix
  ```

-------------------------------------------------------------------------------------------------
### Retrieve all installed application software along with their versions and installation dates

- #### Powershell command to List Installed Applications
  ```
  Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate | Format-Table -AutoSize
  ```

- #### Using the Registry to List Installed Applications
  ```
  Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, 
  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, InstallDate | 
  Where-Object { $_.DisplayName } | Format-Table -AutoSize
  ```

- #### List all installed applications using WMI
  ```
  wmic product get name,version
  ```

--------------------------------------------------------------------------------------------------
### User and Privilege Enumeration
#### Local Users
- #### List all users
  ```
  net user
  ```
  
- #### List users in PowerShell
  ```
  Get-LocalUser
  ```

- #### Get details of a specific user
  ```
  net user <username>
  ```

#### Groups and Privileges
- #### List all local groups
  ```
  net localgroup
  ```

- #### Show members of a specific group (e.g., Administrators)
  ```
  net localgroup administrators
  ```

#### Logged In Users
- ####  Show currently logged-in users
  ```
  query user
  ```

- #### List remote desktop users
  ```
  qwinsta
  ```

- #### Get current sessions (PowerShell)
  ```
  Get-WmiObject -Class Win32_ComputerSystem | Select-Object Username
  ```

#### Administrative Shares
- #### Check if administrative shares are enabled
  ```
  net share
  ```
--------------------------------------------------------------------------------------------
### Network and Firewall Enumeration
#### Network Configuration:
- #### Display all network interface configurations
  ```
  ipconfig /all
  Get-NetAdapter
  ```

- #### List routing table
  ```
  route print
  ```

- #### Show open network connections and associated processes
  ```
  netstat -ano
  ```

#### List Open Ports
- #### Show open TCP and UDP ports
  ```
  netstat -an
  ```

- #### Show open TCP and UDP ports (Powershell)
  ```
  Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
  ```


#### Network Shares
- #### List shared resources on the system
  ```
  net view \\localhost
  ```

#### Active Network Connections
- #### Check active connections (Command Prompt)
  ```
  netstat -an
  ```

- #### Using powershell
  ```
  Get-NetTCPConnection
  ```

#### Firewall Status
- #### Check firewall status
  ```
  netsh advfirewall show allprofiles
  ```

- #### PowerShell firewall status
  ```
  Get-NetFirewallProfile
  ```

#### DNS Information:
- #### Display DNS cache
  ```
  ipconfig /displaydns
  ```

- #### Get the system’s DNS server
  ```
  Get-DnsClientServerAddress
  ```
--------------------------------------------------------------------------------------------------

### Service and Process Enumeration
  
#### Services:
- #### List running services
  ```
  net start
  ```

- #### Get detailed services information (PowerShell)
  ```
  Get-Service
  ```

#### Processes:
- #### List running processes
  ```
  tasklist
  ```

- #### Get process details (PowerShell)
  ```
  Get-Process
  ```

- #### Get detailed process information (with owners)
  ```
  tasklist /v
  ```

- #### To see process by specific users (PowerShell)
  ```
  Get-WmiObject Win32_Process | Select-Object ProcessId, Name, @{Name="UserName";Expression={$_.GetOwner().User}}
  ```

#### Check for High Privileged Processes
- #### List all processes running as "SYSTEM"
  ```
  Get-WmiObject Win32_Process | Where-Object { $_.GetOwner().User -eq 'SYSTEM' }
  ```

#### Dump Process Memory (If Permissioned)
- #### Dump process memory for analysis
  ```
  procdump -ma <PID> dumpfile.dmp
  ```
------------------------------------------------------------------------------------------------------------

### Scheduled Tasks Enumeration
- #### List scheduled tasks
  ```
  schtasks /query /fo LIST /v
  ```

- #### Using PowerShell
  ```
  Get-ScheduledTask | Select-Object TaskName, State, Actions
  ```
-------------------------------------------------------------------------------------------------------------

### Password Policy and Security Settings
- #### Show password policy
  ```
  net accounts
  ```

- #### Check security policies
  ```
  secedit /export /cfg C:\path\to\output\secpol.cfg
  ```

- #### PowerShell password policy check
  ```
  Get-LocalUser | Select-Object Name, PasswordLastSet, PasswordExpires
  ```

#### Audit Policy
- #### Show the current audit policy (useful for detecting if logs are being created)
  ```
  auditpol /get /category:*
  ```
-------------------------------------------------------------------------------------------------------------

### File and Directory Enumeration
- #### List all files and directories in a specified directory
  ```
  dir C:\path\to\directory /s /b
  ```
#### Search for Files Containing Passwords or Secrets
- #### Find files with "password" in the filename
  ```
  dir C:\ /s /b | findstr /i "password"
  ```

- #### Search for files with extensions commonly used for configuration, credentials, etc
  ```
  dir C:\*.config /s /b
  dir C:\*.xml /s /b
  dir C:\*.txt /s /b
  dir C:\*.ini /s /b
  ```
  
- #### PowerShell recursive file search for strings (useful for searching sensitive info in files)
  ```
  Get-ChildItem -Path C:\ -Recurse -Include *.txt, *.xml, *.config | Select-String -Pattern "password"
  ```

- #### List hidden files
  ```
  dir /a:h
  ```

- #### Check permissions on a file or directory (PowerShell)
  ```
  Get-Acl -Path "C:\path\to\directory"
  ```

#### Find Files Owned by Specific Users (e.g., SYSTEM)
- #### Recursively find all files owned by SYSTEM
  ```
  Get-ChildItem -Path C:\ -Recurse | Where-Object { (Get-Acl $_.FullName).Owner -eq 'NT AUTHORITY\SYSTEM' }
  ```
  
----------------------------------------------------------------------------------------

### Registry Enumeration
#### Check Registry for Startup Programs
- #### List startup programs (PowerShell)
  ```
  Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
  ```

#### Check Specific Registry Key
- #### Query a registry key
  ```
  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
  ```
----------------------------------------------------------------------------------------------

### Privilege Escalation Checks

#### Check for Privileged Accounts:
- #### Check for users with admin rights
  ```
  net localgroup administrators
  ```

- #### Check for users with admin rights (powershell)
  ```
  Get-LocalGroupMember -Group "Administrators"
  ```

#### Check UAC Settings
- #### Get User Account Control (UAC) settings
  ```
  Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object ConsentPromptBehaviorAdmin
  ```

#### List Privileges of Current User
- #### Check the privileges of the current user
  ```
  whoami /priv
  ```
  
--------------------------------------------------------------------------------------------------

### Remote Access Enumeration
#### Check RDP Status:
- #### Check if Remote Desktop is enabled
  ```
  reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
  ```

- #### Check firewall rules for RDP
  ```
  netsh advfirewall firewall show rule name="Remote Desktop"
  ```
--------------------------------------------------------------------------------------------

### Active Directory Enumeration

- #### List domain users
  ```
  net user /domain
  ```

- #### Get domain information
  ```
  nltest /dsgetdc:<domain_name>
  ```

- #### Check group policy settings
  ```
  gpresult /r
  ```

- #### Get domain controllers
  ```
  net group "Domain Controllers" /domain
  ```
-----------------------------------------------------------------------------------------------

### Windows Registry Enumeration

#### Check for Startup Programs in Registry
- #### Get all programs that start at system boot
  ```
  Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
  ```

#### Check for Potentially Interesting Keys
- #### Look for credentials stored in registry (sometimes stored by certain programs)
  ```
  Get-ItemProperty -Path "HKCU:\Software\Microsoft\Credentials"
  ```
-------------------------------------------------------------------------------------------

### Windows Defender and AV Enumeration

#### Check Windows Defender Status
- #### Check if Windows Defender is enabled
  ```
  Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
  ```

#### Disable Windows Defender (If Permissions Allow)
- #### Disable Windows Defender (requires elevated permissions)
  ```
  Set-MpPreference -DisableRealtimeMonitoring $true
  ```
