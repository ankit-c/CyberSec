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
  ```

- #### List routing table
  ```
  route print
  ```

- #### Show open network connections and associated processes
  ```
  netstat -ano
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
- ### Show password policy
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
-------------------------------------------------------------------------------------------------------------

### File and Directory Enumeration
- #### List all files and directories in a specified directory
  ```
  dir C:\path\to\directory /s /b
  ```
  
- #### List hidden files
  ```
  dir /a:h
  ```

- #### Check permissions on a file or directory (PowerShell)
  ```
  Get-Acl -Path "C:\path\to\directory"
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
    
