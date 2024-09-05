# Windows Assessment

### System Information

- #### Basic system information
  ```System Version and Configuration```

- #### Get OS version, architecture, and build number
  ```Get-WmiObject -Class Win32_OperatingSystem | Select-Object Version, BuildNumber, OSArchitecture```

- #### Get system uptime
  ```(Get-CimInstance Win32_OperatingSystem).LastBootUpTime```

-------------------------------------------------------------------------------------------------
### Installed Hotfixes and Patches

- #### List all installed patches
  ```wmic qfe list```

- #### Get specific installed updates
  ```Get-HotFix```

-------------------------------------------------------------------------------------------------
### Retrieve all installed application software along with their versions and installation dates

- #### Powershell command to List Installed Applications
  ```Get-WmiObject -Class Win32_Product | Select-Object Name, Version, InstallDate | Format-Table -AutoSize```

- #### Using the Registry to List Installed Applications
  ```
  Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, 
  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, InstallDate | 
  Where-Object { $_.DisplayName } | Format-Table -AutoSize
  ```

--------------------------------------------------------------------------------------------------
### User and Privilege Enumeration
#### Local Users
- #### List all users
  ```net user```
  
- #### List users in PowerShell
  ```Get-LocalUser```

- #### Get details of a specific user
  ```net user <username>```

#### Groups and Privileges
- #### List all local groups
  ```net localgroup```

- #### Show members of a specific group (e.g., Administrators)
  ```net localgroup administrators```

#### Logged In Users
- ####  Show currently logged-in users
  ```query user```

- #### List remote desktop users
  ```qwinsta```

- #### Get current sessions (PowerShell)
  ```Get-WmiObject -Class Win32_ComputerSystem | Select-Object Username```

#### Administrative Shares
- #### Check if administrative shares are enabled
  ```net share```
--------------------------------------------------------------------------------------------
### Network and Firewall Enumeration
#### Network Configuration:
- #### Display all network interface configurations
  ```
  ipconfig /all
  ```

- #### List routing table
  ```route print```

- #### Show open network connections and associated processes
  ```netstat -ano```
