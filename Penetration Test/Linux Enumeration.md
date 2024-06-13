## Enumeration

### hostname
```hostname```: command will return the hostname of the target machine.

### uname -a
```uname -a```: will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.

### /proc/version
```/proc/version```: the proc filesystem (procfs) provides information about the target system processes.

### ps Processes
```ps```: will running processes on a Linux system.

Output of ```ps``` comand:

-  PID: The process ID (unique to the process)
-  TTY: Terminal type used by the user
-  Time: Amount of CPU time used by the process (this is NOT the time this process has been running for)
-  CMD: The command or executable running (will NOT display any command line parameter)

ps command options:

```ps -A```: View all running processes.

```ps axjf```: View process tree (see the tree formation until ps axjf is run below)

```ps aux```: The ```aux``` option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.

### Environment Variables
```env```: command will show environmental variables.

### sudo -l
```sudo -l```: command can be used to list all commands your user can run using sudo.

### id
```id```: command will provide a general overview of the user’s privilege level and group memberships.

```id matt```: obtain _matt_ user’s privilege level and group memberships.

### /etc/passwd
```cat /etc/passwd```: discover users on the system.

```cat /etc/passwd | cut -d ":" -f 1```: Get only usernames from _passwd_ file.

```cat /etc/passwd | grep home | cut -d ":" -f 1```: Get usernames excluding service users accounts.

### IP Routes exists
```ip route```: command to see which network routes exist.

### netstat
```netstat -a```:  shows all listening ports and established connections.

```netstat -at``` or ```netstat -au```: can also be used to list TCP or UDP protocols respectively.

```netstat -l```: list ports in “listening” mode. These ports are open and ready to accept incoming connections.

```netstat -s```: list network usage statistics by protocol (below) This can also be used with the ```-t``` (TCP) or ```-u``` (UDP) options to limit the output to a specific protocol.

```netstat -tp```: list connections with the service name and PID information.

```netstat -i```: Shows interface statistics.

```netstat -ano```: 
- ```-a```: Display all sockets
- ```-n```: Do not resolve names
- ```-o```: Display timers

### find Command - FInd files
- ```find . -name flag1.txt```: find the file named “flag1.txt” in the current directory
- ```find /home -name flag1.txt```: find the file names “flag1.txt” in the /home directory
- ```find / -type d -name config```: find the directory named config under “/”
- ```find / -type f -perm 0777```: find files with the 777 permissions (files readable, writable, and executable by all users)
- ```find / -perm a=x```: find executable files
- ```find /home -user frank```: find all files for user “frank” under “/home”
- ```find / -mtime 10```: find files that were modified in the last 10 days
- ```find / -atime 10```: find files that were accessed in the last 10 day
- ```find / -cmin -60```: find files changed within the last hour (60 minutes)
- ```find / -amin -60```: find files accesses within the last hour (60 minutes)
- ```find / -size 50M```: find files with a 50 MB size
- ```find / -size +50M```: find files larger than 50 MB size
- ```find / -size +100M -type f 2>/dev/null```: find files larger than 100 MB size ("-type f 2>/dev/null" redirect errors to “/dev/null” and have a cleaner output)

Folders and files that can be written to or executed from:

- ```find / -writable -type d 2>/dev/null```: Find world-writeable folders
- ```find / -perm -222 -type d 2>/dev/null```: Find world-writeable folders
- ```find / -perm -o w -type d 2>/dev/null```: Find world-writeable folders
- ```find / -perm -o x -type d 2>/dev/null```: Find world-executable folders

Find development tools and supported languages:

- ```find / -name perl*```
- ```find / -name python*```
- ```find / -name gcc*```

```find / -perm -u=s -type f 2>/dev/null```: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.
