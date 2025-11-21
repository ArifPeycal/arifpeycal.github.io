---
title: Hack the Box - Editor
time: 2025-11-21 12:00:00
categories: [htb, easy]
tags: [xlst injection]
---

## Recon
### Initial Scanning

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
