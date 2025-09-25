---
layout: post
title: Playing with PfSense Firewall
date: 2025-09-23 16:26:00
categories: [pfsense,networking, tutorial]
---

## 1. Introduction

I finally have the opportunity to continue my homelab project. This project was inspired by my internship as a Network Security Intern, where I was exposed to many security tools—especially firewalls. During that time, I realized something important: although I had heard a lot about firewalls, I didn’t actually know how they looked or worked in practice.

My initial assumption was that a firewall was simply software, like the built-in Microsoft Firewall. However, in enterprise environments, a firewall is usually a dedicated networking component that sits between different network segments.

Since hardware firewalls are expensive (and frankly an overkill for a learning environment), I decided to explore the best open-source alternative available: pfSense.

### What is pfSense?

<img width="654" height="457" alt="image" src="https://github.com/user-attachments/assets/3aab24ba-bc5f-4858-b2fe-add872ed98bf" />

pfSense is an open-source firewall and router distribution based on FreeBSD. It provides a wide range of enterprise-grade features such as:

- Stateful packet filtering firewall
- Network Address Translation (NAT)
- VPN (IPsec, OpenVPN, WireGuard)
- DHCP and DNS services
- Web-based GUI for easy management
- Advanced logging and monitoring

Thanks to its flexibility, pfSense can run not only on dedicated hardware but also on virtual machines, which makes it ideal for learning and homelabs.

### Homelab Setup

In this project, I set up pfSense inside VMware Workstation to simulate a small enterprise network. The goal is to understand how pfSense works as a firewall and security gateway, and to test different scenarios, including:

1. Firewall as DHCP Server 
2. DMZ setup.
3. Firewall Rules – controlling inbound and outbound traffic.
4. Web Server in DMZ – exposing services while keeping LAN secure.

## 2. Network Architecture

The virtual lab is designed to resemble a typical enterprise network with three main zones:

- WAN (Untrusted Zone): Simulates the internet.
- LAN (Trusted Zone): Represents internal users and workstations.
- DMZ (Semi-Trusted Zone): Hosts public-facing servers such as a web server or mail server.

## 3. Firewall as DHCP Server
When I first played around with pfSense, one of the things I wanted to try was DHCP. DHCP basically automatically assigns IPs on every machine in the network. This is super useful if you don’t want to bother about asigning new machine IP address by yourseelf. Although in certain case where, static IP is more prefer for critical server that require consistent IP.

So here’s the idea, I configure pfSense to act as the DHCP server for both of these subnet. That way, whenever a new VM boots up, it just asks pfSense for an IP and pfSense will auto assign it based on the remaining address ppol:

- My LAN (192.168.1.0/24): Kali and host Window.
- My DMZ (192.168.2.0/24): Lubuntu with web server.

### How I Set It Up

1. Log into the pfSense web dashboard.
2. Go to Services > DHCP Server.
3. On the LAN tab, tick “Enable DHCP.”
4. I set the range to something like `192.168.1.100 – 192.168.1.200` (so I know all dynamic clients will sit in that range).
5. I did the same for the DMZ tab, but with the `192.168.2.100 – 192.168.2.200` range.

That’s it. Now pfSense is ready to hand out addresses automatically.

### Testing It

Once DHCP is enabled, I just start up one of my Linux VMs and run:
```
ip a
```

<img width="897" height="312" alt="image" src="https://github.com/user-attachments/assets/3fa6e2bd-65ba-4440-b54f-7888e57194c4" />


Kali VM picks up an IP from pfSense automatically. I also check with dhcpclient to see how the DHCP process work behind the scene. 
<img width="726" height="261" alt="image" src="https://github.com/user-attachments/assets/69259637-4174-43bb-9425-00d197121525" />


To double-check, I also looked at the DHCP Leases page in pfSense, and I could see my Kali machine listed there with the IP it got assigned.
<img width="654" height="457" alt="image" src="https://github.com/user-attachments/assets/8d948f5f-7327-4e3f-ba6d-6c5a30dea367" />

4. Firewall Rules – Controlling Inbound and Outbound Traffic

Now we’re moving to the main feature of a firewall — filtering traffic that goes inbound and outbound through each interface.

The way pfSense (and most firewalls) works is by applying rules. A rule usually defines:

- source (where the traffic comes from),
- destination (where it’s going),
- port/service being used (like HTTP, HTTPS, SSH, etc.).

For each rule, you decide whether to allow or block that traffic.

One important thing to remember is that firewall rules are checked from top to bottom. That means the order matters: you should place the most specific rules at the top, and more general rules at the bottom. This way, pfSense knows exactly what to do before it falls back to a default action.

<img width="1001" height="428" alt="image" src="https://github.com/user-attachments/assets/a81132c3-f760-486d-9799-b3eb56255fdc" />

I wanted to test this for myself. So I created a simple scenario:

- Normal behavior: My LAN machine can access websites like httpforever.com over port 80 (HTTP).
- Test behavior: I add a firewall rule in pfSense to block HTTP (port 80) from the LAN. After applying it, I should see that I can’t load httpforever.com anymore.

### How I Set It Up

1. Logged into pfSense → Firewall > Rules > LAN.
2. Added a new rule:

- Action: Block
- Protocol: TCP
- Source: LAN net (all LAN devices)
- Destination: Any
- Destination Port: 80 (HTTP)
- Moved this rule above the default “Allow LAN to Any” rule (order matters in pfSense — rules are checked top to bottom).

### Testing the Rule

- Before the rule: From my Kali VM, I ran curl http://httpforever.com and got the page content back.
<img width="1350" height="460" alt="image" src="https://github.com/user-attachments/assets/af0cec11-9a58-4523-97bd-fcef5a113ad4" />

- After enabling the rule: Same command gave me no response, and the page wouldn’t load in the browser.
<img width="945" height="554" alt="image" src="https://github.com/user-attachments/assets/4f7aea22-7d40-4c3d-a625-eb2a9d0fec33" />

That proved the rule was working — pfSense saw that my traffic was trying to use port 80 and blocked it. You can also enable the logs for the rules, as you can see several 
<img width="1114" height="205" alt="image" src="https://github.com/user-attachments/assets/f8b74cf2-ea3f-464d-8737-7df77665a8f6" />


### Why This Matters

This small test shows exactly how pfSense can control traffic at a granular level. In a real network security engineer job, you’d use this to:

- Block risky ports (like SMB or Telnet).
- Only allow approved applications out to the Internet.
- Stop malware from “phoning home” by restricting outbound connections.



✅ DMZ servers can go out to WAN, but cannot reach LAN.
<img width="1162" height="307" alt="image" src="https://github.com/user-attachments/assets/44c8099f-f3d1-47f2-904a-b8970a43160a" />

From DMZ 192.L168.2.10, cannot ping to LAN network in this case I try toi ping the Windo host ip at 192.168.1.101.
<img width="795" height="76" alt="Screenshot 2025-09-24 152927" src="https://github.com/user-attachments/assets/cd48d8a9-064e-439e-9ab8-fb8d3a7064b7" />

 
