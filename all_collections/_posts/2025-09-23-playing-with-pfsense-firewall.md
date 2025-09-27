---
layout: post
title: Playing with PfSense Firewall
date: 2025-09-23 16:26:00
categories: [pfsense,networking, tutorial]
---

## 1. Introduction
<img width="400" height="250" alt="image" src="https://github.com/user-attachments/assets/3aab24ba-bc5f-4858-b2fe-add872ed98bf" />

Finally, have the opportunity to continue my homelab project. This project was inspired by my internship as a Network Security Intern, where I was exposed to many security tools especially firewalls. 

So, I want to actually implement one in my homelab. Since hardware firewalls are expensive (and frankly an overkill for a learning environment), I decided to explore the best open-source alternative available: pfSense.

### What is pfSense?

pfSense is an open-source firewall and router distribution based on FreeBSD. It provides a wide range of features such as:

- Stateful packet filtering firewall
- Network Address Translation (NAT)
- VPN (IPsec, OpenVPN, WireGuard)
- DHCP and DNS services

Thanks to its flexibility, pfSense can run not only on dedicated hardware but also on virtual machines, which makes it ideal for learning and homelabs.

### Homelab Setup

In this project, I set up pfSense inside VMware Workstation to simulate a small enterprise network. The goal is to understand how pfSense works as a firewall and security gateway, and to test different scenarios, including:

1. Firewall as DHCP Server
2. Firewall Rules 
3. DMZ setup

## 2. Network Architecture

The virtual lab is designed to resemble a typical enterprise network with three main zones:
<img width="699" height="420" alt="image" src="https://github.com/user-attachments/assets/4d9317e9-5466-4140-b958-09e96de08f4f" />

- WAN (Untrusted Zone): Simulates the internet.
- LAN (Trusted Zone): Represents internal users and workstations.
- DMZ (Semi-Trusted Zone): Hosts public-facing servers such as a web server or mail server.

## 3. Firewall as DHCP Server
When I first played around with pfSense, one of the things I wanted to try was DHCP. DHCP basically automatically assigns IPs on every machine in the network. This is super useful if you don’t want to bother about asigning new machine IP address by yourseelf. Although in certain case where, static IP is more prefer for critical server that require consistent IP.

So here’s the idea, I configure pfSense to act as the DHCP server for both of these subnet. That way, whenever a new VM boots up, it just asks pfSense for an IP and pfSense will auto assign it based on the remaining address ppol:

- LAN (192.168.1.0/24): `192.168.1.99 - 192.168.1.200`
- DMZ (192.168.2.0/24): `192.168.2.10	- 192.168.2.100`

### How I Set It Up

1. Log into the pfSense web dashboard.
2. Go to Services > DHCP Server.
3. On the LAN tab, tick “Enable DHCP.”
4. Set the range of address pool for LAN and DMZ.

That’s it. Now pfSense is ready to hand out addresses automatically.

### Testing It

Once DHCP is enabled, I just start up one of my Linux VMs and run:
```
ip a
```

<img width="897" height="312" alt="image" src="https://github.com/user-attachments/assets/3fa6e2bd-65ba-4440-b54f-7888e57194c4" />


Kali VM picks up an IP from pfSense automatically. I also check with `dhclient` to see how the DHCP process work behind the scene. 
<img width="726" height="261" alt="image" src="https://github.com/user-attachments/assets/69259637-4174-43bb-9425-00d197121525" />


To double-check, I also looked at the DHCP Leases page in pfSense, and I could see my Kali machine listed there with the IP it got assigned.
<img width="654" height="457" alt="image" src="https://github.com/user-attachments/assets/8d948f5f-7327-4e3f-ba6d-6c5a30dea367" />

## 4. Firewall Rules
Now we’re moving to the main feature of a firewall — filtering traffic that goes inbound and outbound through each interface.

The way pfSense (and most firewalls) works is by applying rules. A rule usually defines:

- source 
- destination 
- port/service being used (like HTTP, HTTPS, SSH, etc.).

For each rule, you decide whether to allow or block that traffic.

One important thing to remember is that firewall rules are checked from top to bottom. That means the order matters: you should place the most specific rules at the top, and more general rules at the bottom. This way, pfSense knows exactly what to do before it falls back to a default action.
<img width="1001" height="428" alt="image" src="https://github.com/user-attachments/assets/a81132c3-f760-486d-9799-b3eb56255fdc" />

I wanted to create a simple rule where all devices in LAN cannot access HTTP website.

### How I Set It Up

1. Logged into pfSense → Firewall > Rules > LAN.
2. Added a new rule:

- Action: Block
- Protocol: TCP
- Source: LAN net (all LAN devices)
- Destination: Any
- Destination Port: 80 (HTTP)
- Moved this rule above the default “Allow LAN to Any” rule
  
### Testing the Rule

- Before the rule: From my Kali VM, I ran curl http://httpforever.com and got the page content back.
<img width="1350" height="460" alt="image" src="https://github.com/user-attachments/assets/af0cec11-9a58-4523-97bd-fcef5a113ad4" />

- After enabling the rule: Same command gave me no response, and the page wouldn’t load in the browser.
<img width="945" height="554" alt="image" src="https://github.com/user-attachments/assets/4f7aea22-7d40-4c3d-a625-eb2a9d0fec33" />

That proved the rule was working — pfSense saw that my traffic was trying to use port 80 and blocked it. You can also enable the logs for the rules, as you can see several 
<img width="1114" height="205" alt="image" src="https://github.com/user-attachments/assets/f8b74cf2-ea3f-464d-8737-7df77665a8f6" />


## 5. DMZ Setup – Isolating Servers from the LAN

In most enterprise networks, we don’t put public-facing servers directly inside the LAN. Instead, we place them in a DMZ (Demilitarized Zone). The DMZ is a middle ground: servers here can talk to the Internet, but they’re isolated from the internal LAN to reduce the risk of lateral movement if the server gets hacked. For my homelab, I created a DMZ network (`192.168.2.0/24`) and set up a small Lubuntu VM in it. 

### How I Set It Up

1. Logged into pfSense → Firewall > Rules > OPT1 (rename into DMZ)
2. Added a new rule:

- Action: Block
- Protocol: Any
- Source: DMZ subnet
- Destination: LAN subnet
- Moved this rule at the top 
<img width="1162" height="307" alt="image" src="https://github.com/user-attachments/assets/44c8099f-f3d1-47f2-904a-b8970a43160a" />

### Testing the Rule

To make the exercise more realistic, I simulated an attacker who gained control of a Lubuntu VM in the DMZ. I then compared two cases, DMZ→LAN firewall rules disabled and with a block rule in place. This is to demonstrate how easy it is for an attacker to perform lateral movement into the LAN when segmentation is missing, and how a simple rule can prevent it.

With firewall rules disabled, the attacker on the Lubuntu VM can freely reach hosts on the LAN. For example, a simple `ping` to a LAN device succeeds because pfSense will route packets between subnets when there is no rule blocking them. Running `nmap` from the DMZ shows open SSH services at port 22. 

<img width="744" height="198" alt="image" src="https://github.com/user-attachments/assets/eff45b6f-a388-4f59-953e-8eb2fd1eac78" />


If the attacker can guess or obtain weak credentials, they can log in to the LAN host. In short, without explicit deny rules, there are nothing that stop lateral movement; in this case a compromise of a public-facing DMZ host can quickly lead to a compromise of internal systems.
<img width="787" height="381" alt="image" src="https://github.com/user-attachments/assets/7559288b-536a-431d-9e1c-0ef314c7726f" />


After enabling the block rule, pfSense drops any packets originating from the DMZ that are destined for the LAN. As a result, you can no longer `ping` the LAN host, `nmap` reports the host as down, and SSH connections time out. 
<img width="793" height="292" alt="image" src="https://github.com/user-attachments/assets/74159961-a519-4305-bf60-322d5644e912" />


 
