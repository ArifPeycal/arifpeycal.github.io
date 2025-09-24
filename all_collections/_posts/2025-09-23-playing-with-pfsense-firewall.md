---
layout: post
title: Playing with PfSense Firewall
date: 2025-09-23 16:26:00
categories: [pfsense,networking, tutorial]
---

## 1. Introduction

I finally have the opportunity to continue my homelab project. This project was inspired by my internship as a Network Security Intern, where I was exposed to many security tools—especially firewalls. During that time, I realized something important: although I had heard a lot about firewalls, I didn’t actually know how they looked or worked in practice.

My initial assumption was that a firewall was simply software, like the built-in Microsoft Firewall. However, in enterprise environments, a firewall is usually a dedicated networking appliance that sits between different network segments, inspecting and controlling traffic.

Since hardware firewalls are expensive (and frankly an overkill for a learning environment), I decided to explore the best open-source alternative available: pfSense.

### What is pfSense?

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

1. Firewall as DHCP Server – pfSense provides IP addresses to internal hosts.
2. Network Segmentation – WAN, LAN, and DMZ setup.
3. Firewall Rules – controlling inbound and outbound traffic.
4. Web Server in DMZ – exposing services while keeping LAN secure.

## 2. Network Architecture

The virtual lab is designed to resemble a typical enterprise network with three main zones:

- WAN (Untrusted Zone): Simulates the internet.
- LAN (Trusted Zone): Represents internal users and workstations.
- DMZ (Semi-Trusted Zone): Hosts public-facing servers such as a web server or mail server.

## 3. Firewall as DHCP Server


<img width="945" height="554" alt="image" src="https://github.com/user-attachments/assets/4f7aea22-7d40-4c3d-a625-eb2a9d0fec33" />

<img width="1114" height="205" alt="image" src="https://github.com/user-attachments/assets/f8b74cf2-ea3f-464d-8737-7df77665a8f6" />

<img width="1350" height="460" alt="image" src="https://github.com/user-attachments/assets/af0cec11-9a58-4523-97bd-fcef5a113ad4" />

🟢 Step 1: LAN Rules

Goal: Allow LAN clients → Internet, but not directly to DMZ.

1, Go to Firewall > Rules > LAN.

2. Delete the default “LAN to any” rule.

3. Add rules:

- Allow LAN → WAN

  - Action: Pass
  
  - Interface: LAN
  
  - Source: LAN net
  
  - Destination: any
  
  - Save + Apply

- Block LAN → DMZ

  - Action: Block
  
  - Interface: LAN
  
  - Source: LAN net
  
  - Destination: DMZ net
  
  - Save + Apply

✅ LAN can browse internet, but cannot reach DMZ.

🟠 Step 2: DMZ Rules

Goal: Allow DMZ servers → Internet for updates, block DMZ → LAN.

Go to Firewall > Rules > DMZ.

Add rules:

Block DMZ → LAN

Action: Block

Interface: DMZ

Source: DMZ net

Destination: LAN net

Allow DMZ → WAN

Action: Pass

Interface: DMZ

Source: DMZ net

Destination: any

Save + Apply.

✅ DMZ servers can go out to WAN, but cannot reach LAN.
<img width="1162" height="307" alt="image" src="https://github.com/user-attachments/assets/44c8099f-f3d1-47f2-904a-b8970a43160a" />

From DMZ 192.L168.2.10, cannot ping to LAN network in this case I try toi ping the Windo host ip at 192.168.1.101.
<img width="795" height="76" alt="Screenshot 2025-09-24 152927" src="https://github.com/user-attachments/assets/cd48d8a9-064e-439e-9ab8-fb8d3a7064b7" />

 
