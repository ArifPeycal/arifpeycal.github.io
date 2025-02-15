---
layout: post
title: Introduction to Wazuh
date: 2025-02-14 19:26:00
categories: [dfir, tutorial]
---

![image](https://github.com/user-attachments/assets/7578cdda-149a-44ca-817f-71a95db24243)


If you're into cybersecurity and want a simple yet powerful way to monitor and manage your network's security, you might want to check out Wazuh. It's an open-source security information and event management (SIEM) tool that does a lot of the heavy lifting when it comes to detecting threats, compliance monitoring, and incident response.

Wazuh is all about helping you monitor your systems for any signs of malicious activity. It collects logs from different sources like servers, applications, and firewalls, and then analyzes them for suspicious patterns. What's cool is that it's designed to work well on a variety of platforms, including Linux, Windows, and even cloud environments.

One of the key features of Wazuh is its ability to detect intrusions and respond to them, kinda XDR-like capabilities. It uses things like file integrity monitoring, real-time alerts and active response to make sure the system is running smoothly. It’s also handy for compliance because it can help you meet regulations like PCI-DSS, HIPAA, or GDPR by tracking and reporting on security events that are relevant to those standards.

---

## **Wazuh Components**  

There are several components in Wazuh that work together to provide SIEM + XDR capabilities.  

![image](https://github.com/user-attachments/assets/bae191e1-596f-43f1-b8fc-8690a4b63ea1)

### **1. Wazuh Manager (Server)**  
This is the core of Wazuh. It processes data from agents, applies security rules, and generates alerts. The manager is responsible for log analysis, file integrity monitoring, intrusion detection, and compliance checks.  

### **2. Wazuh Agents**  
Agents are installed on the endpoints like servers, desktops, cloud instances, etc. The agents will collect security data and send it to the Wazuh Manager. They monitor logs, file changes, and system activity to detect threats.  

### **3. Wazuh Indexer**  
The indexer stores and indexes security data for efficient searching and analysis.  The Wazuh Indexer is like a huge filing cabinet where all reports are stored and allows users to find past incidents quickly by searching through old reports.

### **4. Wazuh Dashboard (Kibana UI)**  
The dashboard provides a graphical interface for analyzing logs, viewing alerts, and managing security events. It's built on Kibana and offers real-time insights into system security.  

### **5. Wazuh API**  
The API allows integration with other security tools and automation of tasks. It enables users to interact with Wazuh programmatically, retrieve alerts, manage agents, and perform searches.  

---

## **Setting Up Wazuh**  

Setting up Wazuh might seem complex at first, but once you break it down, it’s pretty straightforward.  

The system infrastructure for this setup consists of three main components: Wazuh Manager, DVWA (Damn Vulnerable Web Application), and Kali Linux. The Wazuh Manager is installed on an Ubuntu virtual machine (VM) and collects logs from the agents. This Ubuntu VM also hosts DVWA to test security flaws such as SQL Injection, Cross-Site Scripting (XSS), and brute-force attacks.

On the attacker side, Kali Linux is used to simulate attacks on DVWA. Kali is loaded with various penetration testing tools like SQLmap, Hydra, and Burp Suite, which help in executing security attacks to evaluate the effectiveness of Wazuh’s monitoring. Wazuh detects and alerts on attacks by analyzing web server logs, system logs, and application logs on the Ubuntu VM.

### **Step 1: Install Wazuh Manager (Ubuntu VM)**  
The Wazuh Manager is the core component responsible for processing data and generating alerts. You’ll need a Linux machine (Ubuntu, Debian, or CentOS recommended).  

1. Update your system:  
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
2. Add the Wazuh repository and install the Wazuh Manager:  
   ```bash
   curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh  
   sudo bash wazuh-install.sh --wazuh-manager  
   ```
3. Start and enable the Wazuh Manager service:  
   ```bash
   sudo systemctl enable --now wazuh-manager  
   ```

### **Step 2: Install Wazuh Dashboard (Ubuntu VM)**  
For a user-friendly interface, Wazuh integrates with **Elastic Stack** (Elasticsearch, Logstash, Kibana).  

1. Install the Wazuh Dashboard:  
   ```bash
   sudo bash wazuh-install.sh --wazuh-dashboard  
   ```
2. Start the service:  
   ```bash
   sudo systemctl enable --now wazuh-dashboard  
   ```
3. Access the dashboard by going to `http://<your-server-ip>:5601` in your browser.

### Step 3: Install DVWA (Ubuntu VM)
We will use Docker to install DVWA quickly.

1. Install Docker & Pull DVWA Image
```bash
sudo apt install docker.io -y
sudo systemctl enable --now docker
sudo docker pull vulnerables/web-dvwa
```
2. Run DVWA in a Docker Container
```bash
sudo docker run --name dvwa -d -p 80:80 vulnerables/web-dvwa
```
3. DVWA will now be accessible at: http://[Ubuntu_VM_IP]/

### **Step 4: Install Wazuh Agent (Ubuntu VM)**  
The Wazuh Agent collects data from the machine it's installed on and sends it to the Wazuh Manager.  

1. Add the Wazuh repository:  
   ```bash
   curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh  
   sudo bash wazuh-install.sh --wazuh-agent  
   ```
2. Configure the agent to connect to the Wazuh Manager:  
   ```bash
   sudo nano /var/ossec/etc/ossec.conf  
   ```
3. Find this section and set the manager IP to 127.0.0.1 (since it's the same machine):
   ```xml
   <server>
     <address>127.0.0.1</address>
   </server>
   ```

4. Restart the agent: 
   ```bash
   sudo systemctl restart wazuh-agent
   sudo systemctl enable --now wazuh-agent  
   ```
---

## **Wrapping Up**  
Wazuh is a powerful yet free tool for security monitoring. With its components working together, it provides deep insights into system security, detects threats, and ensures compliance. Once set up, you can start analyzing logs, detecting intrusions, and keeping your infrastructure secure. If you're serious about cybersecurity, Wazuh is definitely worth adding to your toolkit! 🚀
