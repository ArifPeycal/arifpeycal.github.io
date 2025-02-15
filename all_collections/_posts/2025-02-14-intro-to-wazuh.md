---
layout: post
title: Introduction to Wazuh
date: 2025-02-14 19:26:00
categories: [dfir, tutorial]
---

![image](https://github.com/user-attachments/assets/5b01ab40-cbd2-453a-a512-3066ce7b2e30)

![image](https://github.com/user-attachments/assets/7578cdda-149a-44ca-817f-71a95db24243)


If you're into cybersecurity and want a simple yet powerful way to monitor and manage your network's security, you might want to check out Wazuh. It's an open-source security information and event management (SIEM) tool that does a lot of the heavy lifting when it comes to detecting threats, compliance monitoring, and incident response.

Wazuh is all about helping you monitor your systems for any signs of malicious activity. It collects logs from different sources like servers, applications, and firewalls, and then analyzes them for suspicious patterns. What's cool is that it's designed to work well on a variety of platforms, including Linux, Windows, and even cloud environments.

One of the key features of Wazuh is its ability to detect intrusions and respond to them, kinda XDR-like capabilities. It uses things like file integrity monitoring, real-time alerts and active response to make sure the system is running smoothly. It’s also handy for compliance because it can help you meet regulations like PCI-DSS, HIPAA, or GDPR by tracking and reporting on security events that are relevant to those standards.

---

## **Wazuh Components**  

Wazuh is made up of several key components that work together to collect, analyze, and visualize security data:  

### **1. Wazuh Manager**  
This is the core of Wazuh. It processes data from agents, applies security rules, and generates alerts. The manager is responsible for log analysis, file integrity monitoring, intrusion detection, and compliance checks.  

### **2. Wazuh Agents**  
Agents are installed on the endpoints (servers, desktops, cloud instances, etc.) to collect security data and send it to the Wazuh Manager. They monitor logs, file changes, and system activity to detect threats.  

### **3. Wazuh Indexer (Based on OpenSearch)**  
The indexer stores and indexes security data for efficient searching and analysis. It replaces Elasticsearch in newer Wazuh versions and is optimized for performance and scalability.  

### **4. Wazuh Dashboard (Kibana UI)**  
The dashboard provides a graphical interface for analyzing logs, viewing alerts, and managing security events. It's built on Kibana and offers real-time insights into system security.  

### **5. Wazuh API**  
The API allows integration with other security tools and automation of tasks. It enables users to interact with Wazuh programmatically, retrieve alerts, manage agents, and perform searches.  

---

## **Setting Up Wazuh**  

Setting up Wazuh might seem complex at first, but once you break it down, it’s pretty straightforward.  

### **Step 1: Install Wazuh Manager**  
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

### **Step 2: Install Wazuh Agent (On a Client Machine)**  
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
   Find the `<address>` tag and enter the IP of your Wazuh Manager.  
3. Restart the agent: 
   ```bash
   sudo systemctl enable --now wazuh-agent  
   ```

### **Step 3: Install Wazuh Dashboard (For Visualization)**  
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

---

## **Wrapping Up**  
Wazuh is a powerful yet free tool for security monitoring. With its components working together, it provides deep insights into system security, detects threats, and ensures compliance. Once set up, you can start analyzing logs, detecting intrusions, and keeping your infrastructure secure. If you're serious about cybersecurity, Wazuh is definitely worth adding to your toolkit! 🚀
