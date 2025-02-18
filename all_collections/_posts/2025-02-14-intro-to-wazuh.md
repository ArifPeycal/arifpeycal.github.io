---
layout: post
title: Introduction to Wazuh
date: 2025-02-14 19:26:00
categories: [dfir, wazuh, tutorial]
---

![image](https://github.com/user-attachments/assets/7578cdda-149a-44ca-817f-71a95db24243)


If want a simple yet powerful way to monitor and manage your network's security, you might want to check out Wazuh. It's an open-source security information and event management (SIEM) tool that provides threat detection, compliance monitoring, and incident response for endpoints.

Wazuh is all about helping you monitor your systems for any signs of malicious activity. It collects logs from different sources like servers, applications, and firewalls, and then analyzes them for suspicious patterns. What's cool is that it's designed to work well on a variety of platforms, including Linux, Windows, and even cloud environments.

## **Key Features of Wazuh**
1. **Intrusion Detection (HIDS & NIDS)**
- Monitors system and network activity for suspicious behavior.
- Uses rules to detect malicious activities, exploits, and unauthorized access.
  
2. **File Integrity Monitoring (FIM)**
- Detects changes in critical files or directories.
- Helps detect unauthorized modifications or malware infections.

3. **Log Data Analysis**
- Collects and analyzes system logs, application logs, and network logs.
- Detects security events like failed logins, privilege escalations, and brute-force attacks.
  
4. **Malware & Anomaly Detection**
- Scans for rootkits, trojans, and hidden processes.
- Detects malicious system modifications.
  
5. **Compliance Monitoring**
- Helps meet regulatory requirements (e.g., PCI DSS, GDPR, HIPAA).
- Monitors security settings and logs compliance violations.
  
6. **Incident Response**
- Supports automated responses to threats (e.g., blocking IPs, disabling users).
- Integrates with SIEM platforms for real-time threat hunting.


## **Wazuh Components**  

There are several components in Wazuh that work together to provide SIEM + XDR capabilities.  
![image](https://github.com/user-attachments/assets/1f673a1c-e823-4da8-b0f9-79982e7da7c9)

### **1. Wazuh Manager**  
This is the core of Wazuh. It processes data from agents, applies security rules, and generates alerts. The manager is responsible for log analysis, file integrity monitoring, intrusion detection, and compliance checks.  

### **2. Wazuh Agents**  
Agents are installed on the endpoints like servers, desktops, cloud instances, etc. The agents will collect security data and send it to the Wazuh Manager. They monitor logs, file changes, and system activity to detect threats.  

### **3. Wazuh Indexer**  
The indexer stores and indexes security data for efficient searching and analysis.  The Wazuh Indexer is like a huge filing cabinet where all reports are stored and allows users to find past incidents quickly by searching through old reports.

### **4. Wazuh Dashboard**  
The dashboard provides a graphical interface for analyzing logs, viewing alerts, and managing security events. It's built on Kibana and offers real-time insights into system security.  

### **5. Wazuh API**  
The API allows integration with other security tools and automation of tasks. It enables users to interact with Wazuh programmatically, retrieve alerts, manage agents, and perform searches.  


## **Setting Up Wazuh**  

Setting up Wazuh might seem complex at first, but once you break it down, it’s pretty straightforward.  

> Disclaimer: For this blog, I’ll be setting up Wazuh without an agent, well at least not yet. I will just use the Wazuh server to explore and learn some of its functionalities. This is purely for testing and getting familiar with how things work. In the next blog, I’ll go deeper and deploy an agent for full monitoring. Stay tuned!
<!--
The system infrastructure for this setup consists of three main components: Wazuh Manager, DVWA (Damn Vulnerable Web Application), and Kali Linux. The Wazuh Manager is installed on an Ubuntu virtual machine (VM) and collects logs from the agents. This Ubuntu VM also hosts DVWA to test security flaws such as SQL Injection, Cross-Site Scripting (XSS), and brute-force attacks.

On the attacker side, Kali Linux is used to simulate attacks on DVWA. Kali is loaded with various penetration testing tools like SQLmap, Hydra, and Burp Suite, which help in executing security attacks to evaluate the effectiveness of Wazuh’s monitoring. Wazuh detects and alerts on attacks by analyzing web server logs, system logs, and application logs on the Ubuntu VM.
-->
### **Quick Installation Wazuh**  
You can automate the instalation of the central components in Wazuh such as Manager, Dashboard and Indexer. For this tutorial, I want to make it quick and easy by installing Wazuh in single host. You can refer to this website if you want to install each component in different hosts (https://documentation.wazuh.com/current/installation-guide/index.html). 

1. Update your system:
   
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
2. Add the Wazuh repository and install the Wazuh components. This command will install central components of Wazuh including Manager, Indexer, Dashboard and Filebeat.
   
   ```bash
   curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh  
   sudo bash wazuh-install.sh -a  
   ```
3. Access the Wazuh web interface with `https://<WAZUH_DASHBOARD_IP_ADDRESS>` and your credentials:
   
   ```bash
   INFO: --- Summary ---
   INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
   User: admin
   Password: <ADMIN_PASSWORD>
   INFO: Installation finished.   
   ```

You have succesfully installed Wazuh!
![image](https://github.com/user-attachments/assets/64f98515-4a48-4cb4-942f-ea6e28b4058f)
<!--
### Step 2: Install DVWA (Ubuntu VM)
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

![image](https://github.com/user-attachments/assets/7df28dca-00f6-47b9-a68a-fb5810bc1e10)

![image](https://github.com/user-attachments/assets/5350e20f-34b3-4962-86e2-2775235281d8) 
![image](https://github.com/user-attachments/assets/5155f1b5-de11-4586-aa93-8a403f120951)
-->
---

## POC

Now, we can test the functionality of Wazuh in detecting threats and attacks. 

### 1. SQL Injection Attack

SQL Injection (SQLi) is a type of attack where an attacker injects malicious SQL code into an input field (like a login form or search bar). This can allow attackers to bypass authentication, steal data, or even delete entire databases. 

Wazuh default rules can detect any attempts of SQLi by analyzing web server logs (Apache, Nginx etc). 

1. Install Apache web server:
   ```bash
   sudo apt install apache2
   ```
2. Check the status of the Apache service to verify that the web server is running:

   ```bash
   sudo systemctl status apache2
   ```
3. Add the following configurations under `<ossec_config>` tag to the `/var/ossec/etc/ossec.conf` file. This allows the Wazuh agent to monitor the access logs of your Apache server:

   ```
     <localfile>
       <log_format>apache</log_format>
       <location>/var/log/apache2/access.log</location>
     </localfile>
   ```
4. Access the Apache webpage from attacker machine, in this case I'm using Kali Linux.
   
   ```bash
   curl -XGET http://192.168.245.131/users/?id=SELECT%20*%20FROM%20users;
   ```
5. Navigate to Overview page, we can see there is one SQLi alert detected by Wazuh from IP address `192.168.245.131` which is the Kali Linux VM.
![image](https://github.com/user-attachments/assets/8a98f777-9615-4194-a63d-c85ab04b07ce)

There is also page specifically for MITRE ATT&CK which it lists out events and its associated MITRE ATT&CK ID and tactics.
![image](https://github.com/user-attachments/assets/bf70d46a-d7ca-4345-b015-af50ab170da1)

### 2. Monitoring Execution of Malicious Commands

Monitoring user's commands is very important to detect any suspicious commands executed on a Linux machine. Wazuh, combined with Auditd, provides an efficient way to monitor and detect potentially harmful commands executed on a system that can lead to privilege escalation and unauthorized software execution. 

1. Install and configure Auditd. It allows us to log system calls and monitor command executions in real time.
   
   ```bash
   sudo apt -y install auditd
   sudo systemctl start auditd
   sudo systemctl enable auditd
   ```

2. Append audit rules to `/etc/audit/audit.rules` as root to track command executions. These rules will log all commands executed by user 1000 (excluding EGID 994) and assign them the key "audit-wazuh-c":

```bash
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b32 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b64 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
```

3. For Wazuh to monitor Auditd logs, we need to configure the Wazuh agent to read from `/var/log/audit/audit.log`. Open and modify the `/var/ossec/etc/ossec.conf` file on the Wazuh agent:

   ```xml
   <localfile>
     <log_format>audit</log_format>
     <location>/var/log/audit/audit.log</location>
   </localfile>
   ```

4. Define a list of potentially malicious commands. This list allows Wazuh to match executed commands and generate alerts accordingly. Create the file `/var/ossec/etc/lists/suspicious-programs` and add key-value pair according to your need. The value can be used to filter the alert according to the severity level:

   ```
   ncat:yellow
   nc:red
   sudo:red
   chmod:red
   ```

5. To make Wazuh recognize this list, add it to the `<ruleset>` section of the Wazuh server’s `/var/ossec/etc/ossec.conf` file:

   ```xml
   <list>etc/lists/suspicious-programs</list>
   ```

6. Create a custom rule to trigger alerts when commands in our list are executed. Edit the `/var/ossec/etc/rules/local_rules.xml` file and add the following rule:

   ```xml
   <group name="audit">
     <rule id="100210" level="12">
       <if_sid>80792</if_sid>
       <list field="audit.command" lookup="match_key_value" check_value="red">etc/lists/suspicious-programs</list>
       <description>Audit: Highly Suspicious Command executed: $(audit.exe)</description>
       <group>audit_command,</group>
     </rule>
   </group>
   ```

7. Restart the Wazuh manager to apply the changes:

   ```bash
   sudo systemctl restart wazuh-manager
   ```

9. Test the alert rules by executing a known "red" program such as `ncat` and `sudo`:
![image](https://github.com/user-attachments/assets/2a272a8d-1693-46ac-a00a-305704f61c43)

![image](https://github.com/user-attachments/assets/fe1e169d-ad4b-4e63-8975-82b76387b48b)

