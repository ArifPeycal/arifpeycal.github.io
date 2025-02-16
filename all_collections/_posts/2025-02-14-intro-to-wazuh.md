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

### **4. Wazuh Dashboard**  
The dashboard provides a graphical interface for analyzing logs, viewing alerts, and managing security events. It's built on Kibana and offers real-time insights into system security.  

### **5. Wazuh API**  
The API allows integration with other security tools and automation of tasks. It enables users to interact with Wazuh programmatically, retrieve alerts, manage agents, and perform searches.  

---

## **Setting Up Wazuh**  

Setting up Wazuh might seem complex at first, but once you break it down, it’s pretty straightforward.  
<!--
The system infrastructure for this setup consists of three main components: Wazuh Manager, DVWA (Damn Vulnerable Web Application), and Kali Linux. The Wazuh Manager is installed on an Ubuntu virtual machine (VM) and collects logs from the agents. This Ubuntu VM also hosts DVWA to test security flaws such as SQL Injection, Cross-Site Scripting (XSS), and brute-force attacks.

On the attacker side, Kali Linux is used to simulate attacks on DVWA. Kali is loaded with various penetration testing tools like SQLmap, Hydra, and Burp Suite, which help in executing security attacks to evaluate the effectiveness of Wazuh’s monitoring. Wazuh detects and alerts on attacks by analyzing web server logs, system logs, and application logs on the Ubuntu VM.
-->
### **Quick Install Wazuh Manager, Dashboard, Indexer etc**  
The Wazuh Manager is the core component responsible for processing data and generating alerts. Wazuh Dashboard allows you to interact using interactive web interface. 

1. Update your system:  
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```
2. Add the Wazuh repository and install the Wazuh Manager. This command will install central components of Wazuh including Manager, Indexer, Dashboard and Filebeat.  
   ```bash
   curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh  
   sudo bash wazuh-install.sh -a  
   ```
3. Access the Wazuh web interface with https://<WAZUH_DASHBOARD_IP_ADDRESS> and your credentials:  
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

1. Install and configure Auditd. It allows us to log system calls and monitor command executions in real time. To install and enable Auditd, run the following commands:
   ```bash
   sudo apt -y install auditd
   sudo systemctl start auditd
   sudo systemctl enable auditd
   ```

2. Append audit rules to track command executions. These rules log all commands run by users with a specific UID, helping us keep an eye on activities that may indicate an attack. Run the following commands as root to modify the `/etc/audit/audit.rules` file:

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

4. Save the changes and restart the Wazuh manager:

   ```bash
   sudo systemctl restart wazuh-manager
   ```

5. Define a list of potentially malicious commands. This list allows Wazuh to match executed commands and generate alerts accordingly. Create the file `/var/ossec/etc/lists/suspicious-programs` and add key-value pair according to your need. The value can be used to filter the alert according to the severity level:

   ```
   ncat:yellow
   nc:red
   sudo:red
   chmod:red
   ```

6. To make Wazuh recognize this list, add it to the `<ruleset>` section of the Wazuh server’s `/var/ossec/etc/ossec.conf` file:

   ```xml
   <list>etc/lists/suspicious-programs</list>
   ```

7. Create a custom rule to trigger alerts when commands in our list are executed. Edit the `/var/ossec/etc/rules/local_rules.xml` file and add the following rule:

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

8. Restart the Wazuh manager to apply the changes:

   ```bash
   sudo systemctl restart wazuh-manager
   ```

9. Test the alert rules by executing a known "red" program such as `ncat` and `sudo`:
![image](https://github.com/user-attachments/assets/2a272a8d-1693-46ac-a00a-305704f61c43)

![image](https://github.com/user-attachments/assets/fe1e169d-ad4b-4e63-8975-82b76387b48b)


## **Wrapping Up**  
Wazuh is a powerful yet free tool for security monitoring. With its components working together, it provides deep insights into system security, detects threats, and ensures compliance. Once set up, you can start analyzing logs, detecting intrusions, and keeping your infrastructure secure. If you're serious about cybersecurity, Wazuh is definitely worth adding to your toolkit! 🚀
