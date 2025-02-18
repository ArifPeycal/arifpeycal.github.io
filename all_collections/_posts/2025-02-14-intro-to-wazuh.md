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
- Integrates with third-party API such as VirusTotal for real-time threat hunting.


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

> Disclaimer: For this blog, I’ll be setting up Wazuh without an agent, well at least not yet. I will just use the Wazuh server to explore and learn some of its functionalities. This is purely for testing and getting familiar with how things work. 

The system infrastructure for this setup consists of three main components: Wazuh Manager, DVWA (Damn Vulnerable Web Application) on Docker, and Kali Linux VM. The Wazuh Manager is installed on an Ubuntu virtual machine (VM) and collects logs from the agents. This Ubuntu VM also hosts DVWA to test security flaws such as SQL Injection, Cross-Site Scripting (XSS), and Local File Inclusion (LFI).

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


### 3. Monitoring Docker events
Wazuh provides `<docker-listerner>` module that enables real-time monitoring of Docker events. Docker listener collects and sends these logs to the Wazuh server for analysis and alerting. This module helping detect suspicious activities such as:

- **Container creation, deletion, or modification**
- **Image downloads (pulls) from untrusted sources**
- **Privilege escalations within containers**

For this use case, I will try to run DVWA on Docker container to monitor Docker events from user's interaction and web logs using Wazuh.

#### Monitor Docker Events from User's Interaction
1. Install Docker and Pull DVWA Image
```bash
sudo apt install docker.io -y
sudo systemctl enable --now docker
sudo docker pull vulnerables/web-dvwa
```


2. Run DVWA in a Docker Container
```bash
sudo docker run --name dvwa -d -p 80:80 vulnerables/web-dvwa
```
3. **Restart the Wazuh manager** to apply changes. Once enabled, the Docker listener monitors events such as:
| Event Type       | Description | Example Trigger |
|-----------------|-------------|----------------|
| **Container Start** | Detects when a container is launched | `docker run -d <container_name>` |
| **Container Stop** | Detects when a container is stopped | `docker stop <container_id>` |
| **Container Remove** | Logs container deletions | `docker rm <container_id>` |
| **Image Pull** | Detects image downloads | `docker pull ubuntu:latest` |
| **Privileged Mode** | Flags containers running with root privileges | `docker run --privileged` |

4. Navigate to Threat Hunting page and you can see some Docker activities such as Docker container has been started.
![image](https://github.com/user-attachments/assets/6eca8d16-13b7-48ab-aec6-ae80526b791d

#### Monitor DVWA Runtime Logs

1. If you had already run DVWA image, DVWA will now be accessible at: `http://[Ubuntu_VM_IP]/`
![image](https://github.com/user-attachments/assets/7df28dca-00f6-47b9-a68a-fb5810bc1e10)
2. Configure Wazuh Manager to forward the logs to Wazuh Manager by adding these configurations to `/var/ossec/etc/ossec.conf`:
   
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/lib/docker/containers/*/*-json.log</location>
</localfile>
```
You can also use `/var/lib/docker/containers/<CONTAINER_ID>/<CONTAINER_ID>-json.log` instead of wildcard (`*`) if you want to be more specific on which container you want to monitor.

3. Add the following decoders to the `/var/ossec/etc/decoders/local_decoder.xml` decoder file on the Wazuh manager:

```xml
<decoder name="web-accesslog-docker">
  <parent>json</parent>
  <type>web-log</type>
  <use_own_name>true</use_own_name>
  <prematch offset="after_parent">^log":"\S+ \S+ \S+ \.*[\S+ \S\d+] \.*"\w+ \S+ HTTP\S+" \d+</prematch>
  <regex offset="after_parent">^log":"(\S+) \S+ \S+ \.*[\S+ \S\d+] \.*"(\w+) (\S+) HTTP\S+" (\d+)</regex>
  <order>srcip,protocol,url,id</order>
</decoder>

<decoder name="json">
  <parent>json</parent>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

`web-accesslog-docker` decoder will parse relevant fields from the web log, and sets the log type to `web-log` so the Wazuh analysis engine can analyze the log for web attacks. `json` decoder will ensure that Wazuh can parse the log when `web-accesslog-docker` failed to meet the format stated. 

![image](https://github.com/user-attachments/assets/735d855c-9f95-4588-a756-d14cc9043341)
 
4. Demonstrate some `SQLI` attacks using `UNION` query:

```sql
'UNION SELECT user, password FROM user #
```

![image](https://github.com/user-attachments/assets/399c0cf0-31d4-42cd-9b35-e11875ee17da)
 
5. Navigate to **Threat Hunting** and monitor the log alerts created by Docker container. You can see some alert about web attack being successfully executed.

![image](https://github.com/user-attachments/assets/31b0a4ca-b4a4-4bd8-891c-2378722711de)

MITRE ATT&CK page also gives important information about MITRE ATT&CK ID and its TTP.
![image](https://github.com/user-attachments/assets/ef13e40d-9ab4-4a0d-af8f-c2085124ce84)

6. I also tried exploiting `LFI` and `XSS` to see if the default Wazuh rules can detect other types of web attacks:

- **LFI** to access `etc/passwd`

![image](https://github.com/user-attachments/assets/2b943273-e830-4277-a14c-e4e281688472)

- XSS using `<script>alert(1)</script>`
  
![image](https://github.com/user-attachments/assets/d1db1364-01e7-4f62-8f04-eba1a4facdb0)

