---
layout: post
title: Setting Up Wazuh Agent
date: 2025-02-16 19:26:00
categories: [dfir, tutorial]
---

In my previous post, I explored Wazuh without an agent, just to get a feel for how things work. Now, it’s time to level up and deploy the Wazuh agent on an **Ubuntu VM** to start monitoring system activities properly. This guide will walk through the setup process step by step.  

---

## 🛠 Prerequisites  
Before we begin, make sure:  
✅ You have a **Wazuh Manager** running.  
✅ You have **sudo** privileges on the Ubuntu VM.  

![image](https://github.com/user-attachments/assets/e2188b6f-21c5-42fb-bc00-00dda1b0f50f)

---

## Step 1: Install the Wazuh Agent
First, access the Wazuh Dashboard using `https://WAZUH-MANAGER-IP`, make sure you remember the login credentials. On the Homepage, click the Deploy Agent button and follow the instructions.
![image](https://github.com/user-attachments/assets/2fbca750-be9a-479a-9422-ee80b073676b)

You need to choose correct package according to the agent's OS. In my case, I am using Ubuntu so I choose `amd64`.
![image](https://github.com/user-attachments/assets/491f4875-7837-4a7a-b09b-7737fdc0705c)

There are several things that you need to configure such as agent name and server IP. Then, copy and run the command in the agent VM.

![image](https://github.com/user-attachments/assets/5c9f590c-8988-4e84-9f35-335b1cc52d3a)

## Step 2: Configure the Agent
Edit the Wazuh agent config file:
  ```bash
  sudo nano /var/ossec/etc/ossec.conf
  ```
Look for the <client> section and update the <address> field to point to your Wazuh Manager’s IP:
  ```xml
  <client>
    <server>
      <address>YOUR_WAZUH_MANAGER_IP</address>
      <port>1514</port>
    </server>
  </client>
```
The Wazuh agent communicates with the manager using port 1514 (TCP). Make sure the firewall on Wazuh Manager isn't blocking it:
  ```bash
  sudo ufw allow 1514/tcp
  ```

## Step 3: Enable and Start the Agent
Now, enable and start the Wazuh agent:
  ```bash
  sudo systemctl daemon-reload
  sudo systemctl enable wazuh-agent
  sudo systemctl start wazuh-agent
  ```
Check if it’s running:
  ```bash
  sudo systemctl status wazuh-agent
  ```
If you see "active (running)", then you're good to go! 🎉

## Step 4: Verify Connection on Wazuh Manager
Go to your Wazuh Manager and check if the agent is connected:
![image](https://github.com/user-attachments/assets/c27ad474-9bd7-4ef8-858e-d3410b419579)


If the agent appears in the list, everything is working fine. If not, you might need to check firewall settings or restart the Wazuh Manager.
  ```bash
  sudo systemctl restart wazuh-manager
  ```


# Exploring Agents Functionalities

Now it is the time to explore what Wazuh Agent has to offer. Straight off, one of the features that attracts my attention is the Regulatory Compliance dashboard. Since my internship will be mainly on GRC, it's great if I can see how a SIEM can integrate to track compliance. 

## 1. Regulatory Compliance
The compliance feature in the Wazuh agent helps ensure that your system follows security best practices, regulatory standards, and internal policies. It continuously monitors configurations, permissions, and security settings to detect any non-compliance issues. 

There are several standards that you can refer to and there are many well-known security standards like PCI-DSS, NIST, and GDPR. For example, I get an alert from PCI-DSS Requirement 10.6.1 that requires me to review security logs from devices such as firewall, IDP, IPS etc on a regular basis.


![image](https://github.com/user-attachments/assets/b0d59522-1092-4e64-8c86-612f5557e729)

## 2. Vulnerability Detection
This feature helps identify security weaknesses in your system by scanning for known vulnerabilities (CVEs) and ensuring that your system is up-to-date with patches.

From the dashboard, you see the vulnerabilities according to their severity levels. There is also lists of CVEs related to the agent which can help us to patch the vulnerabilities.

For example, `CVE-2024-26458`, `CVE-2024-26461`, `CVE-2024-26462` related to Kerberos 5 1.21.2 that contains a memory leak vulnerability. 

References:
- https://ubuntu.com/security/CVE-2024-26458
- https://ubuntu.com/security/CVE-2024-26461
- https://ubuntu.com/security/CVE-2024-26462

![image](https://github.com/user-attachments/assets/4894b3c5-2583-442f-8773-08cc239adea1)

## 3. File Monitoring 

Wazuh also can tracks changes of file attributes such as modifications, creations, deletions and access times in critical files and directories on a system. This allows security teams to identify unauthorized changes, which could indicate malicious activity or system compromise. Wazuh compares the current state of monitored files with a baseline and will generates alerts whenever changes occur.

1. Edit the Wazuh Agent Configuration
   
On your Ubuntu agent, open the configuration file:
  ```bash
  sudo nano /var/ossec/etc/ossec.conf
  ```
Find the <syscheck> section (or add it if missing), and define which directories to monitor:
  ```xml
  <syscheck>
    <!-- Scan system binaries and config files -->
    <directories check_all="yes" report_changes="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">/var/www/html</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">/home/<user></directories>
  
    <!-- Frequency of checks (in seconds) -->
    <frequency>3600</frequency>
  
    <!-- Alert when file changes -->
    <alert_new_files>yes</alert_new_files>
    <auto_ignore>no</auto_ignore>
  </syscheck>
  ```
Apply the changes by restarting the agent:

  ```bash
  sudo systemctl restart wazuh-agent
  ```

2. Test File Integrity Monitoring
   
Try creating, modifying, and deleting a file in a monitored directory:
  ```bash
  sudo touch /home/<user>/test.txt
  echo "Test" | sudo tee -a /home/<user>/test.txt
  sudo rm /home/<user>/test.txt
  ```
![image](https://github.com/user-attachments/assets/6c9ee97d-95be-4022-950d-0a7e52495a97)

I also tried modifying `/etc/passwd`, and Wazuh successfully detected the changes. It also shows the difference between the original and modified file.

![image](https://github.com/user-attachments/assets/6e0c8ee9-abec-4966-a5db-d1bed0120b6d)

For the compliance part, I look up to alert by PCI-DSS Requirement 11.5 which mentions about deploying file integrity monitoring to detect any malicious file changes.

![image](https://github.com/user-attachments/assets/8ce25fc5-9fd6-4fd3-96f2-059d4699bb79)


![image](https://github.com/user-attachments/assets/c00475fa-9d6d-4303-a1d7-9dccbaa2fa86)

![image](https://github.com/user-attachments/assets/c61419e3-2669-4a24-8252-9a474e30afe8)





## 🎯 Conclusion  
That’s it! Your Ubuntu VM is now running the Wazuh agent and sending logs to the manager. In the next post, I'll explore how to fine-tune the agent and set up rules for detecting **suspicious activity** like XSS and SQLi. Stay tuned!  
 

