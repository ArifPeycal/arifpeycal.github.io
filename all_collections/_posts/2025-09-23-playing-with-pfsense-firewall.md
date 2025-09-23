---
layout: post
title: Playing with PfSense Firewall
date: 2025-09-23 16:26:00
categories: [pfsense,networking, tutorial]
---

In my previous post, I explored Wazuh without an agent, just to get a feel for how things work. Now, it’s time to level up and deploy the Wazuh agent on an **Ubuntu VM** to start monitoring system activities properly. This guide will walk through the setup process step by step.  


## 🛠 Prerequisites  
Before we begin, make sure:  
✅ You have a **Wazuh Manager** running.  
✅ You have **sudo** privileges on the Ubuntu VM.  

![image](https://github.com/user-attachments/assets/e2188b6f-21c5-42fb-bc00-00dda1b0f50f)

## Step 1: Install the Wazuh Agent
First, access the Wazuh Dashboard using `https://WAZUH-MANAGER-IP`, make sure you remember the login credentials. On the Homepage, click the Deploy Agent button and follow the instructions.

![image](https://github.com/user-attachments/assets/2fbca750-be9a-479a-9422-ee80b073676b)

You need to choose correct package according to the agent's OS. In my case, I am using Ubuntu so I choose `DEB amd64`.
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
![image](https://github.com/user-attachments/assets/4894b3c5-2583-442f-8773-08cc239adea1)


References:
- https://ubuntu.com/security/CVE-2024-26458
- https://ubuntu.com/security/CVE-2024-26461
- https://ubuntu.com/security/CVE-2024-26462


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


## 4. Detecting Suspicious Binaries

Wazuh provides malware detection capabilities to identify suspicious binaries such as trojan on an endpoint. A Trojan is a type of malware that disguises itself as a legitimate program to trick users into running it. Once executed, a Trojan can perform malicious actions such as stealing data, opening backdoors, or allowing attackers to gain unauthorized access to a system.

Wazuh helps detect legitimate system binaries (usually at `/usr/bin/`) that have been modified to execute malicious code while still appearing normal. This allows security teams to identify and mitigate potential compromises.

### Configuration
   
By default, the Wazuh Rootcheck module is enabled in the Wazuh agent’s configuration. To confirm this, check the `<rootcheck>` section in `/var/ossec/etc/ossec.conf` on the agent and ensure it includes the following configuration:

```xml
<rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>

    <!-- Enable Trojan detection -->
    <check_trojans>yes</check_trojans>

    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Scan frequency: every 12 hours -->
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
</rootcheck>
```

If we look at `/var/ossec/etc/shared/rootkit_trojans.txt`, we can see several commands that become signature of trojans to do malicious activities when being executed.
```
# Common binaries and public trojan entries
ls          !bash|^/bin/sh|dev/[^clu]|\.tmp/lsfile|duarawkz|/prof|/security|file\.h!
env         !bash|^/bin/sh|file\.h|proc\.h|/dev/|^/bin/.*sh!
echo        !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chown       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chmod       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
chgrp       !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
cat         !bash|^/bin/sh|file\.h|proc\.h|/dev/[^cl]|^/bin/.*sh!
bash        !proc\.h|/dev/[0-9]|/dev/[hijkz]!
```

On the other hand, `/var/ossec/etc/shared/rootkit_files.txt` contains a list of known trojan-related files that Wazuh Rootcheck scans for on monitored endpoints. This list helps detect the presence of malicious files commonly associated with rootkits.
```
# Bash door
tmp/mcliZokhb           ! Bash door ::/rootkits/bashdoor.php
tmp/mclzaKmfa           ! Bash door ::/rootkits/bashdoor.php

# adore Worm
dev/.shit/red.tgz       ! Adore Worm ::/rootkits/adorew.php
usr/lib/libt            ! Adore Worm ::/rootkits/adorew.php
usr/bin/adore           ! Adore Worm ::/rootkits/adorew.php
*/klogd.o               ! Adore Worm ::/rootkits/adorew.php
*/red.tar               ! Adore Worm ::/rootkits/adorew.php
```
### Simulating a Suspicious Binary Attack

1. First, create a backup of an existing system binary before modifying it:
```bash
sudo cp -p /usr/bin/w /usr/bin/w.copy
```
2. Replace the legitimate binary with a malicious script that performs unauthorized actions:
```bash
sudo tee /usr/bin/w << EOF
#!/bin/bash
echo "\$(date) - This is an evil script" > /tmp/trojan_created_file
echo "Test for /usr/bin/w trojaned file" >> /tmp/trojan_created_file
# Running the original binary
/usr/bin/w.copy
EOF
```
This script logs a fake message and then executes the original binary to maintain normal functionality, making it harder to detect.

3. The Rootcheck scan runs every 12 hours by default, but you can force a scan immediately by restarting the Wazuh agent:
```bash
sudo systemctl restart wazuh-agent
```
4. Once the scan completes, Wazuh detects the modified binary and generates an alert. Navigate to the Threat Hunting module in the Wazuh dashboard.
![image](https://github.com/user-attachments/assets/c00475fa-9d6d-4303-a1d7-9dccbaa2fa86)

You can also use the search filter to monitor specific alert:
```
location:rootcheck AND rule.id:510 AND data.title:Trojaned version of file detected.
```
![image](https://github.com/user-attachments/assets/c61419e3-2669-4a24-8252-9a474e30afe8)


## 🎯 Conclusion  
That’s it! Ubuntu VM is now running the Wazuh agent and sending logs to the manager. In the next post, I'll explore how to do some integrations with third-party API such as VirusTotal for active response and maybe Discord for alert notifications. Stay tuned!  
 
