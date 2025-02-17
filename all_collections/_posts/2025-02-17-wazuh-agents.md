---
layout: post
title: Setting Up Wazuh Agent
date: 2025-02-17 19:26:00
categories: [dfir, tutorial]
---

Here's a blog post for setting up the Wazuh agent on an Ubuntu VM. Let me know if you want any changes!  

---

# Setting Up Wazuh Agent on Ubuntu VM  

In my previous post, I explored Wazuh without an agent, just to get a feel for how things work. Now, it’s time to level up and deploy the Wazuh agent on an **Ubuntu VM** to start monitoring system activities properly. This guide will walk through the setup process step by step.  

---

## 🛠 Prerequisites  
Before we begin, make sure:  
✅ You have a **Wazuh Manager** running (installed on another server or VM).  
✅ Your **Ubuntu VM** has internet access.  
✅ You have **sudo** privileges on the Ubuntu VM.  

---

![image](https://github.com/user-attachments/assets/e2188b6f-21c5-42fb-bc00-00dda1b0f50f)

![image](https://github.com/user-attachments/assets/2fbca750-be9a-479a-9422-ee80b073676b)

![image](https://github.com/user-attachments/assets/491f4875-7837-4a7a-b09b-7737fdc0705c)

![image](https://github.com/user-attachments/assets/5c9f590c-8988-4e84-9f35-335b1cc52d3a)

![image](https://github.com/user-attachments/assets/2cc2b7f1-fbf6-4957-b376-4f76ad9367ba)

![image](https://github.com/user-attachments/assets/c27ad474-9bd7-4ef8-858e-d3410b419579)

![image](https://github.com/user-attachments/assets/b0d59522-1092-4e64-8c86-612f5557e729)

![image](https://github.com/user-attachments/assets/4894b3c5-2583-442f-8773-08cc239adea1)

![image](https://github.com/user-attachments/assets/da93d342-ba53-475f-b2d6-4a461f2a1f90)

![image](https://github.com/user-attachments/assets/4b6a3981-37ce-45d5-ab2f-aa0117dd3d76)

![image](https://github.com/user-attachments/assets/3406138d-9746-4155-a79b-210b7f0a5d0e)

![image](https://github.com/user-attachments/assets/6c9ee97d-95be-4022-950d-0a7e52495a97)

![image](https://github.com/user-attachments/assets/6e0c8ee9-abec-4966-a5db-d1bed0120b6d)

![image](https://github.com/user-attachments/assets/8ce25fc5-9fd6-4fd3-96f2-059d4699bb79)


![image](https://github.com/user-attachments/assets/f972e456-7126-4f44-b4b4-796d92e4fa41)


![image](https://github.com/user-attachments/assets/c00475fa-9d6d-4303-a1d7-9dccbaa2fa86)

![image](https://github.com/user-attachments/assets/c61419e3-2669-4a24-8252-9a474e30afe8)



## Step 1: Install the Wazuh Agent  
First, update the system and install necessary packages:  
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install curl apt-transport-https -y
```
Now, download and install the Wazuh agent:  
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-agent.deb
sudo dpkg -i wazuh-agent.deb
```
This installs the agent, but we still need to configure it to communicate with the Wazuh Manager.  

---

## Step 2: Configure the Agent  
Edit the Wazuh agent config file:  
```bash
sudo nano /var/ossec/etc/ossec.conf
```
Look for the `<client>` section and update the `<address>` field to point to your **Wazuh Manager’s IP**:  
```xml
<client>
  <server>
    <address>YOUR_WAZUH_MANAGER_IP</address>
    <port>1514</port>
  </server>
</client>
```
Save and exit (`CTRL+X`, then `Y` and `Enter`).  

---

## Step 3: Enable and Start the Agent  
Now, enable and start the Wazuh agent:  
```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```
Check if it’s running:  
```bash
sudo systemctl status wazuh-agent
```
If you see **"active (running)"**, then you're good to go! 🎉  

---

## Step 4: Verify Connection on Wazuh Manager  
Go to your **Wazuh Manager** and check if the agent is connected:  
```bash
sudo /var/ossec/bin/agent_control -l
```
If the agent appears in the list, everything is working fine. If not, you might need to check firewall settings or ensure the manager is reachable from the Ubuntu VM.  

---

## Step 5: Test the Agent  
To generate some logs and test if Wazuh detects them, try running:  
```bash
sudo tail -f /var/log/syslog
```
Then, create a test alert:  
```bash
sudo su -c "echo 'Test alert from Wazuh agent' >> /var/log/syslog"
```
If everything is set up correctly, this should show up in your Wazuh dashboard under **Alerts**.  

---

## 🎯 Conclusion  
That’s it! Your Ubuntu VM is now running the Wazuh agent and sending logs to the manager. In the next post, I'll explore how to fine-tune the agent and set up rules for detecting **suspicious activity** like XSS and SQLi. Stay tuned!  

Let me know if you have any questions or issues in the comments. 🚀  

---

Want any modifications? 😃
