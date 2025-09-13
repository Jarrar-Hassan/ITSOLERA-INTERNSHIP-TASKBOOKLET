# ITSOLERA-INTERNSHIP-TASKBOOKLET

# Comprehensive Cybersecurity Lab: Wazuh SIEM & pfSense Firewall

This repository documents a comprehensive cybersecurity lab project built during an internship at ITSOLERA PVT LTD. The project, created by **Muhammad Jarrar Hassan (Team Sigma)**, demonstrates a layered security approach by integrating Wazuh, a Security Information and Event Management (SIEM) platform, with pfSense, a powerful open-source firewall.

The lab covers key cybersecurity domains including threat detection, file integrity monitoring (FIM), network security, malware analysis, and incident response following the NIST framework.

## 🚀 Core Technologies

| Technology        | Role                                                                |
| ----------------- | ------------------------------------------------------------------- |
| **Wazuh** | SIEM & Security Monitoring Platform                                 |
| **pfSense** | Next-Generation Firewall (NGFW) and Router                          |
| **VirtualBox** | Virtualization Platform for Lab Environment                         |
| **Squid Proxy** | Web Proxy for Traffic Interception and Filtering on pfSense         |
| **ClamAV** | Antivirus Engine for Malware Detection on pfSense                   |
| **Syslog-NG** | Log Forwarding Service on pfSense                                   |
| **Windows** | Monitored Endpoint with Wazuh Agent                                 |

## 📝 Project Tasks Overview

This project is divided into three hands-on technical tasks that build upon each other to create a fully functional security monitoring solution.

### Task 1: Wazuh SIEM & File Integrity Monitoring (FIM)

* **Objective**: Deploy a Wazuh server and monitor a Windows endpoint for unauthorized file changes.
* **Setup**:
    1.  Deployed the Wazuh OVA (Open Virtual Appliance) in a virtual environment.
    2.  Installed the Wazuh agent on a Windows VM.
    3.  Configured File Integrity Monitoring (FIM) rules on the agent to monitor critical user directories in real-time.
* **Outcome**: The Wazuh dashboard successfully generated alerts for file creation, modification, and deletion events in the monitored directories, validating the FIM setup.

#### 📜 Configuration: Wazuh Agent FIM (`ossec.conf`)

This configuration was added to the Windows agent's `ossec.conf` file to enable real-time monitoring of specific folders.

```xml
<syscheck>
  <disabled>no</disabled>
  
  <frequency>43200</frequency>
  
  <directories check_all="yes" realtime="yes">C:\Users\JARRAR\Documents</directories>
  <directories check_all="yes" realtime="yes">C:\ImportantFiles</directories>
</syscheck>
```

---

### Task 2: pfSense Firewall with GeoIP & DNSBL Blocking

* **Objective**: Implement a pfSense firewall to secure the network by blocking traffic from specific countries and domains, and restricting administrative access.
* **Setup**:
    1.  Installed and configured pfSense in a VirtualBox VM with separate WAN and LAN interfaces.
    2.  Installed the **pfBlockerNG** package to enhance firewall capabilities.
    3.  **GeoIP Blocking**: Created a firewall rule to block all inbound and outbound traffic from the Netherlands.
    4.  **DNSBL (Domain Blocking)**: Configured DNSBL to block access to specific websites like `facebook.com`.
    5.  **Admin Access Control**: Implemented firewall rules to ensure that the pfSense web GUI is only accessible from a designated admin VM.
* **Outcome**: The firewall successfully blocked traffic based on the configured rules, and the logs in pfSense confirmed the enforcement of these policies.

---

### Task 3: Integrated Malware Detection and Incident Response

* **Objective**: Create an integrated system where pfSense detects and blocks malware downloads, and forwards the logs to Wazuh for centralized alerting and analysis.
* **Setup**:
    1.  **Proxy & AV**: Configured Squid as a transparent proxy and integrated the ClamAV antivirus engine on pfSense to scan HTTP/HTTPS traffic.
    2.  **Log Forwarding**: Used the Syslog-NG package on pfSense to forward proxy and firewall logs to the Wazuh manager.
    3.  **Wazuh Ingestion**: Created custom decoders and rules in Wazuh to correctly parse and generate high-severity alerts from the ClamAV logs.
    4.  **Testing**: Attempted to download the EICAR test file from a client VM behind the pfSense firewall.
* **Outcome**: The download was successfully blocked by pfSense/ClamAV. The event log was forwarded to Wazuh, which triggered a custom "Malware Detected" alert, providing full visibility of the incident (Source IP, Malware Signature, URL) in a single dashboard.

#### 📜 Configuration: Wazuh Custom Decoder & Rule

To detect the ClamAV logs from pfSense, the following custom components were added to Wazuh.

**Decoder (`/var/ossec/etc/decoders/local_decoder.xml`)**
```xml
<decoder name="pfsense-clamav-squid">
  <prematch>^pfsense VIRUS FOUND</prematch>
</decoder>

<decoder name="pfsense-clamav-squid-details">
  <parent>pfsense-clamav-squid</parent>
  <regex>^pfsense VIRUS FOUND \| (\S+) \| (\S+) \| (\S+)</regex>
  <order>malware.signature, malware.url, srcip</order>
</decoder>
```

**Rule (`/var/ossec/etc/rules/local_rules.xml`)**
```xml
<group name="pfsense,squid,clamav,">
  <rule id="100600" level="12">
    <decoded_as>pfsense-clamav-squid</decoded_as>
    <description>pfSense (ClamAV): Malware download attempt detected. Signature: $(malware.signature).</description>
    <field name="malware.url">\.+</field>
    <mitre>
      <id>T1204.002</id>
    </mitre>
  </rule>
</group>
```

### 🚨 Incident Response Plan

Based on the malware detection event in Task 3, a formal incident response plan was developed using the **NIST Cybersecurity Framework**.

1.  **Preparation**: Ensuring tools are configured and personnel are trained.
2.  **Detection & Analysis**: Identifying the incident via Wazuh alerts and analyzing logs to determine scope.
3.  **Containment**: Isolating the affected VM and blocklisting the malicious URL at the firewall level.
4.  **Eradication**: Sanitizing the affected system (though in this case, the threat was blocked at the perimeter).
5.  **Recovery**: Safely returning the system to production after verification.
6.  **Lessons Learned**: Reviewing the incident to improve security posture and automate responses.

## 💡 Key Learnings

* **Layered Security**: This project demonstrates that combining network-level controls (pfSense) with endpoint/log analysis (Wazuh) provides robust, in-depth threat visibility.
* **Open-Source Power**: Powerful, enterprise-grade security monitoring can be achieved using freely available open-source tools.
* **Automation and Integration**: The true value of a SIEM is realized when different security tools are integrated to provide a single pane of glass for monitoring and alerting. 
* **Importance of FIM**: File Integrity Monitoring is a critical control for detecting unauthorized changes that could indicate a system compromise.

---

*This project was completed as part of the ITSOLERA PVT LTD internship program. *
