# CodeAlpha - Network Intrusion Detection System (NIDS) utilizing Snort Logic

A lightweight, high-performance Command-Line Interface (CLI) Network Intrusion Detection System (NIDS) developed in Python using the **Scapy** library. This security engine dynamically parses and enforces standard **Snort Rules** signature formats to detect malicious network traffic (such as Port Scanning) in real-time. Developed as part of the **CodeAlpha** Cyber Security Internship.

## 📋 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Project Architecture](#-project-architecture)
- [Active Snort Ruleset](#-active-snort-ruleset)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Usage](#-usage)

---

## 🔍 Overview
This project serves as a signature-based Intrusion Detection System. It bridges Python's robust packet manipulation capabilities with the industry-standard syntax of **Snort**, allowing network administrators to load custom signature blocks and monitor live network interfaces for potential security breaches and scanning activities.

## ✨ Features
- **Snort Rule Integration:** Parses custom configuration files (`snort.rules`) using official syntax components like `msg`, `flags`, and `sid`.
- **Live Packet Inspection:** Continuously sniffs Layer 3/4 traffic and decodes packet headers asynchronously.
- **Port Scan Detection:** Triggers immediate `[!!!] ALERT` banners upon inspecting high-risk TCP SYN flag signatures defined in the active rule-set.
- **Resource Management:** Disables packet archiving in memory (`store=0`) to guarantee minimal system overhead during prolonged live analysis.

## 📁 Project Architecture
```text
CodeAlpha_NetworkIDS/
│
├── nids.py            # Core IDS engine that reads signatures and scans network packets
├── snort.rules        # External configuration file holding Snort-compliant syntax strings
└── README.md          # Comprehensive project documentation

```
## 🔒 Active Snort Ruleset
The engine dynamically monitors traffic based on the rules specified in snort.rules:
```text
alert tcp any any -> any any (msg:"Snort ALERT: Potential Port Scanning Detected"; flags:S; sid:1000001;)

```
*Logic: Flags any TCP packet utilizing a **SYN (S)** flag from any source/port to any destination/port as a potential scouting or port scanning attempt.*
## 🛠️ Prerequisites
Before running the tool, ensure your system meets the following requirements:
 1. **Python 3.x** installed.
 2. **Administrative Privileges:** Opening raw network sockets to sniff interface traffic requires Root/Administrator rights.
 3. **Packet Capture Driver:**
   * **Windows:** Requires **Npcap** installed with the "Install Npcap with WinPcap compatibility mode" option enabled.
   * **Linux:** Requires libpcap (usually pre-installed or available via apt install libpcap-dev).
## 🚀 Installation & Setup
 1. **Clone the Repository:**
```bash
git clone [https://github.com/solda-rasam/CodeAlpha_NetworkIDS.git](https://github.com/solda-rasam/CodeAlpha_NetworkIDS.git)
cd CodeAlpha_NetworkIDS

```
 2. **Install Required Libraries:**
```bash
pip install scapy

```
## 💻 Usage
### Windows (Command Prompt / PowerShell)
Open your terminal **as an Administrator** and execute:
```bash
python nids.py

```
### Linux / macOS
Run the script using sudo to grant packet capturing permissions:
```bash
sudo python3 nids.py

```
### 📊 Expected Output Log
```text
[*] Network Intrusion Detection System (NIDS) Powered by Snort Rules...
[*] Successfully loaded rules from 'snort.rules'.
[*] Continuously monitoring live network traffic... (Press Ctrl+C to stop)

============================================================
[!!!] Snort ALERT: Potential Port Scanning Detected
    [Snort Match] Attacker IP: 192.168.1.50 -> Destination: 192.168.1.1:80
============================================================

```

