# Universal DNS/TLS Network Monitor

**Kali Linux • ARP Spoofing • Scapy • Streamlit**

---

## Educational Use Only

This project is intended **strictly for controlled lab environments** such as:

* cybersecurity learning labs
* personal test networks
* CTF practice

Intercepting network traffic **without permission is illegal** in many regions.

---

# Overview

This project demonstrates a **Man-in-the-Middle (MITM) monitoring setup** that:

* performs ARP spoofing to position the attacker between victim and router
* captures live packets using **Scapy**
* extracts:

  * DNS queried domains
  * HTTPS Server Name Indication (SNI) from TLS Client Hello
* visualizes traffic in **real time** via a **Streamlit dashboard**

The result is a **live website activity monitor** for a chosen device on a local network.

---

#Repository Structure

```
dns-arp-monitor/
├── monitor.py        # Packet sniffer + Streamlit dashboard
├── kali_commands.md  # Quick execution commands
└── README.md
```

---

#  Requirements

## System

* Kali Linux
* Python 3

## Python Libraries

* scapy
* streamlit
* pandas

Install with:

```bash
sudo apt install python3-pip
sudo pip3 install scapy streamlit pandas --break-system-package
```

---

#  Execution Steps

## 1. Enable Packet Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Allows the attacker machine to **relay packets** so the victim’s internet remains functional during MITM.

---

## 2. Launch ARP Spoofing

Open **two terminals**:

**Spoof victim → router**

```bash
sudo arpspoof -i <interface> -t <victim_ip> <gateway_ip>
```

**Spoof router → victim**

```bash
sudo arpspoof -i <interface> -t <gateway_ip> <victim_ip>
```

This forces **all traffic through the attacker machine**.

---

## 3. Start the Monitoring Dashboard

Change the victim IP Address and interface in the python code first.

```bash
sudo streamlit run monitor.py
```

Then open the **local Streamlit web page** shown in the terminal.

---

#  How It Works Internally

## 1. MITM via ARP Poisoning

ARP spoofing sends **forged ARP replies** so that:

* victim maps **gateway IP → attacker MAC**
* gateway maps **victim IP → attacker MAC**

Result:

 Attacker transparently relays and observes traffic.

---

## 2. Packet Capture with Scapy

`monitor.py` runs a **background sniffing thread**:

* uses a **BPF filter**:

  ```
  host <victim_ip>
  ```

  to capture only traffic **to/from the victim**

* processes each packet in `packet_callback()`

---

## 3. Domain Extraction Logic

### DNS Queries

If packet contains:

```
DNS + DNSQR and qr == 0
```

→ extract queried domain name.

---

### HTTPS via TLS Client Hello (SNI)

For encrypted HTTPS:

* the **TLS Client Hello** still exposes
  **Server Name Indication (SNI)** in plaintext.

The script:

* detects `TLSClientHello`
* reads `extensions → server_names`
* extracts requested hostname.

This enables **website visibility even over HTTPS**.

---

## 4. Real-Time Streamlit Dashboard

The dashboard:

* stores recent events in **Streamlit session state**
* converts them into a **Pandas DataFrame**
* refreshes every **1 second**
* displays:

  * timestamp
  * device IP / friendly name
  * visited domain

Also shows:

* packet counter
* active victim filter

---

#  Learning Outcomes

This project teaches:

* ARP spoofing–based MITM positioning
* DNS and TLS SNI visibility limits in encrypted traffic
* packet sniffing with Scapy
* multithreading with real-time UI updates
* building cybersecurity monitoring dashboards

Relevant for:

* penetration testing
* network forensics
* blue-team traffic inspection
* cybersecurity research projects

---

#  Legal Disclaimer

This repository is provided **for educational purposes only**.

Unauthorized interception of network communications may violate:

* privacy laws
* computer misuse laws
* institutional policies

Use **only in authorized lab environments**.

---


Cybersecurity learning project built with:

**Kali Linux • Python • Scapy • Streamlit**
