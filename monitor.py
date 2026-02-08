import streamlit as st
from scapy.all import sniff, DNS, DNSQR, IP, load_layer
from scapy.layers.tls.all import TLS, TLSClientHello
import threading
import pandas as pd
from datetime import datetime
import time
from streamlit.runtime.scriptrunner import add_script_run_ctx

# Load TLS dissectors
load_layer("tls")

# --- UI CONFIGURATION (SIDEBAR) ---
st.set_page_config(page_title="Universal Lab Monitor", layout="wide")
st.sidebar.title("Settings")

# Allow user to change interface and target IP via the UI
target_interface = st.sidebar.text_input("Network Interface", value="eth0") #Update network interface
target_ip = st.sidebar.text_input("Victim IP to Filter", value="192.168.x.y") #Update IP here

FRIENDLY_NAMES = {
    target_ip: "Target Victim",
    "192.168.x.y": "Gateway" #Update IP here
}

# --- DATA STORAGE ---
if 'network_data' not in st.session_state:
    st.session_state.network_data = []
if 'packet_count' not in st.session_state:
    st.session_state.packet_count = 0

def get_domain(pkt):
    """Extracts domain from DNS or TLS Client Hello."""
    try:
        # DNS Logic
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            return pkt.getlayer(DNSQR).qname.decode().strip('.')
        
        # HTTPS/TLS SNI Logic
        if pkt.haslayer(TLSClientHello):
            if hasattr(pkt[TLSClientHello], 'extensions'):
                for ext in pkt[TLSClientHello].extensions:
                    if hasattr(ext, 'server_names'):
                        return ext.server_names[0].hostname.decode()
    except:
        pass
    return None

def packet_callback(pkt):
    """Processes packets caught by the filter."""
    st.session_state.packet_count += 1
    
    domain = get_domain(pkt)
    if domain:
        ip_src = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
        name = FRIENDLY_NAMES.get(ip_src, ip_src)
        
        new_entry = {
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Device IP": name,
            "Website Visited": domain
        }
        st.session_state.network_data.append(new_entry)
        if len(st.session_state.network_data) > 100:
            st.session_state.network_data.pop(0)

def start_sniffer(iface, victim_ip):
    """
    Runs Scapy sniffer with a BPF filter.
    'host victim_ip' captures traffic to AND from that IP.
    """
    bpf_filter = f"host {victim_ip}" if victim_ip else ""
    sniff(iface=iface, prn=packet_callback, filter=bpf_filter, store=0)

# --- MAIN DASHBOARD ---
st.title("🛡️ Universal Network Monitoring Dashboard")
st.write(f"Currently monitoring *{target_ip}* on interface *{target_interface}*")

# Start thread if not already running
if 'sniffer_started' not in st.session_state or st.session_state.current_target != target_ip:
    # This logic allows the sniffer to restart if you change the IP in the sidebar
    thread = threading.Thread(target=start_sniffer, args=(target_interface, target_ip), daemon=True)
    add_script_run_ctx(thread)
    thread.start()
    st.session_state.sniffer_started = True
    st.session_state.current_target = target_ip

# Visual Feedback
c1, c2 = st.columns(2)
c1.metric("Packets Captured (Filtered)", st.session_state.packet_count)
c2.info(f"Filter Active: Traffic involving {target_ip} only")

placeholder = st.empty()

while True:
    with placeholder.container():
        if st.session_state.network_data:
            df = pd.DataFrame(st.session_state.network_data[::-1])
            st.table(df)
        else:
            st.warning("No website traffic detected yet. Ensure your ARP spoofing is active.")
    time.sleep(1)
