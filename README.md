# DNS Spoofing Tool:

This is a Python-based DNS spoofing tool that uses `netfilterqueue` and `scapy` to intercept DNS requests and redirect them to a malicious IP address.  

---

## ⚠ Disclaimer

    This project is for educational purposes only.  

    Do NOT use it on networks without explicit permission.  

    Unauthorized use may be illegal in your country.

---

## 📌 Features

    - Intercepts DNS requests using `netfilterqueue`

    - Spoofs a specified domain and redirects it to a malicious IP

    - Works on Python 2

    - No hardcoded values — all options are set via command line

    - Can be easily integrated into penetration testing workflows

---

## 🛠 Installation

1. Clone the repository:
```bash
git clone https://github.com/Nozarashi-1/dns-spoofer.git
cd dns-spoofer
```
---

## 🚀 Usage

First, enable packet forwarding:

    echo 1 > /proc/sys/net/ipv4/ip_forward

Set up iptables to forward packets to the NFQUEUE:

    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0    

(For testing on your own machine, you can use OUTPUT and INPUT chains instead of FORWARD.)

# Run the script:

    sudo python dns_spoof.py -w "www.example.com" -m "192.168.1.100"

# When finished, restore firewall rules:

    sudo iptables --flush    

---

## 📂 Command-Line Options:

| Option             | Description                                | Example                |
| ------------------ | ------------------------------------------ | ---------------------- |
| `-w` / `--website` | The target domain to spoof                 | `-w "www.example.com"` |
| `-m` / `--malip`   | The malicious IP to redirect the domain to | `-m "192.168.1.100"`   |
