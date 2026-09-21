# CCIG — Log Lab

CTF CIG (**CCIG**) lab for **log analysis** (web/auth/Windows logs + cleartext HTTP pcap).

All student materials are in **[log_lab/](log_lab/)**.

---

## How to do the lab

1. **Get the files** — clone or download this repo onto Kali (or any machine with a terminal and Wireshark):

   ```bash
   git clone https://github.com/luftwaffe864/log_NTA_lab.git
   cd log_NTA_lab/log_lab
   ```

2. **Read the challenges** — open [log_lab/CHALLENGES.md](log_lab/CHALLENGES.md).

3. **Work in `artifacts/`**

   ```bash
   cd artifacts
   ls
   ```

   You will use:
   - `access.log` — web access log  
   - `auth.log` — Linux auth log  
   - `windows_security.csv` — Windows logon events  
   - `http_login.pcap` — packet capture  
   - `triage-note.txt` — short SOC note  

4. **Parts A–C (logs)** — use the command line, for example:

   ```bash
   grep -i something access.log
   grep -c ' 404 ' access.log
   cut -d' ' -f1 access.log | sort | uniq -c | sort -rn | head
   ```

5. **Part D (pcap)** — open `http_login.pcap` in Wireshark:
   - Filter on the suspicious IP and port 80  
   - Right-click a packet → **Follow** → **HTTP Stream**  
   - Read the login form fields and response headers  

6. **Submit your answers** as your instructor directs.

No Salt or VMs are required — only the files in this repo plus Wireshark (or `tshark`).

---

## Optional: rebuild artifacts

```bash
cd log_lab
python3 generate_lab.py
```
