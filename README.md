# CCIG — Log & NTA Lab

CTF CIG (CCIG) lab materials for **log analysis** and related **network traffic analysis**.

| Folder | Track |
|--------|--------|
| [log_lab/](log_lab/) | Log analysis + cleartext HTTP pcap (main challenges) |
| [nta_tls/](nta_tls/) | Separate NTA/TLS challenge (pcap + TLS key log) |

---

## How to do the log lab

1. **Get the files**  
   Clone this repo (or download the ZIP) onto Kali or any machine with a terminal and Wireshark:

   ```bash
   git clone https://github.com/luftwaffe864/log_NTA_lab.git
   cd log_NTA_lab/log_lab
   ```

2. **Read the challenges**  
   Open [log_lab/CHALLENGES.md](log_lab/CHALLENGES.md).

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

6. **Submit your answers** as your instructor directs (worksheet, form, or mentor check).

No Salt or VMs are required for the log lab — only the files in this repo plus Wireshark (or `tshark`).

---

## Optional: rebuild log artifacts

```bash
cd log_lab
python3 generate_lab.py
```

---

## NTA / TLS folder

See [nta_tls/README.md](nta_tls/README.md) for the separate encrypted-traffic challenge (different tools and workflow from the log lab).
