# CCIG — Log Lab (Northline Portal)

CTF CIG (**CCIG**) artifacts-only lab: web/auth/Windows logs plus a cleartext HTTP pcap.
---

## How to do the lab

1. Open **[CHALLENGES.md](CHALLENGES.md)** and follow Parts A–E in order.
2. Go into the evidence folder:

   ```bash
   cd artifacts
   ```

3. **Logs (Parts A–C)** — filter with CLI tools:

   ```bash
   grep -i requests access.log
   grep -c '203.0.113.77' access.log
   grep -iE 'union|passwd|\.\.' access.log
   grep Failed auth.log
   grep 4625 windows_security.csv
   ```

4. **Packets (Part D)** — open `http_login.pcap` in Wireshark:
   - Filter: attacker IP and `tcp.port == 80`
   - **Follow → HTTP Stream**
   - Find the successful login password (not stored in `access.log`)

5. Turn in answers the way your CCIG instructor asks.

---

## Files in `artifacts/`

| File | Role |
|------|------|
| `access.log` | Nginx-style web access log |
| `auth.log` | Linux SSH / sudo log |
| `windows_security.csv` | Windows Security export |
| `http_login.pcap` | Cleartext HTTP capture |
| `triage-note.txt` | Short SOC note / flags |

---

## Rebuild artifacts (optional)

```bash
python3 generate_lab.py
```
