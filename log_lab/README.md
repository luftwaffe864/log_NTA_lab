# F26 Log Lab — Northline Portal Incident

**Artifacts-only lab** (no Salt / VMs required). Works on Kali, any Linux analysis box, or Windows with Wireshark + a grep tool.

This lab is **original** for the log-analysis track. It is **not** the teammate NTA/TLS challenge (`reference_nta_tls/`).

| This lab | Teammate NTA lab |
|----------|------------------|
| Cleartext **HTTP** + **log files** | Encrypted **TLS** + SSL key log |
| `grep` / `awk` / `cut` / `sort` on logs | Wireshark TLS decrypt + Follow stream |
| Correlate IP from **access.log** → **HTTP pcap** | Correlate via TLS Client Hello / SNI |

---

## Story

Overnight, someone probed **portal.northline.lab**. You have:

| File | Description |
|------|-------------|
| `artifacts/access.log` | Nginx-style web access log |
| `artifacts/auth.log` | Linux SSH / sudo auth log |
| `artifacts/windows_security.csv` | Windows Security events (CSV export) |
| `artifacts/http_login.pcap` | Packet capture of cleartext HTTP to the portal |
| `artifacts/triage-note.txt` | Short SOC note (also “found” via the web log) |

---

## Skills covered

1. Web access log triage (SQLi, traversal, brute force, status codes, user-agents)
2. Linux `auth.log` review
3. Windows failed logon review (account **Kestrel**)
4. CLI filtering: `grep`, `awk`, `cut`, `sort`, `uniq`
5. Log → packet correlation in Wireshark (**Follow → HTTP Stream**) to recover a **plaintext password**

---

## How to start

```bash
cd F26_log_lab
# artifacts already generated; to rebuild:
python3 generate_lab.py
```

Open challenges: [CHALLENGES.md](CHALLENGES.md)

Mentors: [ANSWER_KEY.txt](ANSWER_KEY.txt) — **do not give to students**.  
Before handing out a zip, delete `artifacts/LAB_FACTS.txt` if present.

---

## Suggested tools

- Terminal: `grep`, `awk`, `cut`, `sort`, `uniq`, `wc`
- Wireshark or `tshark` for `http_login.pcap`
