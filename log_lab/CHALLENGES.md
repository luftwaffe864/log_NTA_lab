# Northline Portal — Student Challenges

Work in the `artifacts/` folder. Submit answers to your mentor (or fill a worksheet).

---

## Part A — Web access log (`access.log`)

**A1.** How many lines in `access.log` contain the attacker-looking IP that also appears with `python-requests`?  
*(Hint: find the unusual User-Agent first.)*

**A2.** What is that attacker IP address?

**A3.** Find a request that looks like **SQL injection**. Paste the path/query fragment that proves it (or the full request target).

**A4.** Find a **directory traversal** style request. Paste evidence (path snippet is enough).

**A5.** How many responses in the log are HTTP **404**?  
`grep -c` is fine.

**A6.** How many responses are HTTP **500**?

**A7.** The attacker eventually gets a **302** on `POST /login`. What username is associated with that success in the log?  
*(Combined log format: the user field is between the first two spaces after the IP — often `-` until authenticated.)*

**A8.** Open `triage-note.txt` (or find how the log points you there). What is the web triage flag?  
`FLAG{...}`

---

## Part B — Linux auth log (`auth.log`)

**B1.** Does the same attacker IP appear in `auth.log`? (yes/no)

**B2.** Name one SSH username that had a **Failed password** from that IP.

**B3.** Is there a failed attempt for an account that looks like **kestrel** (any capitalization)? (yes/no)

---

## Part C — Windows Security export (`windows_security.csv`)

**C1.** Which **AccountName** is repeatedly failing logon from the attacker IP?  
*(Look for the repeated fake account name in the CSV.)*

**C2.** What **EventId** is used for those failures?

**C3.** What flag is embedded in those Windows failure messages?  
`FLAG{...}`

---

## Part D — Packet correlation (`http_login.pcap`)

The access log does **not** store the POST password. The password is in the packet capture (cleartext HTTP).

**D1.** Open `http_login.pcap` in Wireshark. Filter to the attacker IP talking to the web server on port 80.  
What display filter did you use? (Example shape: `ip.addr == … && tcp.port == 80`)

**D2.** Follow the **HTTP stream**. What **password** did the attacker send on the successful login?

**D3.** What flag appears in the HTTP **response** headers?  
`FLAG{...}`

**D4.** Write the correlation flag from `triage-note.txt` (log ↔ pcap).  
`FLAG{...}`

---

## Part E — Short write-up (mentor may grade)

In 3–5 sentences: What did the attacker try, what finally worked, and how did logs + pcap prove it?
