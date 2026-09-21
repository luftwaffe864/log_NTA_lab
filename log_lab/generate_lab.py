#!/usr/bin/env python3
"""
F26 LOG LAB — artifact generator (original content; does NOT use teammate NTA/TLS files)

Creates:
  artifacts/access.log      Nginx-style web access log
  artifacts/auth.log        Linux authentication log
  artifacts/windows_security.csv   Failed / success logon events (fake account Kestrel)
  artifacts/http_login.pcap Cleartext HTTP capture for Wireshark Follow HTTP Stream

Story: Northline Facilities portal (northline.lab) was probed overnight.
Attacker: 203.0.113.77  ("Kestrel" shows up in Windows logs as the account tried)
"""
from __future__ import annotations

import argparse
import random
import struct
import zlib
from datetime import datetime, timedelta
from pathlib import Path

# ---- Canonical answers (mentor) ------------------------------------------------
ATTACKER_IP = "203.0.113.77"
VICTIM_WEB = "198.51.100.40"
SUCCESS_USER = "j.hale"
SUCCESS_PASS = "HarborLight!2026"
SQLI_SNIPPET = "1'%20OR%20'1'%3D'1"
TRAVERSAL_SNIPPET = "..%2F..%2F..%2Fetc%2Fpasswd"
PROBE_ACCOUNT = "Kestrel"
FLAG_WEB = "FLAG{northline_access_log_triage}"
FLAG_HTTP = "FLAG{cleartext_creds_in_http}"
FLAG_WIN = "FLAG{kestrel_failed_logon}"
FLAG_CORR = "FLAG{log_to_pcap_correlation}"

UA_ATTACKER = "python-requests/2.31.0"
UA_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/123.0",
]


def ts(base: datetime, offset_sec: int) -> str:
    return (base + timedelta(seconds=offset_sec)).strftime("%d/%b/%Y:%H:%M:%S +0000")


def build_access_log(base: datetime) -> str:
    lines: list[str] = []
    # Benign traffic
    paths = ["/", "/css/app.css", "/js/app.js", "/favicon.ico", "/about", "/contact", "/health"]
    clients = ["198.51.100.10", "198.51.100.22", "192.0.2.55", "198.51.100.18"]
    for i in range(180):
        ip = random.choice(clients)
        path = random.choice(paths)
        code = 200 if path != "/favicon.ico" or random.random() > 0.2 else 404
        size = random.randint(200, 8000)
        lines.append(
            f'{ip} - - [{ts(base, i * 3)}] "GET {path} HTTP/1.1" {code} {size} '
            f'"-" "{random.choice(UA_NORMAL)}"'
        )

    # Directory traversal probes
    for i, p in enumerate(
        [
            f"/static/{TRAVERSAL_SNIPPET}",
            "/download?file=....//....//....//windows/win.ini",
            "/assets/..%2F..%2F..%2Fetc%2Fshadow",
        ]
    ):
        lines.append(
            f'{ATTACKER_IP} - - [{ts(base, 600 + i)}] "GET {p} HTTP/1.1" 403 312 '
            f'"-" "{UA_ATTACKER}"'
        )

    # SQLi attempts (failed)
    sqli_paths = [
        f"/login?user=admin&pass={SQLI_SNIPPET}",
        "/api/v1/search?q=1%20UNION%20SELECT%20null--",
        "/product?id=1;%20DROP%20TABLE%20users--",
    ]
    for i, p in enumerate(sqli_paths):
        lines.append(
            f'{ATTACKER_IP} - - [{ts(base, 700 + i * 2)}] "GET {p} HTTP/1.1" 400 198 '
            f'"-" "{UA_ATTACKER}"'
        )

    # Brute-force POSTs (failed) then one success — password NOT in access log URI
    # (forces students to the pcap for plaintext password)
    bad_users = ["admin", "root", "sa", "backup", "j.hale", "operator"]
    for i, u in enumerate(bad_users):
        lines.append(
            f'{ATTACKER_IP} - - [{ts(base, 800 + i * 5)}] '
            f'"POST /login HTTP/1.1" 401 145 "-" "{UA_ATTACKER}"'
        )

    # Successful login (200) — still no password in the log line
    lines.append(
        f'{ATTACKER_IP} - j.hale [{ts(base, 860)}] '
        f'"POST /login HTTP/1.1" 302 0 "/dashboard" "{UA_ATTACKER}"'
    )
    lines.append(
        f'{ATTACKER_IP} - j.hale [{ts(base, 861)}] '
        f'"GET /dashboard HTTP/1.1" 200 4821 "-" "{UA_ATTACKER}"'
    )

    # Hidden note path with flag (404 hunting / grepping)
    lines.append(
        f'198.51.100.10 - - [{ts(base, 900)}] '
        f'"GET /internal/triage-note.txt HTTP/1.1" 200 64 "-" "{UA_NORMAL[0]}"'
    )

    # Noise 404/500
    for i in range(40):
        ip = random.choice(clients + [ATTACKER_IP])
        code = random.choice([404, 404, 404, 500, 403])
        lines.append(
            f'{ip} - - [{ts(base, 950 + i)}] '
            f'"GET /old/{random.randint(1,99)}.php HTTP/1.1" {code} 120 '
            f'"-" "{random.choice(UA_NORMAL + [UA_ATTACKER])}"'
        )

    random.shuffle(lines)
    # Keep chronological-ish: re-sort by embedded time is hard after shuffle;
    # for labs, shuffled is fine to force grep not "read top to bottom".
    header = (
        f"# Northline Facilities — nginx access log export\n"
        f"# Host: portal.northline.lab ({VICTIM_WEB})\n"
        f"# Embedded note: triage staff left FLAG at /internal/triage-note.txt → {FLAG_WEB}\n"
    )
    # Put flag content as if that request body were logged in a side file — students
    # find path via 200 to triage-note; flag also in challenges via that path string.
    # Better: add a tiny companion file.
    return "\n".join(lines) + "\n", header


def build_auth_log(base: datetime) -> str:
    lines = []
    lines.append(
        f"{(base).strftime('%b %d %H:%M:%S')} portal sshd[2201]: Accepted publickey for deploy from 198.51.100.10 port 51122 ssh2"
    )
    for i, user in enumerate(["root", "admin", "ubuntu", "deploy", "j.hale"]):
        lines.append(
            f"{(base + timedelta(seconds=800 + i * 4)).strftime('%b %d %H:%M:%S')} "
            f"portal sshd[3100]: Failed password for {user} from {ATTACKER_IP} port {40000 + i} ssh2"
        )
    lines.append(
        f"{(base + timedelta(seconds=860)).strftime('%b %d %H:%M:%S')} "
        f"portal sshd[3100]: Failed password for invalid user kestrel from {ATTACKER_IP} port 40110 ssh2"
    )
    lines.append(
        f"{(base + timedelta(seconds=900)).strftime('%b %d %H:%M:%S')} "
        f"portal sudo: j.hale : TTY=pts/0 ; PWD=/home/j.hale ; USER=root ; COMMAND=/usr/bin/less /var/log/nginx/access.log"
    )
    return "\n".join(lines) + "\n"


def build_windows_csv(base: datetime) -> str:
    """Simplified Security log export — Event ID 4625 failed logon, 4624 success."""
    rows = [
        "TimeGenerated,EventId,AccountName,IpAddress,LogonType,Status,Message",
    ]
    # Noise
    for i in range(15):
        t = (base + timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
        rows.append(
            f"{t},4624,SYSTEM,-,5,0x0,An account was successfully logged on"
        )
    # Fake account "Kestrel" failed logons from attacker IP
    for i in range(8):
        t = (base + timedelta(seconds=820 + i * 3)).strftime("%Y-%m-%d %H:%M:%S")
        rows.append(
            f"{t},4625,{PROBE_ACCOUNT},{ATTACKER_IP},3,0xC000006D,"
            f"An account failed to log on (unknown user or bad password) hint:{FLAG_WIN}"
        )
    # One failed for Administrator
    t = (base + timedelta(seconds=850)).strftime("%Y-%m-%d %H:%M:%S")
    rows.append(
        f"{t},4625,Administrator,{ATTACKER_IP},3,0xC000006A,An account failed to log on"
    )
    return "\n".join(rows) + "\n"


# ---- Minimal PCAP writer (no scapy required) ------------------------------------

def _pcap_global_header() -> bytes:
    # magic, vmaj, vmin, thiszone, sigfigs, snaplen, network(1=ethernet)
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _pcap_record(ts_sec: int, ts_usec: int, data: bytes) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _eth_ip_tcp_http(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
) -> bytes:
    def ip_bytes(ip: str) -> bytes:
        return bytes(int(x) for x in ip.split("."))

    eth = b"\xaa\xaa\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb\xbb\xbb\x08\x00"
    tcp_len = 20 + len(payload)
    total_len = 20 + tcp_len
    # IP header (checksum left 0 — Wireshark still dissects fine for lab)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0x1234,
        0,
        64,
        6,
        0,
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        (5 << 4),  # data offset = 5 (20-byte header), reserved = 0
        flags,
        8192,
        0,
        0,
    )
    return eth + ip + tcp + payload


def build_http_pcap(base: datetime) -> bytes:
    """Single HTTP POST /login with cleartext credentials + 302 response."""
    body = f"username={SUCCESS_USER}&password={SUCCESS_PASS}&submit=Login"
    req = (
        "POST /login HTTP/1.1\r\n"
        f"Host: portal.northline.lab\r\n"
        f"User-Agent: {UA_ATTACKER}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{body}"
    ).encode()
    resp = (
        "HTTP/1.1 302 Found\r\n"
        "Location: /dashboard\r\n"
        f"X-Lab-Flag: {FLAG_HTTP}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    t0 = int(base.timestamp()) + 860
    frames = []
    # SYN
    frames.append(
        _pcap_record(
            t0,
            0,
            _eth_ip_tcp_http(ATTACKER_IP, VICTIM_WEB, 51774, 80, 1000, 0, 0x02, b""),
        )
    )
    # SYN-ACK
    frames.append(
        _pcap_record(
            t0,
            1000,
            _eth_ip_tcp_http(VICTIM_WEB, ATTACKER_IP, 80, 51774, 5000, 1001, 0x12, b""),
        )
    )
    # ACK
    frames.append(
        _pcap_record(
            t0,
            2000,
            _eth_ip_tcp_http(ATTACKER_IP, VICTIM_WEB, 51774, 80, 1001, 5001, 0x10, b""),
        )
    )
    # HTTP POST
    frames.append(
        _pcap_record(
            t0,
            3000,
            _eth_ip_tcp_http(ATTACKER_IP, VICTIM_WEB, 51774, 80, 1001, 5001, 0x18, req),
        )
    )
    # HTTP response
    frames.append(
        _pcap_record(
            t0 + 1,
            0,
            _eth_ip_tcp_http(
                VICTIM_WEB, ATTACKER_IP, 80, 51774, 5001, 1001 + len(req), 0x18, resp
            ),
        )
    )
    return _pcap_global_header() + b"".join(frames)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate F26 Log Lab artifacts")
    ap.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "artifacts",
    )
    args = ap.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    random.seed(26)  # reproducible lab
    base = datetime(2026, 9, 18, 2, 14, 0)

    access, _ = build_access_log(base)
    (out / "access.log").write_text(access, encoding="utf-8")
    (out / "auth.log").write_text(build_auth_log(base), encoding="utf-8")
    (out / "windows_security.csv").write_text(build_windows_csv(base), encoding="utf-8")
    (out / "http_login.pcap").write_bytes(build_http_pcap(base))
    (out / "triage-note.txt").write_text(
        f"Northline SOC scratch note\n{FLAG_WEB}\nCorrelate web IP with pcap → {FLAG_CORR}\n",
        encoding="utf-8",
    )

    meta = out / "LAB_FACTS.txt"
    meta.write_text(
        "Mentor-only facts used by ANSWER_KEY (do not ship to students if avoidable).\n"
        f"ATTACKER_IP={ATTACKER_IP}\n"
        f"SUCCESS_USER={SUCCESS_USER}\n"
        f"SUCCESS_PASS={SUCCESS_PASS}\n"
        f"PROBE_ACCOUNT={PROBE_ACCOUNT}\n"
        f"FLAG_WEB={FLAG_WEB}\n"
        f"FLAG_HTTP={FLAG_HTTP}\n"
        f"FLAG_WIN={FLAG_WIN}\n"
        f"FLAG_CORR={FLAG_CORR}\n",
        encoding="utf-8",
    )
    # Don't leave mentor facts in student zip by default — generator keeps it;
    # README tells mentors to delete before distributing.
    print(f"Wrote artifacts to {out}")


if __name__ == "__main__":
    main()
