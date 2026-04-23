# MyAV — Basic Antivirus Simulation

A Python-based antivirus simulation demonstrating real-world security concepts
through three-layer threat detection, VirusTotal cloud intelligence, heuristic
analysis, email alerting, and a full GUI dashboard.

Built as an educational project — every concept maps directly to how real AV
engines like Windows Defender and CrowdStrike work.

---

## Three-Layer Detection Engine

| Layer | Module | Method | Works offline? |
|---|---|---|---|
| Layer 1 | antivirus.py | SHA-256 hash vs signatures.json | Yes |
| Layer 2 | virustotal_lookup.py | VirusTotal API — 70+ engines | No (needs internet) |
| Layer 3 | heuristics.py | Pattern-based suspicious behaviour | Yes |

Layer 1 catches known threats instantly.
Layer 2 catches unknown threats via real cloud intelligence.
Layer 3 catches brand new threats with no signature at all.

---

## What Each File Does

| File | Purpose |
|---|---|
| antivirus.py | Brain — controls all three layers, CLI entry point |
| virustotal_lookup.py | Layer 2 — VirusTotal API integration with local cache |
| heuristics.py | Layer 3 — double extension, dangerous location, size mismatch |
| email_alert.py | Sends email alert when threat or suspicious file found |
| demo_setup.py | Creates test_folder with clean and simulated malware files |
| report_generator.py | Reads scan_log.txt and produces HTML scan report |
| dashboard.html | Interactive browser GUI dashboard |
| signatures.json | Local malware hash database (auto-created) |
| vt_cache.json | VirusTotal results cache (auto-created) |
| scan_log.txt | Timestamped audit log (auto-created) |
| quarantine/ | Isolated threat files (auto-created) |

---

## Quick Start

### 1. Install the only required library
```
pip install requests
```

### 2. Set up demo environment
```
python antivirus.py setup-demo
```

### 3. Run basic scan (Layer 1 + Layer 3)
```
python antivirus.py scan test_folder/
```

### 4. Run full scan (all three layers)
```
python antivirus.py scan test_folder/ --virustotal
```

### 5. Scan and quarantine threats
```
python antivirus.py scan test_folder/ --virustotal --quarantine
```

### 6. Scan with email alerts
```
python antivirus.py scan test_folder/ --virustotal --quarantine --email
```

### 7. Generate HTML report
```
python report_generator.py --log scan_log.txt --out report.html
```

### 8. Open dashboard
Double-click dashboard.html in your file explorer to open in browser.

---

## All CLI Commands

```
python antivirus.py scan test_folder/                           Layer 1 + 3
python antivirus.py scan test_folder/ --virustotal              All 3 layers
python antivirus.py scan test_folder/ --virustotal --quarantine All 3 + quarantine
python antivirus.py scan test_folder/ --virustotal --quarantine --email   Full power

python antivirus.py scan file.exe                               Single file
python antivirus.py list-sigs                                   View signatures
python antivirus.py add-sig file.exe --label "Trojan.X"         Add signature
python antivirus.py setup-demo                                  Create test files

python heuristics.py                                            Test Layer 3 alone
python email_alert.py                                           Test email setup
python report_generator.py --log scan_log.txt --out report.html Generate report
```

---

## VirusTotal Setup (free)

1. Go to https://www.virustotal.com and sign up free
2. Click your username (top right) then My API key
3. Copy the key
4. Open virustotal_lookup.py and replace line 14:
   VT_API_KEY = "your_key_here"
5. Done — free tier gives 4 lookups per minute, 500 per day

Results are cached in vt_cache.json so the same hash is never queried twice.

---

## Email Alert Setup (optional)

1. Open email_alert.py
2. Fill in:
   EMAIL_SENDER       = "yourgmail@gmail.com"
   EMAIL_APP_PASSWORD = "your_16_char_app_password"
   EMAIL_RECEIVER     = "yourgmail@gmail.com"
   EMAIL_ENABLED      = True
3. To get App Password:
   myaccount.google.com > Security > 2-Step Verification > App Passwords > Mail

---

## Layer 3 Heuristic Checks

### Check 1 — Double extension
Catches files like invoice.pdf.exe where the real extension (.exe) is hidden
behind a fake innocent-looking one (.pdf). Flags as HIGH severity.

### Check 2 — Dangerous location
Catches executable files (.exe .bat .vbs .ps1 etc) sitting inside Temp,
AppData, or Recycle folders where legitimate software never lives.
Flags as MEDIUM severity.

### Check 3 — File size mismatch
Catches files whose size makes no sense for their type.
A .txt file that is 500MB or a .jpg that is 0 bytes is flagged.
Flags as MEDIUM severity.

---

## Detection Flow

```
File on disk
     |
     v
compute_hash() -- SHA-256 fingerprint
     |
     v
Layer 1: signatures.json     -- known hash? --> THREAT [LOCAL]
     | miss
     v
Layer 2: VirusTotal API      -- 3+ engines?  --> THREAT [VT]
     | miss
     v
Layer 3: heuristics.py       -- looks bad?   --> SUSPICIOUS
     | clean
     v
CLEAN
     |
     v (on any THREAT or SUSPICIOUS)
email_alert.py  -->  sends email notification
quarantine_file() -->  shutil.move to quarantine/
log_event()  -->  write to scan_log.txt
```

---

## Statuses Explained

| Status | Meaning | Action taken |
|---|---|---|
| CLEAN | No flags from any layer | Logged only |
| THREAT | Confirmed by Layer 1 or 2 | Quarantine + email alert |
| SUSPICIOUS | Layer 3 heuristic flags | Email alert, user decides |
| ERROR | File not found or unreadable | Logged only |

---

## Key Concepts Demonstrated

| Concept | Where in project |
|---|---|
| SHA-256 hashing | compute_hash() in antivirus.py |
| Signature matching | scan_file() Layer 1 check |
| Cloud threat intelligence | virustotal_lookup.py |
| API rate limiting | time.sleep(15) between VT calls |
| Local cache for quota | vt_cache.json in virustotal_lookup.py |
| Heuristic detection | heuristics.py — 3 pattern checks |
| Quarantine (not delete) | quarantine_file() using shutil.move() |
| Audit logging | log_event() append mode |
| Recursive folder scan | Path.rglob() in scan_folder() |
| False negative limitation | Modified file = new hash = evades Layer 1 |
| Email notification | email_alert.py using smtplib |

---

## Project Roadmap

### Completed
- [x] Layer 1 — local signature scanning
- [x] Layer 2 — VirusTotal API integration
- [x] Layer 3 — heuristic detection engine
- [x] Quarantine system
- [x] Email alert notifications
- [x] GUI browser dashboard
- [x] HTML scan report generator
- [x] VT result caching

## Notes

- Educational use only
- Simulated malware files contain plain text — completely safe
- Layer 2 requires internet and a free VirusTotal account
- VT threshold is 3 engines to avoid false positives
- SUSPICIOUS files are not auto-quarantined — user reviews manually
