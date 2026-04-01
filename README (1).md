# Security Engineering Take-Home Assignment

Three assignments covering phishing detection, malware sandboxing, and SQL injection — built as part of a security engineering interview process.

---

## Assignment 1 — Email Phishing Detector

A rule-based phishing detector with a CLI scanner (`detector.py`) and a Flask web UI on top. The detection logic lives in a single module.

The analyzer splits the raw email into headers and body, then runs three independent checks that feed into a weighted score:

- **Sender check** — flags raw IP senders and typosquatted domains using SequenceMatcher (similarity between 0.75 and 1.0)
- **Link check** — flags URLs pointing to raw IPs and hostnames on known-abused TLDs (.tk, .ml, .xyz, etc.)
- **Urgent language check** — scans the body for ~20 phrases that consistently show up in phishing campaigns

Scoring: sender issues → 4pts, link issues → 3pts, language → 1pt per phrase. Thresholds: HIGH (≥7), MEDIUM (≥3), LOW (any hit), CLEAN (nothing).

**Run it:**
```bash
cd Analyze_email
pip install -r requirements.txt

# CLI
python detector.py sample_email.txt

# Web UI
python app.py
# Open http://localhost:5000
```

---

## Assignment 2 — Malware Analysis Sandbox

A containerized sandbox that runs simulated malware, monitors its behavior in real time, and generates a structured risk report.

**Architecture:**

```
Host Machine
├── app.py        Flask control plane — starts/stops Docker, serves the UI
├── monitor.py    Standalone behavioral monitor — tails logs, fires alerts
├── report.py     Report generator — reads logs, makes a risk determination
└── logs/         Volume-mounted into the container at /logs

Docker Container
├── fake_malware.py   Simulated malware — writes structured logs to /logs
└── strace            Wraps execution, writes raw syscall trace to /logs/syscalls.log
```

The `/logs` directory is the only channel between the container and the host — same physical directory on disk from both sides. The malware writes to it, the monitor reads from it in real time.

`fake_malware.py` simulates three phases of a typical infection: staging files (`drop_files`), beaconing out (`beacon`), and system recon (`recon`). The Dockerfile wraps execution with strace so every file open, network connection, and process spawn is captured at the kernel boundary regardless of what the malware reports about itself.

`monitor.py` runs as a separate process from Flask — same way production EDR agents run independently of whatever UI is displaying their data.

**Run it:**
```bash
cd Malware
pip install -r requirements.txt

# Terminal 1 — start the web UI
python app.py
# Open http://localhost:8080

# Terminal 2 — start the behavioral monitor
python monitor.py
```

Docker Desktop needs to be running. First build takes a minute because it installs strace into the image.

---

## Assignment 3 — SQL Injection Demo

A Flask app with a SQLite backend that demonstrates SQL injection through a direct side-by-side comparison — same login form, same attack payload, two different backend implementations.

**Vulnerable:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
conn.execute(query)
```
The payload `' OR '1'='1' --` closes the string literal early, comments out the password check, and returns the first row in the table. No valid credentials needed.

**Secure:**
```python
query_template = "SELECT * FROM users WHERE username = ? AND password = ?"
conn.execute(query_template, (username, password))
```
The query is compiled before the values arrive. A quote in the input has no SQL structure to break into — the payload gets treated as a literal string and login fails.

Passwords are stored in plaintext intentionally. bcrypt would be the right call in production, but adding it here would pull focus from the injection demo.

Test users seeded on first run: `admin/password`, `alice/alice_123`, `bob/bob_234`.

**Run it:**
```bash
cd sql_injection
pip install -r requirements.txt
python app.py
# Open http://localhost:5001
```

---

## Dependencies

- Python 3.9+
- Flask
- Docker Desktop (Assignment 2 only)
