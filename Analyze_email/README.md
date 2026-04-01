# Email Phishing Detector

A dual-interface (CLI and Web) phishing detection tool that evaluates emails based on a weighted heuristic scoring system. Built with **Python** and **Flask**.

---

## Detection Logic

The detector evaluates raw `.txt` or `.eml` files across three weighted criteria:

1. **Sender Spoofing (Weight: 4)**
   Matches the `From:` header domain against a known list of high-value targets (Google, PayPal, Microsoft, etc.) using `SequenceMatcher`. Flags domains that attempt typosquatting (e.g., `paypa1.com` instead of `paypal.com`) or use raw IP addresses.

2. **Suspicious Links (Weight: 3)**
   Extracts URLs from the email body and flags those pointing directly to raw IP addresses or utilizing cheap/suspicious Top-Level Domains (TLDs) like `.tk`, `.ml`, or `.xyz`.

3. **Urgent Language (Weight: 1 per phrase)**
   Scans the body against a dictionary of common social engineering phrases designed to induce panic (e.g., "action required", "account suspended").

The final cumulative score maps to a clear risk verdict: **CLEAN**, **LOW RISK**, **MEDIUM RISK**, or **HIGH RISK**.

## Requirements

- Python 3.11+

## Usage

You can use the detector either as a command-line utility or via the web interface.

### Option 1: Web Interface

**1. Install Dependencies & Start Server:**
```bash
pip install -r requirements.txt
python app.py
```

**2. Access the Application:**
Open your browser and navigate to:
```
http://localhost:5001
```

**3. Upload:**
Select an email text file (like `sample_phishing.txt`) and click **Analyze**. The UI will present a verdict banner along with a drill-down into specific detected indicators.

### Option 2: Command-Line Interface

For quick analysis or integration into other pipelines, run the detector directly against a file:

```bash
python detector.py sample_phishing.txt
```

**Sample Output:**
```
====================================================
  From    : security@paypa1.com
  Subject : Urgent: Your account has been suspended
  Verdict : HIGH RISK  (score: 8)
  Summary : This email is very likely a phishing attempt.
====================================================

  Indicators:
    [!] 'paypa1.com' closely resembles 'paypal.com' — possible spoofing
    [!] urgent phrase detected: 'action required'
    [!] IP-based URL: http://192.168.10.55/paypal/verify/login
```
