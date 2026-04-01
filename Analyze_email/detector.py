import re
import sys
import argparse
from difflib import SequenceMatcher

LEGIT_DOMAINS = [
    'google.com', 'paypal.com', 'apple.com', 'microsoft.com',
    'amazon.com', 'facebook.com', 'bankofamerica.com', 'chase.com',
    'wellsfargo.com', 'irs.gov', 'netflix.com', 'instagram.com',
    'linkedin.com', 'twitter.com', 'dropbox.com',
]

URGENT_PHRASES = [
    'action required', 'verify your account', 'your account will be',
    'unauthorized access', 'suspicious activity', 'update your information',
    'confirm your identity', 'password expired', 'billing problem',
    'update your payment', 'you have won', 'claim your prize',
    'limited time offer', 'act now', 'urgent', 'immediately',
    'suspended', 'account blocked', 'click here', 'free gift',
]

# TLDs commonly abused in phishing campaigns
SUSPICIOUS_TLDS = ('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.ru', '.top', '.click')


def _parse_email(raw):
    lines = raw.splitlines()
    headers = {}

    i = 0
    for i, line in enumerate(lines):
        if not line.strip():
            break
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip().lower()] = v.strip()

    return headers, '\n'.join(lines[i + 1:])


def _extract_domain(from_field):
    m = re.search(r'[\w.+\-]+@([\w.\-]+)', from_field)
    return m.group(1).lower() if m else None


def check_sender(from_field):
    domain = _extract_domain(from_field)
    if not domain:
        return None

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        return f"IP address used as sender domain ({domain})"

    for legit in LEGIT_DOMAINS:
        ratio = SequenceMatcher(None, domain, legit).ratio()
        # 0.75 catches close variants like paypa1.com vs paypal.com;
        # capped at < 1.0 so an exact match isn't flagged as spoofing
        if 0.75 < ratio < 1.0:
            return f"'{domain}' closely resembles '{legit}' — possible spoofing"

    return None


def check_links(body):
    results = []
    for url in re.findall(r'https?://[^\s<>"\']+', body):
        if re.match(r'https?://\d{1,3}(\.\d{1,3}){3}', url):
            results.append(f"IP-based URL: {url}")
            continue
        m = re.match(r'https?://([^/?#]+)', url)
        if m:
            host = m.group(1).lower().split(':')[0]
            if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
                results.append(f"suspicious domain: {url}")
    return results


def check_urgent_language(body):
    lower = body.lower()
    return [p for p in URGENT_PHRASES if p in lower]


def analyze(content):
    headers, body = _parse_email(content)

    hits = []

    sender_issue = check_sender(headers.get('from', ''))
    if sender_issue:
        hits.append(('sender', sender_issue))

    for phrase in check_urgent_language(body):
        hits.append(('language', f"urgent phrase detected: '{phrase}'"))

    for link in check_links(body):
        hits.append(('link', link))

    weights = {'sender': 4, 'link': 3, 'language': 1}
    score = sum(weights[cat] for cat, _ in hits)

    if score >= 7:
        verdict = 'HIGH RISK'
    elif score >= 3:
        verdict = 'MEDIUM RISK'
    elif hits:
        verdict = 'LOW RISK'
    else:
        verdict = 'CLEAN'

    return {
        'verdict': verdict,
        'score': score,
        'from': headers.get('from', 'N/A'),
        'subject': headers.get('subject', '(no subject)'),
        'findings': hits,
    }


SUMMARY = {
    'HIGH RISK':   'This email is very likely a phishing attempt.',
    'MEDIUM RISK': 'This email shows signs of being a phishing attempt.',
    'LOW RISK':    'This email has minor phishing indicators — treat with caution.',
    'CLEAN':       'This email does not appear to be a phishing attempt.',
}


def _print_result(r):
    print(f"\n{'=' * 52}")
    print(f"  From    : {r['from']}")
    print(f"  Subject : {r['subject']}")
    print(f"  Verdict : {r['verdict']}  (score: {r['score']})")
    print(f"  Summary : {SUMMARY[r['verdict']]}")
    print(f"{'=' * 52}")

    if r['findings']:
        print("\n  Indicators:")
        for _, msg in r['findings']:
            print(f"    [!] {msg}")
    else:
        print("\n  No phishing indicators detected.")
    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='scan an email .txt file for phishing indicators')
    parser.add_argument('file', help='path to the .txt email file')
    args = parser.parse_args()

    try:
        with open(args.file, encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"error: '{args.file}' not found")
        sys.exit(1)
    except UnicodeDecodeError:
        print("error: file must be UTF-8 encoded")
        sys.exit(1)

    _print_result(analyze(content))
