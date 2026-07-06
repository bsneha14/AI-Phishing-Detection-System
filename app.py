from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
import pickle, re, sqlite3, csv, io, json
from datetime import datetime
from urllib.parse import urlparse, quote
from feature_extractor import extract_features
import webbrowser

FEATURE_NAMES = [
    "IP Address Used", "URL Length", "URL Shortener", "@ Symbol",
    "Double Slash Redirect", "Prefix/Suffix Dash", "Subdomains",
    "SSL State", "Domain Registration", "Favicon", "Non-Standard Port",
    "HTTPS in Domain", "Request URL", "Anchor URL", "Links in Tags",
    "Form Handler", "Email Submission", "Abnormal URL", "Redirect Count",
    "Mouseover", "Right Click Disabled", "Popup Window", "iFrame",
    "Domain Age", "DNS Record", "Web Traffic", "Page Rank",
    "Google Index", "Links Pointing", "Statistical Report",
]

app = Flask(__name__)
DB  = 'history.db'

# ─── Jinja2 Custom Filter ─────────────────────────────────────
@app.template_filter('strftime')
def _jinja2_filter_datetime(date, fmt=None):
    if date is None:
        return ""
    if fmt:
        return date.strftime(fmt)
    return date.strftime("%Y-%m-%d")

# Make urlencode available inside templates

# ─── Load Model ───────────────────────────────────────────────
with open('phishing_model.pkl', 'rb') as f:
    model = pickle.load(f)

# ─── Database Setup ───────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB)
    con.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            url        TEXT    NOT NULL,
            result     TEXT    NOT NULL,
            confidence REAL,
            score      INTEGER DEFAULT 0,
            level      TEXT    DEFAULT '',
            reason     TEXT,
            method     TEXT    DEFAULT 'single',
            scanned_at TEXT    DEFAULT (datetime('now','localtime'))
        )
    ''')
    # Auto-add columns for existing DBs that may not have newer columns
    for col, typedef in [
        ("score",  "INTEGER DEFAULT 0"),
        ("level",  "TEXT DEFAULT ''"),
        ("method", "TEXT DEFAULT 'single'"),
    ]:
        try:
            con.execute(f"ALTER TABLE scans ADD COLUMN {col} {typedef}")
        except Exception:
            pass
    con.commit()
    con.close()

def save_scan(url, result, confidence, reason, score=0, level='', method='single'):
    con = sqlite3.connect(DB)
    con.execute(
        'INSERT INTO scans (url, result, confidence, score, level, reason, method) '
        'VALUES (?,?,?,?,?,?,?)',
        (url, result, confidence, score, level, reason, method)
    )
    con.commit()
    con.close()

def get_history(q='', verdict='', method='', sort='newest', page=1, per_page=20):
    """
    Returns (list_of_dicts, total_count) with optional filtering/sorting/pagination.
    """
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row

    conditions = []
    params     = []

    if q:
        conditions.append("url LIKE ?")
        params.append(f"%{q}%")
    if verdict:
        conditions.append("result = ?")
        params.append(verdict.upper())
    if method:
        conditions.append("method = ?")
        params.append(method.lower())

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # count total
    total = con.execute(
        f"SELECT COUNT(*) FROM scans {where}", params
    ).fetchone()[0]

    # sort
    order_map = {
        'newest':     'id DESC',
        'oldest':     'id ASC',
        'score_high': 'score DESC',
        'score_low':  'score ASC',
    }
    order = order_map.get(sort, 'id DESC')

    offset = (page - 1) * per_page
    rows = con.execute(
        f"SELECT id, url, result, confidence, score, level, reason, method, scanned_at "
        f"FROM scans {where} ORDER BY {order} LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    con.close()
    return [dict(r) for r in rows], total

def get_stats():
    con  = sqlite3.connect(DB)
    cur  = con.cursor()
    total      = cur.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    phishing   = cur.execute("SELECT COUNT(*) FROM scans WHERE result='PHISHING'").fetchone()[0]
    legit      = cur.execute("SELECT COUNT(*) FROM scans WHERE result='LEGITIMATE'").fetchone()[0]
    suspicious = cur.execute("SELECT COUNT(*) FROM scans WHERE result='SUSPICIOUS'").fetchone()[0]
    reasons    = cur.execute(
        "SELECT reason, COUNT(*) as c FROM scans WHERE result='PHISHING' "
        "GROUP BY reason ORDER BY c DESC LIMIT 6"
    ).fetchall()
    con.close()
    return {
        'total':      total,
        'phishing':   phishing,
        'legit':      legit,
        'suspicious': suspicious,
        'reasons':    [{'label': r[0][:40] if r[0] else 'Unknown', 'count': r[1]} for r in reasons],
    }

init_db()

# ─── Cybercrime Link ───────────────────────────────────────────
CYBERCRIME_LINK = {
    "type":  "link",
    "url":   "https://cybercrime.gov.in",
    "label": "File an official cybercrime complaint → cybercrime.gov.in"
}

# ─── Reason Explanations ──────────────────────────────────────
REASON_EXPLANATIONS = {
    "IP address used instead of domain name": (
        "Legitimate websites always use a domain name (like google.com). "
        "Using a raw IP address (e.g. http://192.168.1.1/login) is a classic attacker trick "
        "to bypass domain reputation checks and hide the true owner of the server."
    ),
    "Suspicious free domain extension detected": (
        "Extensions like .tk, .ml, .ga, .xyz are available for free and are "
        "heavily abused in phishing campaigns because they cost nothing to register "
        "and can be abandoned immediately after an attack without financial loss."
    ),
    "@ symbol found in URL": (
        "Browsers ignore everything before an @ symbol in a URL and treat it as "
        "login credentials. Attackers write 'paypal.com@evil.com/steal' so the URL "
        "looks legitimate at a glance but actually loads evil.com instead."
    ),
    "Too many subdomains detected": (
        "Attackers stack subdomains like 'paypal.secure.verify.evil.com' to visually "
        "mimic a legitimate domain. The real domain is always the part just before the "
        "TLD — every subdomain before that is under the attacker's control."
    ),
    "URL shortener detected": (
        "URL shorteners like bit.ly hide the real destination entirely. Phishers use them "
        "to mask malicious links and bypass email/spam filters that block known bad domains."
    ),
    "Multiple phishing keywords found": (
        "The URL contains multiple terms (like 'verify', 'login', 'confirm', 'account', "
        "'password') that are statistically overrepresented in phishing URLs. Legitimate "
        "sites rarely combine more than one of these in a single URL path."
    ),
    "HTTP with suspicious keywords": (
        "Sensitive actions like login or account verification must happen over HTTPS. "
        "Using plain HTTP sends all data in cleartext. Combining HTTP with sensitive "
        "keywords like 'banking' or 'verify' is a strong phishing signal."
    ),
    "Very long URL with suspicious patterns": (
        "Phishers craft excessively long URLs to bury the malicious domain deep in the "
        "path, hoping users focus only on the visible start of the URL in the address bar."
    ),
    "Dash in domain with phishing keywords": (
        "Legitimate brands almost never hyphenate their core domain. A pattern like "
        "'paypal-secure.com' combined with keywords like 'login' or 'verify' strongly "
        "indicates a spoofed/impersonation domain."
    ),
    "Multiple dashes in domain name": (
        "Multiple hyphens in a domain name (e.g. paypal-secure-login.com) are a "
        "hallmark of phishing impersonation domains attempting to look official "
        "while unable to register the actual brand domain."
    ),
    "Machine Learning Model Analysis": (
        "Our Random Forest model analyzed 30 structural features of this URL — including "
        "length buckets, SSL state, hyphen usage, keyword presence, redirect patterns, "
        "port anomalies, and subdomain depth — and found the combination of signals "
        "is statistically consistent with phishing URLs in its training data."
    ),
}

DEFAULT_EXPLANATION = (
    "This URL exhibits a combination of structural signals — unusual domain patterns, "
    "suspicious keywords, or encoding tricks — that are statistically associated "
    "with phishing attempts based on our trained model."
)

def get_reason_explanation(reason):
    for key, explanation in REASON_EXPLANATIONS.items():
        if key.lower() in reason.lower() or reason.lower() in key.lower():
            return explanation
    return DEFAULT_EXPLANATION

# ─── Recovery Steps ───────────────────────────────────────────
RECOVERY_STEPS = {
    "IP address used instead of domain name": [
        "Do NOT click any links or download attachments from this source.",
        "Report the email/message to your email provider as phishing.",
        "If you already clicked, disconnect from the internet immediately.",
        "Run a full antivirus/malware scan on your device.",
        "Change passwords for any accounts you may have entered.",
        "Enable two-factor authentication (2FA) on critical accounts.",
        "Monitor your bank statements for unauthorized transactions.",
        CYBERCRIME_LINK,
    ],
    "Suspicious free domain extension detected": [
        "Avoid entering any personal or financial information on this site.",
        "Report the URL to Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish/",
        "Clear your browser cache and cookies immediately.",
        "If credentials were entered, change them right now.",
        "Notify your IT/security team if this was accessed on a work device.",
        "Check 'Have I Been Pwned' (haveibeenpwned.com) for data breaches.",
        CYBERCRIME_LINK,
    ],
    "@ symbol found in URL": [
        "This is a classic phishing redirect trick — do not proceed.",
        "Close this browser tab immediately without interacting.",
        "Report to your ISP or national cybersecurity authority.",
        "If you already accessed it, scan your device with Malwarebytes or Windows Defender.",
        "Check your email account for suspicious login activity.",
        CYBERCRIME_LINK,
    ],
    "Too many subdomains detected": [
        "The domain structure is engineered to look legitimate — it is not.",
        "Verify the real domain by navigating directly to the official website.",
        "Use WHOIS lookup (whois.domaintools.com) to check domain age and ownership.",
        "If you submitted any data, contact your bank or the impersonated company.",
        CYBERCRIME_LINK,
    ],
    "URL shortener detected": [
        "Expand the URL first using unshorten.it or checkshorturl.com before visiting.",
        "Never trust shortened URLs received from unknown or unverified senders.",
        "If the expanded URL looks suspicious, do not visit it.",
        "Report abuse to the shortener service (Bitly, TinyURL).",
        CYBERCRIME_LINK,
    ],
    "Machine Learning Model Analysis": [
        "Verify the website through official channels before entering any data.",
        "Look for HTTPS and a valid SSL certificate (the padlock icon in your browser).",
        "Cross-check the domain on VirusTotal (virustotal.com) for third-party validation.",
        "Do not submit login credentials or payment information.",
        "When in doubt, navigate directly to the company's official website.",
        "Contact the company via their official phone number or email to verify.",
        CYBERCRIME_LINK,
    ],
}

DEFAULT_RECOVERY = [
    "Do not interact further with this URL.",
    "Run a security scan on your device using trusted antivirus software.",
    "Change passwords for any accounts that may be compromised.",
    "Enable two-factor authentication (2FA) wherever possible.",
    "Report the phishing URL at: safebrowsing.google.com/safebrowsing/report_phish/",
    "Notify your bank immediately if any financial details were shared.",
    CYBERCRIME_LINK,
]

def get_recovery_steps(reason):
    for key in RECOVERY_STEPS:
        if key.lower() in reason.lower() or reason.lower() in key.lower():
            return RECOVERY_STEPS[key]
    return DEFAULT_RECOVERY

# ─── Threat Score (0–100) ─────────────────────────────────────
def threat_score(result, confidence, reason):
    if result == "LEGITIMATE":
        return round((1 - confidence / 100) * 40)
    base = confidence
    boosts = {
        "IP address": 10,
        "@ symbol":   10,
        "shortener":   8,
        "subdomains":  7,
        "free domain": 6,
        "keywords":    5,
        "HTTP":        5,
    }
    for kw, pts in boosts.items():
        if kw.lower() in reason.lower():
            base = min(100, base + pts)
    return round(base)

def threat_level(score):
    if score <= 30: return "LOW",      "safe"
    if score <= 60: return "MEDIUM",   "warn"
    if score <= 80: return "HIGH",     "danger"
    return                 "CRITICAL", "danger"

# ─── Rule Engine ──────────────────────────────────────────────
def is_phishing_by_rules(url):
    parsed    = urlparse(url)
    hostname  = parsed.hostname or ""
    url_lower = url.lower()

    if re.search(r'\d+\.\d+\.\d+\.\d+', hostname):
        return True, "IP address used instead of domain name"

    bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq',
                '.xyz', '.top', '.click', '.link', '.work']
    if any(hostname.endswith(t) for t in bad_tlds):
        return True, "Suspicious free domain extension detected"

    if '@' in url:
        return True, "@ symbol found in URL"

    if hostname.count('.') > 3:
        return True, "Too many subdomains detected"

    phishing_keywords = [
        'secure', 'account', 'update', 'login', 'verify',
        'banking', 'confirm', 'paypal', 'signin', 'password',
        'credential', 'ebay', 'apple-id', 'suspended',
        'locked', 'unusual', 'validate', 'authenticate'
    ]
    matched = [k for k in phishing_keywords if k in url_lower]
    if len(matched) >= 2:
        return True, f"Multiple phishing keywords found: {', '.join(matched)}"

    if parsed.scheme == 'http' and any(k in url_lower for k in phishing_keywords):
        return True, "HTTP with suspicious keywords"

    if len(url) > 100 and ('-' in hostname or any(k in url_lower for k in phishing_keywords)):
        return True, "Very long URL with suspicious patterns"

    if '-' in hostname and any(k in url_lower for k in phishing_keywords):
        return True, "Dash in domain with phishing keywords"

    if hostname.count('-') >= 2:
        return True, "Multiple dashes in domain name"

    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd']
    if any(s in url for s in shorteners):
        return True, "URL shortener detected"

    return False, ""

# ─── Core Scan Logic ──────────────────────────────────────────
def scan_url(url):
    phishing_by_rule, rule_reason = is_phishing_by_rules(url)
    if phishing_by_rule:
        result, confidence, reason = "PHISHING", 95.0, rule_reason
        features = extract_features(url)
    else:
        features   = extract_features(url)
        prediction = model.predict([features])[0]
        proba      = model.predict_proba([features])[0]
        confidence = round(max(proba) * 100, 2)
        result     = "PHISHING" if prediction == 1 else "LEGITIMATE"
        reason     = "Machine Learning Model Analysis"

    score        = threat_score(result, confidence, reason)
    level, color = threat_level(score)
    explanation  = get_reason_explanation(reason) if result == "PHISHING" else ""
    recovery     = get_recovery_steps(reason)     if result == "PHISHING" else []

    dna = []
    for name, val in zip(FEATURE_NAMES, features):
        if val == 1:
            status  = "suspicious"
            meaning = "Flagged as risky"
        elif val == -1:
            status  = "safe"
            meaning = "Looks normal"
        else:
            status  = "neutral"
            meaning = "Could not determine"
        dna.append({"name": name, "value": val, "status": status, "meaning": meaning})

    return result, confidence, reason, score, level, color, explanation, recovery, dna

# ══════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════

# ─── Home / Single Scanner ────────────────────────────────────
@app.route('/', methods=['GET', 'POST'])
def index():
    ctx = dict(result=None, url="", confidence=0, reason="",
               score=0, level="", color="", explanation="",
               recovery_steps=[], stats=get_stats(), dna=[])

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            try:
                result, confidence, reason, score, level, \
                color, explanation, recovery, dna = scan_url(url)

                save_scan(url, result, confidence, reason, score, level, method='single')
                ctx.update(result=result, url=url, confidence=confidence,
                           reason=reason, score=score, level=level, color=color,
                           explanation=explanation, recovery_steps=recovery,
                           stats=get_stats(), dna=dna)
            except Exception as e:
                ctx.update(result="ERROR", url=url, reason=str(e))

    return render_template('index.html', **ctx)

# ─── Bulk Scan ────────────────────────────────────────────────
@app.route('/bulk', methods=['GET', 'POST'])
def bulk_scan():
    results  = []
    raw_urls = ''

    if request.method == 'POST':
        raw_urls = request.form.get('urls', '')
        url_list = [u.strip() for u in raw_urls.split('\n') if u.strip()]

        for url in url_list[:50]:
            try:
                result, confidence, reason, score, level, \
                color, explanation, recovery, dna = scan_url(url)

                save_scan(url, result, confidence, reason, score, level, method='bulk')
                results.append({
                    'url':        url,
                    'result':     result,
                    'confidence': confidence,
                    'score':      score,
                    'level':      level,
                    'reason':     reason,
                })
            except Exception as e:
                results.append({
                    'url':        url,
                    'result':     'ERROR',
                    'confidence': 0,
                    'score':      0,
                    'level':      '',
                    'reason':     str(e),
                })

    return render_template('bulk.html', results=results, raw_urls=raw_urls)

# ─── Bulk Export CSV ──────────────────────────────────────────
@app.route('/bulk/export')
def bulk_export():
    # Export the most recent bulk scan results from the DB
    con = sqlite3.connect(DB)
    rows = con.execute(
        "SELECT id, url, result, confidence, score, level, reason, scanned_at "
        "FROM scans WHERE method='bulk' ORDER BY id DESC LIMIT 200"
    ).fetchall()
    con.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'URL', 'Result', 'Confidence', 'Score', 'Level', 'Reason', 'Scanned At'])
    cw.writerows(rows)
    output = io.BytesIO(si.getvalue().encode())
    return send_file(output, mimetype='text/csv',
                     as_attachment=True, download_name='phishguard_bulk.csv')

# ─── Scan History ─────────────────────────────────────────────
@app.route('/history')
def history():

    scans = []

    stats = {
        "total": 0,
        "phishing": 0,
        "suspicious": 0,
        "legit": 0
    }

    filters = {
        "q": "",
        "verdict": "",
        "method": "",
        "sort": "newest"
    }

    pagination = {
        "page": 1,
        "pages": 1,
        "total": 0,
        "offset": 0
    }

    return render_template(
        "history.html",
        scans=scans,
        stats=stats,
        filters=filters,
        pagination=pagination
    )

# ─── History Export CSV ───────────────────────────────────────
@app.route('/history/export')
def export_history():
    q       = request.args.get('q', '')
    verdict = request.args.get('verdict', '')
    method  = request.args.get('method', '')

    scans, _ = get_history(q=q, verdict=verdict, method=method,
                           sort='newest', page=1, per_page=10000)

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'URL', 'Result', 'Confidence', 'Score',
                 'Level', 'Reason', 'Method', 'Scanned At'])
    for s in scans:
        cw.writerow([s['id'], s['url'], s['result'], s['confidence'],
                     s['score'], s['level'], s['reason'],
                     s.get('method', 'single'), s['scanned_at']])
    output = io.BytesIO(si.getvalue().encode())
    return send_file(output, mimetype='text/csv',
                     as_attachment=True, download_name='phishguard_history.csv')

# ─── History Export JSON ──────────────────────────────────────
@app.route('/history/export.json')
def export_history_json():
    q       = request.args.get('q', '')
    verdict = request.args.get('verdict', '')
    method  = request.args.get('method', '')

    scans, _ = get_history(q=q, verdict=verdict, method=method,
                           sort='newest', page=1, per_page=10000)
    output = io.BytesIO(json.dumps(scans, indent=2).encode())
    return send_file(output, mimetype='application/json',
                     as_attachment=True, download_name='phishguard_history.json')

# ─── Clear History ────────────────────────────────────────────
@app.route('/history/clear', methods=['POST'])
def clear_history():
    con = sqlite3.connect(DB)
    con.execute('DELETE FROM scans')
    con.commit()
    con.close()
    return redirect(url_for('history'))

# ─── Delete Single Scan ───────────────────────────────────────
@app.route('/history/delete/<int:scan_id>', methods=['GET' ,'POST'])
def delete_scan(scan_id):
    con = sqlite3.connect(DB)
    con.execute('DELETE FROM scans WHERE id=?', (scan_id,))
    con.commit()
    con.close()
    return redirect(url_for('history'))

# ─── API: Check URL ───────────────────────────────────────────
@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json()
    url  = (data or {}).get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    try:
        result, confidence, reason, score, level, color, explanation, recovery, dna = scan_url(url)
        save_scan(url, result, confidence, reason, score, level, method='api')
        return jsonify({
            'result':         result,
            'confidence':     confidence,
            'reason':         reason,
            'threat_score':   score,
            'threat_level':   level,
            'explanation':    explanation,
            'recovery_steps': recovery,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── API: Stats ───────────────────────────────────────────────
@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

# ─── API: History (JSON) ──────────────────────────────────────
@app.route('/api/history')
def api_history():
    scans, total = get_history(page=1, per_page=100)
    return jsonify({'total': total, 'scans': scans})

if __name__ == "__main__":
    webbrowser.open("http://127.0.0.1:5000")
    app.run(debug=True)

# ─── Run ──────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)