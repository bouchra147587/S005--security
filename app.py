from flask import Flask, request, jsonify, render_template
import joblib, re, numpy as np, scipy.sparse as sp
from urllib.parse import urlparse
import os

app = Flask(__name__)

required_files = ['best_model.pkl', 'tfidf_subject.pkl', 'tfidf_body.pkl', 'scaler.pkl']
missing = [f for f in required_files if not os.path.exists(f)]
if missing:
    print(f"ERROR: Missing files: {missing}")
    print("Make sure all model files are in the same directory as app.py")
    exit(1)

model         = joblib.load('best_model.pkl')
tfidf_subject = joblib.load('tfidf_subject.pkl')
tfidf_body    = joblib.load('tfidf_body.pkl')
scaler        = joblib.load('scaler.pkl')

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf',
    '.gq', '.pw', '.club', '.work', '.link', '.click', '.win',
    '.online', '.site', '.info', '.biz', '.pro'
}
URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
IP_PATTERN  = re.compile(r'https?://(\d{1,3}\.){3}\d{1,3}', re.IGNORECASE)
HTML_TAG_PATTERN = re.compile(r'<[a-zA-Z][^>]*>', re.IGNORECASE)

FREE_EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'live.com', 'aol.com', 'icloud.com', 'protonmail.com',
    'mail.com', 'zoho.com', 'yandex.com', 'gmx.com'
}

# Whitelist of highly reputable domains (never phishing from these)
TRUSTED_DOMAINS = {
    'amazon.com', 'github.com', 'linkedin.com', 'microsoft.com',
    'google.com', 'apple.com', 'facebook.com', 'twitter.com',
    'paypal.com', 'netflix.com', 'uber.com', 'airbnb.com',
    'spotify.com', 'slack.com', 'zoom.us', 'teams.microsoft.com',
    'calendar.teams.microsoft.com', 'dropbox.com', 'box.com',
    'adobe.com', 'salesforce.com', 'atlassian.com', 'github.io'
}

# Domains commonly impersonated in phishing (spoofed)
SPOOFED_PATTERNS = [
    'outlook-helpdesk', 'microsoft-support', 'google-verify', 'paypal-secure',
    'amazon-account', 'apple-id', 'netflix-security', 'facebook-security'
]

PHISHING_KEYWORDS = [
    # === DATA-DRIVEN KEYWORDS (Top 30 from chi-squared test on CEAS_08 dataset) ===
    # Note: Removed overly generic terms ('com', 'org', 'mail', 'dev') that appear in legitimate emails
    # and appear mostly in old mailing lists in the CEAS_08 dataset
    'python', 'cnn', 'wrote', 'replica', 'watches',
    'python org', 'python dev', 'cnn com', 'opensuse', 'index html',
    'list', 'perl', 'love', 'www cnn', 'mailman',
    'python 3000', '2007', '3000', 'file', 'index', 'message',
    'http mail', 'health', 'org mailman', 'mail python', 'bug',
    # === EXPERT-CURATED KEYWORDS (For generalization beyond CEAS_08) ===
    # Account / Credential theft
    'validate', 'authenticate', 'verify account', 'confirm identity',
    'password', 're-enter', 'reactivate', 'suspended', 'locked',
    'verification', 'credential', 'confirm password',
    # Financial lures
    'paypal', 'wire transfer', 'prize', 'winner', 'lottery',
    'cashback', 'bitcoin', 'crypto', 'million', 'inheritance',
    'refund', 'tax return', 'payment failed',
    # Urgency / Fear
    'urgent action', 'immediately', 'action required', 'limited time',
    'deadline', 'last chance', 'important notice',
    'your account will be closed', 'failure to comply',
    'act now', 'expires', 'expired',
    # Generic phishing
    'click here', 'click link', 'follow link',
    'dear customer', 'dear user', 'dear member',
    'congratulations', 'chosen', 'claim reward',
    'confirm details', 'update information',
]

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'action required', 'expire', 'expires',
    'deadline', 'last chance', 'limited time', 'act now', 'respond now',
    'failure to act', 'your account will be'
]


def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = text.encode('ascii', errors='ignore').decode()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()

def extract_urls(text):
    if not text:
        return []
    return URL_PATTERN.findall(str(text))

def get_sender_domain(sender):
    if not sender:
        return ''
    match = re.search(r'@([\w.\-]+)', str(sender))
    return match.group(1).lower() if match else ''

def extract_domain(email_field):
    if not email_field:
        return 'unknown'
    match = re.search(r'@([\w.\-]+)', str(email_field))
    return match.group(1).lower() if match else 'unknown'

def extract_numeric_features(subject, body, sender="", receiver=""):
    """
    Extracts the exact 18 numeric features used during training (Role 2).
    Order must match NUMERIC_FEATURES in the notebook.
    """
    urls = extract_urls(body)

    # URL features
    url_count = len(urls)

    has_ip = int(bool(IP_PATTERN.search(body))) if body else 0

    has_susp_tld = 0
    for url in urls:
        try:
            domain = urlparse(url).netloc.lower().split(':')[0]
            if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                has_susp_tld = 1
                break
        except Exception:
            pass

    max_url_len = max((len(u) for u in urls), default=0)

    has_mismatch = 0
    sender_domain = get_sender_domain(sender)
    if sender_domain:
        for url in urls:
            try:
                url_domain = urlparse(url).netloc.lower().split(':')[0]
                url_domain = re.sub(r'^www\.', '', url_domain)
                sd_stripped = re.sub(r'^www\.', '', sender_domain)
                if url_domain and url_domain != sd_stripped:
                    has_mismatch = 1
                    break
            except Exception:
                pass

    # Keyword features 
    body_lower = (body or '').lower()
    subj_lower = (subject or '').lower()

    subject_kw = sum(1 for kw in PHISHING_KEYWORDS if kw in subj_lower)
    body_kw    = sum(1 for kw in PHISHING_KEYWORDS if kw in body_lower)
    total_kw   = sum(1 for kw in PHISHING_KEYWORDS if kw in (body_lower + ' ' + subj_lower))
    has_urgency = int(any(kw in (body_lower + ' ' + subj_lower) for kw in URGENCY_KEYWORDS))

    # Structural features
    sender_is_free = int(extract_domain(sender) in FREE_EMAIL_DOMAINS)

    recv_domain = extract_domain(receiver)
    send_domain = extract_domain(sender)
    domain_match = int(
        send_domain != 'unknown' and
        recv_domain != 'unknown' and
        send_domain == recv_domain
    )

    body_len    = len(body or '')
    subject_len = len(subject or '')
    excl_count  = (body or '').count('!')
    quest_count = (body or '').count('?')
    has_html    = int(bool(HTML_TAG_PATTERN.search(body or '')))

    # sending_hour and sending_dayofweek are unknown at inference time
    # Set to -1 (NaT placeholder used during training) to avoid prediction drift
    sending_hour       = -1
    sending_dayofweek  = -1   

    return [
        url_count,          # url_count
        has_ip,             # has_ip_url
        has_susp_tld,       # has_suspicious_tld
        max_url_len,        # max_url_length
        has_mismatch,       # has_url_mismatch
        subject_kw,         # subject_keyword_hits
        body_kw,            # body_keyword_hits
        total_kw,           # total_keyword_hits
        has_urgency,        # has_urgency_words
        sender_is_free,     # sender_is_free_email
        domain_match,       # sender_receiver_domain_match
        body_len,           # body_length
        subject_len,        # subject_length
        excl_count,         # body_exclamation_count
        quest_count,        # body_question_count
        has_html,           # has_html_tags
        sending_hour,       # sending_hour
        sending_dayofweek,  # sending_dayofweek
    ]

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data     = request.get_json()
    subject  = data.get('subject', '')
    body     = data.get('body', '')
    sender   = data.get('sender', '')
    receiver = data.get('receiver', '')

    # 1. Clean text
    subject_clean = clean_text(subject)
    body_clean    = clean_text(body)

    # 2. TF-IDF vectorization
    X_subj = tfidf_subject.transform([subject_clean])
    X_body = tfidf_body.transform([body_clean])

    # 3. Numeric features → scale → sparse
    num_feats = extract_numeric_features(subject, body, sender, receiver)
    X_num = sp.csr_matrix(scaler.transform([num_feats]))

    # 4. Combine and predict
    X_combined  = sp.hstack([X_subj, X_body, X_num], format='csr')
    proba       = model.predict_proba(X_combined)[0]
    confidence  = float(proba[1]) * 100

    # Base prediction with threshold 0.80
    prediction  = 1 if proba[1] > 0.80 else 0

    # === POST-PROCESSING: Domain-based adjustments ===
    sender_domain = extract_domain(sender)
    
    # Check for spoofed/impersonated domains
    is_spoofed = any(pattern in sender_domain.lower() for pattern in SPOOFED_PATTERNS)
    if is_spoofed and proba[1] > 0.50:  # If looks like phishing AND confidence > 50%
        prediction = 1  # Mark as phishing
    
    # If sender is from a highly trusted domain, don't mark as phishing unless very confident (>0.95)
    if prediction == 1 and sender_domain in TRUSTED_DOMAINS:
        if proba[1] < 0.95:
            prediction = 0  # Override: trusted domain, low confidence → legitimate

    return jsonify({
        'label': 'Phishing' if prediction == 1 else 'Legitimate',
        'confidence': round(confidence, 1),
        'phishing_prob': round(confidence, 1)
    })

if __name__ == '__main__':
    app.run(debug=False)