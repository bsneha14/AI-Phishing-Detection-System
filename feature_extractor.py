# feature_extractor.py

import re
from urllib.parse import urlparse
import pandas as pd
df = pd.read_csv('phishing_dataset.csv')
print(df.columns.tolist())
from train_model import extract_features
print(len(extract_features("https://google.com")))

def extract_features(url):
    parsed    = urlparse(url)
    hostname  = parsed.hostname or ""
    path      = parsed.path or ""

    # 1. Having IP Address
    having_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else -1

    # 2. URL Length
    url_len = len(url)
    if url_len < 54:
        url_length = -1
    elif url_len <= 75:
        url_length = 0
    else:
        url_length = 1

    # 3. Shortening Service
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co', 'is.gd']
    short_service = 1 if any(s in url for s in shorteners) else -1

    # 4. Having @ Symbol
    at_symbol = 1 if '@' in url else -1

    # 5. Double Slash Redirecting
    double_slash = 1 if url.rfind('//') > 7 else -1

    # 6. Prefix or Suffix
    prefix_suffix = 1 if '-' in hostname else -1

    # 7. Having Sub Domain
    dots = hostname.count('.')
    if dots == 1:
        sub_domain = -1
    elif dots == 2:
        sub_domain = 0
    else:
        sub_domain = 1

    # 8. SSL Final State
    ssl_state = -1 if parsed.scheme == 'https' else 1

    # 9. Domain Registration Length
    domain_reg = 0

    # 10. Favicon
    favicon = -1

    # 11. Port
    port = parsed.port
    port_feature = 1 if port and port not in [80, 443] else -1

    # 12. HTTPS Token in Domain
    https_token = 1 if 'https' in hostname.lower() else -1

    # 13. Request URL
    request_url = -1

    # 14. URL of Anchor
    url_anchor = -1

    # 15. Links in Tags
    links_tags = -1

    # 16. SFH
    sfh = -1

    # 17. Submitting to Email
    submit_email = 1 if 'mailto:' in url else -1

    # 18. Abnormal URL
    abnormal = -1 if hostname in url else 1

    # 19. Redirect
    redirect = 0 if url.count('//') <= 1 else 1

    # 20. On Mouseover
    mouseover = -1

    # 21. Right Click
    right_click = -1

    # 22. Popup Window
    popup = -1

    # 23. Iframe
    iframe = -1

    # 24. Age of Domain
    age_domain = -1

    # 25. DNS Record
    dns_record = -1

    # 26. Web Traffic
    web_traffic = 0

    # 27. Page Rank
    page_rank = -1

    # 28. Google Index
    bad_tld = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    google_index = 1 if any(t in hostname for t in bad_tld) else -1

    # 29. Links Pointing to Page
    links_pointing = 0

    # 30. Statistical Report
    bad_keywords = [
        'secure', 'account', 'update', 'login', 'verify',
        'banking', 'confirm', 'paypal', 'signin', 'password',
        'credential', 'ebay', 'amazon', 'apple', 'microsoft'
    ]
    stat_report = 1 if any(k in url.lower() for k in bad_keywords) else -1

    return [
        having_ip, url_length, short_service, at_symbol,
        double_slash, prefix_suffix, sub_domain, ssl_state,
        domain_reg, favicon, port_feature, https_token,
        request_url, url_anchor, links_tags, sfh,
        submit_email, abnormal, redirect, mouseover,
        right_click, popup, iframe, age_domain,
        dns_record, web_traffic, page_rank, google_index,
        links_pointing, stat_report
    ]