import ipaddress
from urllib.parse import urlparse


FEATURE_NAMES = [
    "url_length",
    "valid_url",
    "at_symbol",
    "sensitive_words_count",
    "path_length",
    "isHttps",
    "nb_dots",
    "nb_hyphens",
    "nb_and",
    "nb_or",
    "nb_www",
    "nb_com",
    "nb_underscore",
    "domain_length",
    "query_length",
    "digit_count",
    "has_ip_address",
    "suspicious_tld",
    "subdomain_count",
    "has_port",
    "double_slash_in_path",
    "percent_encoded_count",
]

SENSITIVE_WORDS = [
    "account",
    "auth",
    "bank",
    "billing",
    "bonus",
    "confirm",
    "free",
    "login",
    "password",
    "paypal",
    "prize",
    "secure",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
]

SUSPICIOUS_TLDS = {
    "bid",
    "click",
    "country",
    "download",
    "fake",
    "gq",
    "link",
    "loan",
    "party",
    "review",
    "stream",
    "tk",
    "top",
    "work",
    "xyz",
}


def normalize_url(url):
    return url.strip()


def parsed_url(url):
    value = normalize_url(url)
    return urlparse(value if "://" in value else f"https://{value}")


def extract_domain(url):
    parsed = parsed_url(url)
    return parsed.netloc.lower().split(":")[0]


def has_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return 1
    except ValueError:
        return 0


def count_subdomains(domain):
    parts = [part for part in domain.split(".") if part]
    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def extract_features(url):
    value = normalize_url(url)
    parsed = parsed_url(value)
    domain = extract_domain(value)
    path = parsed.path or ""
    query = parsed.query or ""
    lowered = value.lower()
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""

    return [
        len(value),
        1 if parsed.scheme in {"http", "https"} and bool(domain) else 0,
        value.count("@"),
        sum(1 for word in SENSITIVE_WORDS if word in lowered),
        len(path),
        1 if parsed.scheme == "https" else 0,
        value.count("."),
        value.count("-"),
        value.count("&"),
        value.count("|"),
        lowered.count("www"),
        lowered.count(".com"),
        value.count("_"),
        len(domain),
        len(query),
        sum(1 for char in value if char.isdigit()),
        has_ip_address(domain),
        1 if tld in SUSPICIOUS_TLDS else 0,
        count_subdomains(domain),
        1 if parsed.port else 0,
        1 if "//" in path else 0,
        value.count("%"),
    ]


def features_from_row(row):
    return [float(row.get(name, 0) or 0) for name in FEATURE_NAMES]
