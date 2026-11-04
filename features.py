import ipaddress
from urllib.parse import urlsplit, parse_qs


def extract_features(urls):
    result = []

    for url in urls:
        url = str(url).strip()

        if "://" not in url:
            url = "https://" + url

        p = urlsplit(url)
        host = p.hostname or ""
        path = p.path or ""

        try:
            ipaddress.ip_address(host)
            has_ip = 1
        except ValueError:
            has_ip = 0

        try:
            port = p.port or 0
        except ValueError:
            port = -1

        segments = [x for x in path.split("/") if x]
        query_params = parse_qs(p.query)

        features = {
            "url_length": len(url),
            "host_length": len(host),
            "path_length": len(path),
            "query_length": len(p.query),
            "fragment_length": len(p.fragment),

            "dots": host.count("."),
            "hyphens": host.count("-"),
            "digits_host": sum(c.isdigit() for c in host),
            "digits_url": sum(c.isdigit() for c in url),

            "subdomains": max(0, len(host.split(".")) - 2),
            "path_segments": len(segments),
            "query_params": len(query_params),

            "has_ip": has_ip,
            "has_https": int(p.scheme == "https"),
            "has_http": int(p.scheme == "http"),
            "has_at": int("@" in url),
            "has_port": int(port != 0),
            "has_punycode": int("xn--" in host),
            "has_percent_encoding": int("%" in url),
            "has_double_slash_path": int("//" in path),
            "has_fragment": int(bool(p.fragment)),

            "suspicious_words": sum(
                word in url.lower()
                for word in [
                    "login", "signin", "verify", "account",
                    "secure", "update", "password", "wallet"
                ]
            )
        }

        result.append(features)

    return result


def normalize_url(urls):
    if isinstance(urls, str):
        urls = [urls]
        single_url = True
    else:
        single_url = False

    result = []

    for url in urls:
        url = str(url).strip()

        if "://" not in url:
            url = "https://" + url

        p = urlsplit(url)
        host = (p.hostname or "").lower()

        if host.startswith("www."):
            host = host[4:]

        normalized = host + (p.path or "")

        if p.query:
            normalized += "?" + p.query

        result.append(normalized)

    return result[0] if single_url else result