"""
OSINT Aggregator Engine v7.0
Агресивний пошук по всіх джерелах паралельно.
Ланцюговий пошук: phone → name → email → social → IP → ...
"""
import asyncio, hashlib, json, logging, re, socket
from urllib.parse import quote_plus, urlparse
import aiohttp
import config

log = logging.getLogger("engine")

try:
    from curl_cffi.requests import AsyncSession as CF
    HAS_CURL = True
except ImportError:
    HAS_CURL = False

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as tz_ph
    HAS_PN = True
except ImportError:
    HAS_PN = False

try:
    import asyncwhois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.asyncresolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ═══════════════════════════════════════════
#  HTTP CORE
# ═══════════════════════════════════════════
async def _http(method: str, url: str, *, headers=None, params=None,
                data=None, jdata=None, rapid_key=None,
                timeout=None, retries=2) -> tuple[int, any]:
    t = timeout or config.TIMEOUT_MED
    h = config.get_headers(headers)
    if rapid_key:
        m = re.search(r"https?://([^/]+)", url)
        if m:
            h["X-RapidAPI-Key"]  = rapid_key
            h["X-RapidAPI-Host"] = m.group(1)

    for attempt in range(retries):
        # Спробуємо curl_cffi (обхід Cloudflare/TLS)
        if HAS_CURL and method == "GET":
            try:
                async with CF(impersonate="chrome120", timeout=t) as s:
                    r = await asyncio.wait_for(
                        s.get(url, headers=h, params=params, allow_redirects=True),
                        timeout=t + 3
                    )
                    ct = r.headers.get("content-type", "")
                    body = r.json() if "json" in ct else r.text
                    return r.status_code, body
            except asyncio.TimeoutError:
                return 0, None
            except Exception as e:
                log.debug(f"curl #{attempt} {url}: {e}")

        # aiohttp fallback
        try:
            px = config.PROXY or None
            conn = aiohttp.TCPConnector(ssl=False, limit=200, ttl_dns_cache=300)
            to   = aiohttp.ClientTimeout(total=t, connect=5, sock_read=t)
            async with aiohttp.ClientSession(connector=conn, timeout=to) as s:
                kw = dict(headers=h, params=params, proxy=px, allow_redirects=True, ssl=False)
                if method == "POST":
                    kw["data"] = data
                    kw["json"] = jdata
                async with getattr(s, method.lower())(url, **kw) as r:
                    ct = r.headers.get("content-type", "")
                    if "json" in ct:
                        body = await r.json(content_type=None)
                    else:
                        body = await r.text(errors="ignore")
                    return r.status, body
        except asyncio.TimeoutError:
            return 0, None
        except Exception as e:
            log.debug(f"aio #{attempt} {url}: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(1)

    return 0, None


async def GET(url, **kw):  return await _http("GET",  url, **kw)
async def POST(url, **kw): return await _http("POST", url, **kw)


def safe(coro):
    """Обгортка — якщо впаде, повертає None."""
    async def _inner():
        try:
            return await coro
        except Exception as e:
            log.debug(f"safe: {e}")
            return None
    return _inner()


# ═══════════════════════════════════════════
#  IP SCAN
# ═══════════════════════════════════════════
async def scan_ip(ip: str, rapid_key: str = "") -> dict:
    out = {}

    async def _ipinfo():
        s, d = await GET(f"https://ipinfo.io/{ip}/json", timeout=8)
        if s == 200 and isinstance(d, dict):
            out["ipinfo"] = {
                "ip": d.get("ip"), "hostname": d.get("hostname"),
                "city": d.get("city"), "region": d.get("region"),
                "country": d.get("country"), "loc": d.get("loc"),
                "org": d.get("org"), "timezone": d.get("timezone"),
                "bogon": d.get("bogon", False),
            }

    async def _ipapi():
        s, d = await GET(f"http://ip-api.com/json/{ip}", timeout=8,
            params={"fields": "status,country,countryCode,regionName,city,lat,lon,isp,org,as,reverse,mobile,proxy,hosting,query"})
        if s == 200 and isinstance(d, dict) and d.get("status") == "success":
            out["ipapi"] = d

    async def _bgp():
        s, d = await GET(f"https://api.bgpview.io/ip/{ip}", timeout=10)
        if s == 200 and isinstance(d, dict):
            dt = d.get("data", {})
            asns = []
            for px in dt.get("prefixes", [])[:5]:
                for a in px.get("asns", []):
                    asns.append({
                        "asn":     a.get("asn"),
                        "name":    a.get("name", ""),
                        "country": a.get("country_code", ""),
                        "prefix":  px.get("prefix", ""),
                    })
            out["bgp"] = {
                "ptr":  dt.get("ptr_record", ""),
                "asns": asns,
                "rir":  dt.get("rir_allocation", {}).get("rir_name", ""),
                "date": dt.get("rir_allocation", {}).get("date_allocated", ""),
            }

    async def _otx():
        s, d = await GET(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", timeout=10)
        if s == 200 and isinstance(d, dict):
            pulses = d.get("pulse_info", {}).get("pulses", [])
            out["otx"] = {
                "pulses":    d.get("pulse_info", {}).get("count", 0),
                "reputation": d.get("reputation", 0),
                "country":   d.get("country_name", ""),
                "tags":      [p.get("name", "") for p in pulses[:8] if p.get("name")],
                "malware":   [p.get("malware_families", []) for p in pulses[:3]],
            }

    async def _gn():
        s, d = await GET(f"https://api.greynoise.io/v3/community/{ip}",
                         headers={"key": "community"}, timeout=8)
        if s == 200 and isinstance(d, dict):
            out["greynoise"] = {
                "noise":          d.get("noise", False),
                "riot":           d.get("riot", False),
                "classification": d.get("classification", ""),
                "name":           d.get("name", ""),
                "link":           d.get("link", ""),
            }

    async def _abuse():
        s, d = await GET("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": "free", "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=8)
        if s == 200 and isinstance(d, dict):
            da = d.get("data", {})
            out["abuseipdb"] = {
                "score":   da.get("abuseConfidenceScore", 0),
                "reports": da.get("totalReports", 0),
                "isp":     da.get("isp", ""),
                "usage":   da.get("usageType", ""),
                "is_tor":  da.get("isTor", False),
                "domain":  da.get("domain", ""),
            }

    async def _ipqs():
        s, d = await GET(f"https://ipqualityscore.com/api/json/ip/free/{ip}", timeout=8)
        if s == 200 and isinstance(d, dict) and d.get("success") is not False:
            out["ipqs"] = {
                "fraud":  d.get("fraud_score", 0),
                "vpn":    d.get("vpn", False),
                "tor":    d.get("tor", False),
                "proxy":  d.get("proxy", False),
                "bot":    d.get("bot_status", False),
                "isp":    d.get("ISP", ""),
                "org":    d.get("organization", ""),
            }

    async def _shodan_free():
        # Shodan InternetDB (безкоштовно, без ключа)
        s, d = await GET(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if s == 200 and isinstance(d, dict):
            out["shodan"] = {
                "ports":   d.get("ports", []),
                "hostnames": d.get("hostnames", []),
                "cpes":    d.get("cpes", []),
                "vulns":   d.get("vulns", [])[:10],
                "tags":    d.get("tags", []),
            }

    async def _virustotal():
        s, d = await GET(f"https://www.virustotal.com/vtapi/v2/ip-address/report",
                         params={"apikey": "free", "ip": ip}, timeout=10)
        if s == 200 and isinstance(d, dict):
            detected = d.get("detected_urls", [])
            out["virustotal"] = {
                "detected_urls": len(detected),
                "country":       d.get("country", ""),
                "asn":           d.get("asn", ""),
                "as_owner":      d.get("as_owner", ""),
                "samples":       [u.get("url", "")[:60] for u in detected[:5]],
            }

    async def _rapid_ip():
        if not rapid_key: return
        s, d = await GET(
            "https://ip-reputation-geoip-fraud-score.p.rapidapi.com/",
            params={"ip": ip}, rapid_key=rapid_key, timeout=8
        )
        if s == 200 and isinstance(d, dict):
            out["rapid"] = {
                "fraud": d.get("fraud_score", 0),
                "vpn":   d.get("vpn", False),
                "tor":   d.get("tor", False),
                "bot":   d.get("bot_status", False),
                "isp":   d.get("ISP", ""),
            }

    async def _rdns():
        try:
            loop = asyncio.get_event_loop()
            host = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            out["rdns"] = host[0]
        except Exception:
            pass

    await asyncio.gather(
        _ipinfo(), _ipapi(), _bgp(), _otx(), _gn(),
        _abuse(), _ipqs(), _shodan_free(), _virustotal(), _rapid_ip(), _rdns(),
        return_exceptions=True
    )
    return out


# ═══════════════════════════════════════════
#  DOMAIN SCAN
# ═══════════════════════════════════════════
async def scan_domain(domain: str, rapid_key: str = "") -> dict:
    out = {}

    async def _whois():
        if not HAS_WHOIS: return
        try:
            res = await asyncio.wait_for(asyncwhois.aio_whois_domain(domain), timeout=15)
            p = res.parser_output or {}
            out["whois"] = {
                "registrar":    p.get("registrar", ""),
                "created":      str(p.get("created", ""))[:10],
                "expires":      str(p.get("expires", ""))[:10],
                "updated":      str(p.get("updated", ""))[:10],
                "nameservers":  [str(n) for n in (p.get("name_servers") or [])[:6]],
                "status":       (p.get("status") or [])[:3],
                "emails":       (p.get("emails") or [])[:3],
                "registrant":   p.get("registrant_name", "") or p.get("registrant", ""),
                "org":          p.get("registrant_organization", ""),
                "country":      p.get("registrant_country", ""),
            }
        except Exception as e:
            out["whois"] = {"error": str(e)[:80]}

    async def _dns_all():
        recs = {}
        tasks = []
        rtypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]
        for t in rtypes:
            tasks.append(GET(f"https://dns.google/resolve?name={domain}&type={t}", timeout=6))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for rtype, res in zip(rtypes, results):
            if isinstance(res, tuple) and res[0] == 200 and isinstance(res[1], dict):
                ans = [a.get("data", "") for a in res[1].get("Answer", [])]
                if ans:
                    recs[rtype] = ans[:5]
        out["dns"] = recs

    async def _crt():
        s, d = await GET(f"https://crt.sh/?q=%.{domain}&output=json", timeout=25)
        if s == 200 and isinstance(d, list):
            subs, issuers = set(), set()
            for c in d[:500]:
                for n in c.get("name_value", "").split("\n"):
                    n = n.strip().lstrip("*.")
                    if domain in n and n != domain:
                        subs.add(n)
                m = re.search(r"CN=([^,]+)", c.get("issuer_name", ""))
                if m: issuers.add(m.group(1))
            out["crt"] = {
                "total_certs": len(d),
                "subs":        sorted(subs)[:60],
                "issuers":     list(issuers)[:8],
            }

    async def _ht():
        s, txt = await GET(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=12)
        if s == 200 and isinstance(txt, str) and "error" not in txt.lower():
            lines = [l.split(",") for l in txt.strip().split("\n") if "," in l]
            if lines:
                out["hackertarget"] = [{"host": l[0], "ip": l[1]} for l in lines[:50]]

    async def _urlscan():
        s, d = await GET(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10", timeout=12)
        if s == 200 and isinstance(d, dict):
            results = d.get("results", [])
            out["urlscan"] = {
                "total": d.get("total", 0),
                "scans": [
                    {
                        "ip":      r.get("page", {}).get("ip", ""),
                        "country": r.get("page", {}).get("country", ""),
                        "server":  r.get("page", {}).get("server", ""),
                        "asn":     r.get("page", {}).get("asn", ""),
                        "url":     r.get("page", {}).get("url", ""),
                        "score":   r.get("verdicts", {}).get("overall", {}).get("score", 0),
                    }
                    for r in results[:8]
                ],
            }

    async def _wayback():
        s, d = await GET(f"https://archive.org/wayback/available?url={domain}", timeout=8)
        if s == 200 and isinstance(d, dict):
            snap = d.get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                ts = snap.get("timestamp", "")
                out["wayback"] = {
                    "url":  snap.get("url", ""),
                    "date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts,
                }

    async def _securitytrails():
        s, d = await GET(
            f"https://api.securitytrails.com/v1/domain/{domain}",
            headers={"apikey": "free"}, timeout=10
        )
        if s == 200 and isinstance(d, dict):
            out["securitytrails"] = {
                "apex_domain": d.get("apex_domain", ""),
                "alexa_rank":  d.get("alexa_rank"),
                "whois":       d.get("whois", {}),
            }

    async def _robots_sitemap():
        tasks = [
            GET(f"https://{domain}/robots.txt", timeout=6),
            GET(f"https://{domain}/sitemap.xml", timeout=6),
            GET(f"https://{domain}/.well-known/security.txt", timeout=6),
        ]
        res = await asyncio.gather(*tasks, return_exceptions=True)
        extras = {}
        labels = ["robots", "sitemap", "security_txt"]
        for lbl, r in zip(labels, res):
            if isinstance(r, tuple) and r[0] == 200 and isinstance(r[1], str):
                extras[lbl] = r[1][:500]
        if extras:
            out["extras"] = extras

    async def _headers():
        s, _ = await GET(f"https://{domain}", timeout=8,
                         headers={"Accept": "text/html"})
        # headers aren't easily available from GET response here
        # but we can check if site is alive
        out["alive"] = s == 200

    async def _shodan_domain():
        s, d = await GET(f"https://api.shodan.io/dns/domain/{domain}?key=free", timeout=10)
        if s == 200 and isinstance(d, dict):
            out["shodan_dns"] = {
                "subdomains": (d.get("subdomains") or [])[:20],
                "data":       (d.get("data") or [])[:5],
            }

    await asyncio.gather(
        _whois(), _dns_all(), _crt(), _ht(), _urlscan(),
        _wayback(), _robots_sitemap(), _shodan_domain(),
        return_exceptions=True
    )
    return out


# ═══════════════════════════════════════════
#  EMAIL SCAN
# ═══════════════════════════════════════════
async def scan_email(email: str, rapid_key: str = "") -> dict:
    out = {}

    async def _emailrep():
        s, d = await GET(f"https://emailrep.io/{email}",
                         headers={"User-Agent": "osint-aggregator"}, timeout=8)
        if s == 200 and isinstance(d, dict):
            dt = d.get("details", {})
            out["emailrep"] = {
                "reputation":  d.get("reputation", ""),
                "suspicious":  d.get("suspicious", False),
                "refs":        d.get("references", 0),
                "breached":    dt.get("data_breach", False),
                "leaked":      dt.get("credentials_leaked", False),
                "disposable":  dt.get("disposable", False),
                "spam":        dt.get("spam", False),
                "profiles":    dt.get("profiles", []),
                "first_seen":  dt.get("first_seen", ""),
                "last_seen":   dt.get("last_seen", ""),
                "domain_exists": dt.get("domain_exists", True),
                "deliverable": dt.get("deliverable", True),
            }

    async def _gravatar():
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        s, d = await GET(f"https://www.gravatar.com/{h}.json", timeout=8)
        if s == 200 and isinstance(d, dict):
            e = d.get("entry", [{}])[0]
            out["gravatar"] = {
                "found":    True,
                "name":     e.get("displayName", ""),
                "url":      e.get("profileUrl", ""),
                "location": e.get("currentLocation", ""),
                "bio":      e.get("aboutMe", "")[:100],
                "avatar":   f"https://www.gravatar.com/avatar/{h}?s=200",
                "accounts": [a.get("shortname") for a in e.get("accounts", []) if a.get("shortname")],
                "emails":   [em.get("value") for em in e.get("emails", []) if em.get("value")],
            }
        else:
            out["gravatar"] = {"found": False}

    async def _breach():
        s, d = await GET("https://breachdirectory.org/api",
                         params={"func": "auto", "term": email},
                         headers={"Referer": "https://breachdirectory.org/"}, timeout=10)
        if s == 200 and isinstance(d, dict):
            out["breach_dir"] = {
                "found": d.get("found", False),
                "count": d.get("result", {}).get("count", 0) if d.get("found") else 0,
                "samples": (d.get("result", {}).get("sources") or [])[:5] if d.get("found") else [],
            }

    async def _disposable():
        dom = email.split("@")[-1]
        s, d = await GET(f"https://open.kickbox.com/v1/disposable/{dom}", timeout=6)
        if s == 200 and isinstance(d, dict):
            out["disposable"] = d.get("disposable", False)

    async def _hunter():
        dom = email.split("@")[-1]
        s, d = await GET(f"https://api.hunter.io/v2/email-verifier?email={email}&api_key=free", timeout=8)
        if s == 200 and isinstance(d, dict):
            da = d.get("data", {})
            out["hunter"] = {
                "result":        da.get("result", ""),
                "score":         da.get("score", 0),
                "disposable":    da.get("disposable", False),
                "mx_records":    da.get("mx_records", False),
                "smtp_server":   da.get("smtp_server", False),
                "smtp_check":    da.get("smtp_check", False),
            }

    async def _tw():
        s, d = await GET("https://api.twitter.com/i/users/email_available.json",
                         params={"email": email}, timeout=6)
        if s == 200 and isinstance(d, dict):
            out["twitter_reg"] = not d.get("valid", True)

    async def _gh():
        s, txt = await POST("https://github.com/password_reset",
                            data={"email": email},
                            headers={"Referer": "https://github.com/password_reset"}, timeout=8)
        if isinstance(txt, str):
            out["github_reg"] = "we found" in txt.lower()

    async def _hashes():
        # Перевірка по хешу (анонімна HIBP-style)
        h = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix = h[:5]
        s, txt = await GET(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
        # Це для перевірки пароля, але для email використовуємо інший ендпоінт

    async def _rapid_email():
        if not rapid_key: return
        s, d = await GET("https://email-reputation.p.rapidapi.com/",
                         params={"email": email}, rapid_key=rapid_key, timeout=8)
        if s == 200 and isinstance(d, dict):
            out["rapid"] = {
                "valid":      d.get("valid"),
                "disposable": d.get("disposable"),
                "risky":      d.get("risky"),
                "score":      d.get("score"),
                "domain":     d.get("domain", ""),
            }

    await asyncio.gather(
        _emailrep(), _gravatar(), _breach(), _disposable(),
        _hunter(), _tw(), _gh(), _rapid_email(),
        return_exceptions=True
    )
    return out


# ═══════════════════════════════════════════
#  PHONE SCAN
# ═══════════════════════════════════════════
async def scan_phone(phone: str, rapid_key: str = "") -> dict:
    out = {}
    clean = re.sub(r"[^\d+]", "", phone)
    num   = clean.lstrip("+")

    # Google phonenumbers
    if HAS_PN:
        try:
            p = phonenumbers.parse(clean, None)
            TYPE_MAP = {
                0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_OR_MOBILE",
                3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST",
                6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER",
                9: "UAN", 10: "VOICEMAIL", 27: "UNKNOWN"
            }
            ntype = int(phonenumbers.number_type(p))
            region = phonenumbers.region_code_for_number(p)
            out["pn"] = {
                "valid":    phonenumbers.is_valid_number(p),
                "possible": phonenumbers.is_possible_number(p),
                "intl":     phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "national": phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL),
                "e164":     phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164),
                "country":  geocoder.description_for_number(p, "uk"),
                "country_en": geocoder.description_for_number(p, "en"),
                "carrier":  carrier.name_for_number(p, "uk"),
                "carrier_en": carrier.name_for_number(p, "en"),
                "tz":       list(tz_ph.time_zones_for_number(p)),
                "type":     TYPE_MAP.get(ntype, str(ntype)),
                "cc":       p.country_code,
                "region":   region or "",
            }
        except Exception as e:
            out["pn_err"] = str(e)[:60]

    async def _fragment():
        s, txt = await GET(f"https://fragment.com/number/{num}", timeout=10)
        if s == 200 and isinstance(txt, str) and len(txt) > 200:
            avail = "available for purchase" in txt.lower()
            sold  = "sold" in txt.lower()
            nfnd  = "not found" in txt.lower() or len(txt) < 400
            pm    = re.search(r'(\d+(?:[.,]\d+)?)\s*TON', txt)
            price = pm.group(1) if pm else ""
            # Ім'я з Fragment
            nm = re.search(r'<div class="tm-section-header-name">([^<]+)', txt)
            out["fragment"] = {
                "registered": not avail and not nfnd,
                "price_ton":  price,
                "name":       nm.group(1).strip() if nm else "",
                "url":        f"https://fragment.com/number/{num}",
            }
        else:
            out["fragment"] = {"registered": None}

    async def _truecaller():
        if not rapid_key: return
        cc = "UA"
        if clean.startswith("+7"):  cc = "RU"
        elif clean.startswith("+1"): cc = "US"
        elif clean.startswith("+44"): cc = "GB"
        s, d = await GET(
            "https://truecaller4.p.rapidapi.com/api/v1/getDetails",
            params={"phone": clean, "countryCode": cc},
            rapid_key=rapid_key, timeout=10
        )
        if s == 200 and isinstance(d, dict) and d.get("data"):
            dd = d["data"]
            phones = (dd.get("phones") or [{}])
            out["truecaller"] = {
                "name":    dd.get("name", ""),
                "carrier": (phones[0] if phones else {}).get("carrier", ""),
                "type":    (phones[0] if phones else {}).get("numberType", ""),
                "score":   dd.get("spamScore", 0),
                "tags":    (dd.get("tags") or [])[:3],
                "emails":  (dd.get("internetAddresses") or [])[:3],
            }

    async def _phval():
        if not rapid_key: return
        s, d = await GET(
            "https://phone-number-validator-and-lookup.p.rapidapi.com/lookup",
            params={"phone": clean}, rapid_key=rapid_key, timeout=8
        )
        if s == 200 and isinstance(d, dict):
            out["phval"] = {
                "valid":    d.get("valid"),
                "country":  d.get("country", ""),
                "location": d.get("location", ""),
                "carrier":  d.get("carrier", ""),
                "line":     d.get("line_type", ""),
            }

    async def _influeencer_phone(inf_key: str):
        if not inf_key: return
        s, d = await GET(
            "https://influeencer.p.rapidapi.com/phone",
            params={"phone": clean},
            rapid_key=inf_key, timeout=10
        )
        if s == 200 and isinstance(d, dict):
            out["influeencer_phone"] = d

    # Перевірка в різних сервісах (відкриті)
    async def _numverify():
        s, d = await GET(
            f"https://apilayer.net/api/validate?number={clean}&access_key=free", timeout=8
        )
        if s == 200 and isinstance(d, dict) and d.get("valid"):
            out["numverify"] = {
                "country":   d.get("country_name", ""),
                "location":  d.get("location", ""),
                "carrier":   d.get("carrier", ""),
                "line_type": d.get("line_type", ""),
            }

    async def _hlr_lookup():
        # HLR free lookup
        s, txt = await GET(f"https://www.hlrlookup.com/index.php?phone={num}", timeout=8)
        if s == 200 and isinstance(txt, str) and "Network" in txt:
            net = re.search(r"Network[:\s]+([^\n<]+)", txt)
            if net:
                out["hlr"] = {"network": net.group(1).strip()[:60]}

    async def _getcontact():
        # GetContact web check
        s, txt = await GET(f"https://getcontact.com/en/phone/{num}", timeout=8)
        if s == 200 and isinstance(txt, str):
            tags = re.findall(r'"tag":"([^"]+)"', txt)
            names = re.findall(r'"name":"([^"]+)"', txt)
            if tags or names:
                out["getcontact"] = {"tags": list(set(tags))[:5], "names": list(set(names))[:5]}

    out["links"] = {
        "whatsapp": f"https://wa.me/{num}",
        "telegram": f"https://t.me/+{num}",
        "viber":    f"viber://contact?number={clean}",
        "signal":   f"https://signal.me/#p/{clean}",
    }

    rk = rapid_key
    await asyncio.gather(
        _fragment(), _truecaller(), _phval(),
        _numverify(), _hlr_lookup(), _getcontact(),
        return_exceptions=True
    )
    return out


# ═══════════════════════════════════════════
#  USERNAME / SOCIAL SCAN
# ═══════════════════════════════════════════
PLATFORMS = [
    # (name, url_tmpl, not_found_str, is_json_api)
    ("GitHub",      "https://api.github.com/users/{}",           None,                        True),
    ("GitLab",      "https://gitlab.com/api/v4/users?username={}", None,                       True),
    ("Reddit",      "https://www.reddit.com/user/{}/about.json",  None,                        True),
    ("Mastodon",    "https://mastodon.social/api/v1/accounts/lookup?acct={}", None,             True),
    ("Telegram",    "https://t.me/{}",                            "if you have telegram",      False),
    ("Twitter/X",   "https://x.com/{}",                           "this account doesnt exist", False),
    ("Instagram",   "https://www.instagram.com/{}/",              "sorry, this page",          False),
    ("TikTok",      "https://www.tiktok.com/@{}",                 "couldnt find this account", False),
    ("YouTube",     "https://www.youtube.com/@{}",                "this page isnt available",  False),
    ("Twitch",      "https://www.twitch.tv/{}",                    "sorry. unless",             False),
    ("Steam",       "https://steamcommunity.com/id/{}",            "the specified profile",     False),
    ("VK",          "https://vk.com/{}",                           None,                        False),
    ("Facebook",    "https://www.facebook.com/{}",                 "this page isnt available",  False),
    ("LinkedIn",    "https://www.linkedin.com/in/{}/",             "page not found",            False),
    ("Pinterest",   "https://www.pinterest.com/{}/",               None,                        False),
    ("Snapchat",    "https://www.snapchat.com/add/{}",             "sorry",                     False),
    ("Medium",      "https://medium.com/@{}",                      "page not found",            False),
    ("Dev.to",      "https://dev.to/{}",                           "page not found",            False),
    ("Habr",        "https://habr.com/en/users/{}/",               "user not found",            False),
    ("HackerNews",  "https://news.ycombinator.com/user?id={}",     "no such user",              False),
    ("Keybase",     "https://keybase.io/{}",                       "not a keybase user",        False),
    ("SoundCloud",  "https://soundcloud.com/{}",                   None,                        False),
    ("Spotify",     "https://open.spotify.com/user/{}",            None,                        False),
    ("Last.fm",     "https://www.last.fm/user/{}",                 "user not found",            False),
    ("Flickr",      "https://www.flickr.com/people/{}",            None,                        False),
    ("500px",       "https://500px.com/p/{}",                      "not found",                 False),
    ("Behance",     "https://www.behance.net/{}",                  None,                        False),
    ("Dribbble",    "https://dribbble.com/{}",                     None,                        False),
    ("DeviantArt",  "https://www.deviantart.com/{}",               None,                        False),
    ("ArtStation",  "https://www.artstation.com/{}",               None,                        False),
    ("Linktree",    "https://linktr.ee/{}",                        None,                        False),
    ("Ko-fi",       "https://ko-fi.com/{}",                        None,                        False),
    ("Patreon",     "https://www.patreon.com/{}",                  None,                        False),
    ("Substack",    "https://{}.substack.com",                     "not found",                 False),
    ("Tumblr",      "https://{}.tumblr.com",                       "theres nothing here",       False),
    ("Pastebin",    "https://pastebin.com/u/{}",                   None,                        False),
    ("Fiverr",      "https://www.fiverr.com/{}",                   None,                        False),
    ("Etsy",        "https://www.etsy.com/shop/{}",                None,                        False),
    ("itch.io",     "https://{}.itch.io",                          None,                        False),
    ("Chess.com",   "https://www.chess.com/member/{}",             "oops",                      False),
    ("Lichess",     "https://lichess.org/api/user/{}",             None,                        True),
    ("osu!",        "https://osu.ppy.sh/users/{}",                 "the user you're looking for was not found", False),
    ("Letterboxd",  "https://letterboxd.com/{}",                   None,                        False),
    ("AniList",     "https://anilist.co/user/{}",                  None,                        False),
    ("Goodreads",   "https://www.goodreads.com/{}",                None,                        False),
    ("Kaggle",      "https://www.kaggle.com/{}",                   None,                        False),
    ("HackerOne",   "https://hackerone.com/{}",                    None,                        False),
    ("Bugcrowd",    "https://bugcrowd.com/{}",                     None,                        False),
    ("npm",         "https://www.npmjs.com/~{}",                   None,                        False),
    ("PyPI",        "https://pypi.org/user/{}/",                   None,                        False),
    ("DockerHub",   "https://hub.docker.com/u/{}",                 None,                        False),
    ("Replit",      "https://replit.com/@{}",                      None,                        False),
    ("Codepen",     "https://codepen.io/{}",                       None,                        False),
    ("LeetCode",    "https://leetcode.com/{}",                     None,                        False),
    ("Speedrun",    "https://www.speedrun.com/user/{}",            None,                        False),
    ("Roblox",      "https://www.roblox.com/user.aspx?username={}", None,                       False),
    ("Producthunt", "https://www.producthunt.com/@{}",             None,                        False),
    ("About.me",    "https://about.me/{}",                         None,                        False),
    ("Gravatar",    "https://en.gravatar.com/{}",                  None,                        False),
    ("Twitch",      "https://www.twitch.tv/{}",                    None,                        False),
    ("Trakt",       "https://trakt.tv/users/{}",                   None,                        False),
]


async def _check_platform(name: str, url_tmpl: str, not_found: str | None,
                           is_api: bool, username: str) -> dict:
    url   = url_tmpl.replace("{}", username)
    extra = {}
    try:
        s, body = await GET(url, timeout=10)

        if s == 0 or s == 404:
            return {"found": False, "url": url}
        if s != 200:
            return {"found": False, "url": url}

        body_str = body if isinstance(body, str) else json.dumps(body)
        body_low = body_str.lower()

        if not_found and not_found.lower() in body_low:
            return {"found": False, "url": url}

        # Витягуємо дані
        if name == "GitHub" and isinstance(body, dict):
            if body.get("message") == "Not Found":
                return {"found": False, "url": url}
            extra = {
                "name":      body.get("name", ""),
                "bio":       body.get("bio", "")[:100],
                "location":  body.get("location", ""),
                "email":     body.get("email", ""),
                "company":   body.get("company", ""),
                "blog":      body.get("blog", ""),
                "followers": body.get("followers", 0),
                "following": body.get("following", 0),
                "repos":     body.get("public_repos", 0),
                "gists":     body.get("public_gists", 0),
                "twitter":   body.get("twitter_username", ""),
                "created":   (body.get("created_at") or "")[:10],
                "updated":   (body.get("updated_at") or "")[:10],
                "avatar":    body.get("avatar_url", ""),
                "url":       body.get("html_url", url),
            }
            url = body.get("html_url", url)

        elif name == "GitLab" and isinstance(body, list):
            if not body:
                return {"found": False, "url": url}
            u = body[0]
            extra = {
                "name":     u.get("name", ""),
                "bio":      u.get("bio", "")[:80],
                "location": u.get("location", ""),
                "created":  (u.get("created_at") or "")[:10],
                "avatar":   u.get("avatar_url", ""),
            }
            url = u.get("web_url", url)

        elif name == "Reddit" and isinstance(body, dict):
            if body.get("error"):
                return {"found": False, "url": url}
            data = body.get("data", {})
            extra = {
                "karma":     data.get("total_karma", 0),
                "post_k":    data.get("link_karma", 0),
                "comm_k":    data.get("comment_karma", 0),
                "is_mod":    data.get("is_mod", False),
                "created":   str(int(data.get("created_utc", 0)))[:10],
                "gold":      data.get("is_gold", False),
            }
            url = f"https://reddit.com/u/{username}"

        elif name == "Lichess" and isinstance(body, dict):
            if body.get("disabled"): return {"found": False, "url": url}
            extra = {
                "name":   body.get("username", ""),
                "rating": body.get("perfs", {}).get("bullet", {}).get("rating", 0),
                "online": body.get("online", False),
            }

        elif name == "Mastodon" and isinstance(body, dict):
            if body.get("error"): return {"found": False, "url": url}
            extra = {
                "name":      body.get("display_name", ""),
                "bio":       re.sub(r'<[^>]+>', '', body.get("note", ""))[:80],
                "followers": body.get("followers_count", 0),
                "following": body.get("following_count", 0),
                "posts":     body.get("statuses_count", 0),
                "created":   (body.get("created_at") or "")[:10],
            }
            url = body.get("url", url)

        elif name == "Telegram" and isinstance(body, str):
            title = re.search(r'<meta property="og:title" content="([^"]+)"', body)
            desc  = re.search(r'<meta property="og:description" content="([^"]+)"', body)
            subs  = re.search(r'(\d[\d\s,]+)\s*(members|subscribers|followers)', body, re.I)
            img   = re.search(r'<meta property="og:image" content="([^"]+)"', body)
            extra = {
                "title": title.group(1) if title else "",
                "desc":  desc.group(1)[:80] if desc else "",
                "subs":  subs.group(0)[:30] if subs else "",
                "photo": img.group(1) if img else "",
            }

        return {"found": True, "url": url, **extra}

    except Exception as e:
        log.debug(f"{name} check: {e}")
        return {"found": False, "url": url}


async def scan_social(username: str, inf_key: str = "") -> dict:
    tasks = [
        _check_platform(name, url_tmpl, nf, is_api, username)
        for name, url_tmpl, nf, is_api in PLATFORMS
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    out = {}
    for (name, _, _, _), res in zip(PLATFORMS, results):
        if isinstance(res, Exception):
            out[name] = {"found": False, "url": ""}
        else:
            out[name] = res

    # Додатково: influeencer API для соцмереж
    if inf_key:
        try:
            s, d = await GET(
                "https://influeencer.p.rapidapi.com/search",
                params={"username": username},
                rapid_key=inf_key, timeout=12
            )
            if s == 200 and isinstance(d, dict):
                out["influeencer"] = d
        except Exception:
            pass

    return out


# ═══════════════════════════════════════════
#  CHAIN SEARCH (ланцюговий пошук)
# ═══════════════════════════════════════════
async def chain_search(seed: str, seed_type: str,
                        rapid_key: str = "", inf_key: str = "") -> dict:
    """
    Запускає ланцюговий пошук:
    phone → name/carrier → social → email → ip
    email → gravatar/name → social → ip
    username → profiles → phone/email → ip
    """
    chain = {"seed": seed, "type": seed_type, "steps": [], "summary": {}}

    found_names    = set()
    found_emails   = set()
    found_phones   = set()
    found_usernames = set()
    found_ips      = set()
    found_domains  = set()

    async def step(label: str, coro):
        try:
            result = await asyncio.wait_for(coro, timeout=30)
            chain["steps"].append({"step": label, "data": result})
            return result
        except asyncio.TimeoutError:
            chain["steps"].append({"step": label, "error": "timeout"})
            return {}
        except Exception as e:
            chain["steps"].append({"step": label, "error": str(e)[:60]})
            return {}

    if seed_type == "phone":
        # КРОК 1: основний скан телефону
        phone_data = await step("phone_scan", scan_phone(seed, rapid_key))
        pn = phone_data.get("pn", {})
        tc = phone_data.get("truecaller", {})
        fr = phone_data.get("fragment", {})

        # Ім'я з Truecaller
        if tc.get("name"):
            found_names.add(tc["name"])
        # Ім'я з Fragment
        if fr.get("name"):
            found_names.add(fr["name"])

        # Emails з Truecaller
        for e in tc.get("emails", []):
            if isinstance(e, dict) and e.get("id"):
                found_emails.add(e["id"])
            elif isinstance(e, str):
                found_emails.add(e)

        # КРОК 2: якщо знайшли ім'я — шукаємо по імені
        for name in list(found_names)[:2]:
            username_guess = name.lower().replace(" ", "").replace(".", "")
            found_usernames.add(username_guess)
            username_guess2 = name.lower().split()[0] if " " in name else ""
            if username_guess2:
                found_usernames.add(username_guess2)

        # КРОК 3: соцмережі по username-guess
        for uname in list(found_usernames)[:2]:
            soc = await step(f"social_{uname}", scan_social(uname, inf_key))
            for platform, data in soc.items():
                if data.get("found") and data.get("email"):
                    found_emails.add(data["email"])

        # КРОК 4: email скан
        for email in list(found_emails)[:2]:
            em_data = await step(f"email_{email}", scan_email(email, rapid_key))
            gv = em_data.get("gravatar", {})
            if gv.get("found") and gv.get("name"):
                found_names.add(gv["name"])

    elif seed_type == "email":
        # КРОК 1: скан email
        em_data = await step("email_scan", scan_email(seed, rapid_key))
        gv  = em_data.get("gravatar", {})
        er  = em_data.get("emailrep", {})

        # Ім'я з Gravatar
        if gv.get("found") and gv.get("name"):
            found_names.add(gv["name"])
            # Акаунти з Gravatar
            for acc in gv.get("accounts", []):
                if acc:
                    found_usernames.add(acc)

        # Профілі з EmailRep
        for prof in er.get("profiles", []):
            if prof:
                found_usernames.add(prof)

        # КРОК 2: соцмережі
        username = seed.split("@")[0]
        found_usernames.add(username)
        soc = await step(f"social_{username}", scan_social(username, inf_key))

        # КРОК 3: по знайдених username
        for uname in list(found_usernames)[:2]:
            if uname != username:
                await step(f"social_{uname}", scan_social(uname, inf_key))

    elif seed_type == "username":
        # КРОК 1: соцмережі
        soc = await step("social_scan", scan_social(seed, inf_key))
        for platform, data in soc.items():
            if data.get("found"):
                if data.get("email"):
                    found_emails.add(data["email"])
                if data.get("name") and data["name"] != seed:
                    found_names.add(data["name"])

        # КРОК 2: email скан
        for email in list(found_emails)[:2]:
            await step(f"email_{email}", scan_email(email, rapid_key))

        # КРОК 3: GitHub → emails, blog, twitter
        gh = soc.get("GitHub", {})
        if gh.get("found"):
            if gh.get("email"):
                found_emails.add(gh["email"])
            if gh.get("twitter"):
                found_usernames.add(gh["twitter"])
            if gh.get("blog"):
                domain = urlparse(gh["blog"]).netloc
                if domain:
                    found_domains.add(domain)

    # Summary
    chain["summary"] = {
        "names":     list(found_names),
        "emails":    list(found_emails),
        "phones":    list(found_phones),
        "usernames": list(found_usernames),
        "ips":       list(found_ips),
        "domains":   list(found_domains),
    }
    return chain


# ═══════════════════════════════════════════
#  GOOGLE DORK — РЕАЛЬНИЙ ПОШУК РЕЗУЛЬТАТІВ
# ═══════════════════════════════════════════
async def dork_search(query: str, engine: str = "google", limit: int = 5) -> list[dict]:
    """
    Виконує реальний пошук через scraping і повертає результати,
    а не просто посилання.
    """
    results = []

    async def _google_scrape():
        url = f"https://www.google.com/search?q={quote_plus(query)}&num=10&hl=en"
        s, txt = await GET(url, headers={"Accept": "text/html"}, timeout=12)
        if s == 200 and isinstance(txt, str):
            # Парсимо результати
            items = re.findall(
                r'<div class="[^"]*">\s*<a href="(https?://[^"]+)"[^>]*>.*?'
                r'<h3[^>]*>([^<]+)</h3>.*?(?:<div[^>]*>([^<]{20,200})</div>)?',
                txt, re.DOTALL
            )
            for url_r, title, snippet in items[:limit]:
                if "google.com" not in url_r and "webcache" not in url_r:
                    results.append({
                        "title":   re.sub(r'<[^>]+>', '', title).strip()[:100],
                        "url":     url_r[:200],
                        "snippet": re.sub(r'<[^>]+>', '', snippet or "").strip()[:200],
                        "engine":  "google",
                    })

    async def _ddg_scrape():
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        s, txt = await GET(url, headers={"Accept": "text/html"}, timeout=12)
        if s == 200 and isinstance(txt, str):
            # DDG HTML result parsing
            links   = re.findall(r'<a class="result__a" href="([^"]+)"[^>]*>([^<]+)</a>', txt)
            snips   = re.findall(r'<a class="result__snippet"[^>]*>([^<]+)</a>', txt)
            for i, (link, title) in enumerate(links[:limit]):
                results.append({
                    "title":   title.strip()[:100],
                    "url":     link[:200],
                    "snippet": snips[i].strip()[:200] if i < len(snips) else "",
                    "engine":  "duckduckgo",
                })

    async def _bing_scrape():
        url = f"https://www.bing.com/search?q={quote_plus(query)}&count=10"
        s, txt = await GET(url, headers={"Accept": "text/html"}, timeout=12)
        if s == 200 and isinstance(txt, str):
            items = re.findall(
                r'<h2><a href="(https?://[^"]+)"[^>]*>([^<]+)</a></h2>'
                r'(?:.*?<p[^>]*>([^<]{20,200})</p>)?',
                txt, re.DOTALL
            )
            for url_r, title, snippet in items[:limit]:
                if "bing.com" not in url_r:
                    results.append({
                        "title":   re.sub(r'<[^>]+>', '', title).strip()[:100],
                        "url":     url_r[:200],
                        "snippet": re.sub(r'<[^>]+>', '', snippet or "").strip()[:200],
                        "engine":  "bing",
                    })

    if engine == "google":
        await _google_scrape()
    elif engine == "bing":
        await _bing_scrape()
    elif engine == "ddg":
        await _ddg_scrape()
    else:
        await asyncio.gather(_google_scrape(), _ddg_scrape(), return_exceptions=True)

    # Дедуп
    seen = set()
    unique = []
    for r in results:
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)

    return unique[:limit]


# ═══════════════════════════════════════════
#  HOSTING / SERVER DETECTION
# ═══════════════════════════════════════════
async def scan_hosting(target: str) -> dict:
    """Детектування хостингу, ЦОД, CDN, технологій."""
    out = {}

    # Resolve IP
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, target)
        out["ip"] = ip
    except Exception:
        ip = None

    if ip:
        # Shodan InternetDB
        s, d = await GET(f"https://internetdb.shodan.io/{ip}", timeout=8)
        if s == 200 and isinstance(d, dict):
            out["shodan"] = {
                "ports":     d.get("ports", []),
                "cpes":      d.get("cpes", []),
                "vulns":     d.get("vulns", [])[:5],
                "hostnames": d.get("hostnames", []),
                "tags":      d.get("tags", []),
            }

        # IPInfo для ASN/org
        s, d = await GET(f"https://ipinfo.io/{ip}/json", timeout=6)
        if s == 200 and isinstance(d, dict):
            org = d.get("org", "")
            out["hosting_org"] = org
            out["hosting_country"] = d.get("country", "")

            # Визначаємо тип хостингу
            provider = "Unknown"
            org_low = org.lower()
            if any(x in org_low for x in ["amazon", "aws"]): provider = "AWS (Amazon)"
            elif any(x in org_low for x in ["google", "gcp"]): provider = "Google Cloud"
            elif any(x in org_low for x in ["microsoft", "azure"]): provider = "Azure (Microsoft)"
            elif any(x in org_low for x in ["cloudflare"]): provider = "Cloudflare"
            elif any(x in org_low for x in ["digitalocean"]): provider = "DigitalOcean"
            elif any(x in org_low for x in ["linode", "akamai"]): provider = "Linode/Akamai"
            elif any(x in org_low for x in ["hetzner"]): provider = "Hetzner"
            elif any(x in org_low for x in ["ovh"]): provider = "OVH"
            elif any(x in org_low for x in ["fastly"]): provider = "Fastly CDN"
            elif any(x in org_low for x in ["vultr"]): provider = "Vultr"
            elif any(x in org_low for x in ["hostinger"]): provider = "Hostinger"
            out["provider"] = provider

    # HTTP headers для технологій
    s, txt = await GET(f"https://{target}", timeout=8)
    if s == 200 and isinstance(txt, str):
        tech = []
        txt_low = txt.lower()
        if "wp-content" in txt_low or "wordpress" in txt_low:      tech.append("WordPress")
        if "drupal" in txt_low:                                      tech.append("Drupal")
        if "joomla" in txt_low:                                      tech.append("Joomla")
        if "shopify" in txt_low:                                     tech.append("Shopify")
        if "react" in txt_low:                                       tech.append("React")
        if "vue.js" in txt_low or "vuejs" in txt_low:               tech.append("Vue.js")
        if "angular" in txt_low:                                     tech.append("Angular")
        if "next.js" in txt_low or "__next" in txt_low:             tech.append("Next.js")
        if "jquery" in txt_low:                                      tech.append("jQuery")
        if "bootstrap" in txt_low:                                   tech.append("Bootstrap")
        if "cloudflare" in txt_low:                                  tech.append("Cloudflare")
        if "google-analytics" in txt_low or "gtag" in txt_low:     tech.append("Google Analytics")
        if "yandex.metrika" in txt_low:                              tech.append("Yandex Metrika")
        if "php" in txt_low:                                         tech.append("PHP")
        if "asp.net" in txt_low:                                     tech.append("ASP.NET")
        if "laravel" in txt_low:                                     tech.append("Laravel")
        out["technologies"] = tech

    # Wappalyzer-style API (безкоштовно)
    s, d = await GET(f"https://api.whatcms.org/?Service=Check&url={target}&key=free", timeout=8)
    if s == 200 and isinstance(d, dict) and d.get("result", {}).get("code") == 200:
        out["cms"] = d.get("result", {}).get("name", "")

    return out


# ═══════════════════════════════════════════
#  ПАБЛІК ВИТОКИ (без ключів)
# ═══════════════════════════════════════════
async def search_public_leaks(query: str, qtype: str) -> list[dict]:
    """
    Шукає публічно відомі витоки без API ключів.
    Джерела: Pastebin, GitHub, різні публічні аггрегатори.
    """
    results = []

    async def _paste_search():
        # Pastebin search (через DDG)
        dork = f'site:pastebin.com "{query}"'
        found = await dork_search(dork, "ddg", 3)
        for r in found:
            results.append({
                "source":   "pastebin.com",
                "type":     "paste",
                "url":      r["url"],
                "title":    r["title"],
                "snippet":  r["snippet"],
            })

    async def _github_search():
        # GitHub code search
        s, d = await GET(
            "https://api.github.com/search/code",
            params={"q": f'"{query}"', "per_page": 5},
            headers={"Accept": "application/vnd.github.v3+json",
                     "User-Agent": "osint-bot"},
            timeout=10
        )
        if s == 200 and isinstance(d, dict):
            for item in d.get("items", [])[:5]:
                results.append({
                    "source":  "github.com",
                    "type":    "code",
                    "url":     item.get("html_url", ""),
                    "title":   item.get("name", ""),
                    "snippet": f"Repo: {item.get('repository', {}).get('full_name', '')}",
                })

    async def _intelligencex():
        # Intelligence X free tier
        s, d = await POST(
            "https://2.intelx.io/intelligent/search",
            jdata={"term": query, "maxresults": 5, "media": 0, "sort": 4, "terminate": []},
            headers={"x-key": "free"}, timeout=12
        )
        if s == 200 and isinstance(d, dict) and d.get("id"):
            await asyncio.sleep(2)
            sid = d["id"]
            s2, d2 = await GET(
                f"https://2.intelx.io/intelligent/search/result?id={sid}",
                headers={"x-key": "free"}, timeout=10
            )
            if s2 == 200 and isinstance(d2, dict):
                for r in (d2.get("records") or [])[:5]:
                    results.append({
                        "source":  "intelx.io",
                        "type":    r.get("mediah", ""),
                        "url":     f"https://intelx.io/?did={r.get('storageid','')}",
                        "title":   r.get("name", ""),
                        "snippet": f"Date: {r.get('added','')[:10]}",
                    })

    async def _leakcheck():
        s, d = await GET(
            f"https://leakcheck.net/api/public?key=free&check={query}",
            timeout=10
        )
        if s == 200 and isinstance(d, dict) and d.get("found"):
            results.append({
                "source":  "leakcheck.net",
                "type":    "breach",
                "url":     "https://leakcheck.net",
                "title":   f"Знайдено у {d.get('sources', [{}])[0].get('name', 'базі')}",
                "snippet": f"Знайдено: {d.get('found',0)} записів",
            })

    await asyncio.gather(
        _paste_search(), _github_search(), _intelligencex(), _leakcheck(),
        return_exceptions=True
    )
    return results
