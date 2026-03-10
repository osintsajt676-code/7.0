"""
OSINT Aggregator — Background Crawler
Запускається при старті бота у фоні.
Збирає публічні OSINT-бази і зберігає в локальну БД.
"""
import asyncio, logging, re, time
import config, db, engine

log = logging.getLogger("crawler")

# ═══════════════════════════════════════════
#  ПУБЛІЧНІ OSINT ДЖЕРЕЛА (без реєстрації)
# ═══════════════════════════════════════════
PUBLIC_FEEDS = [
    # Паблік бази відомих порушень (тільки metadata, не паролі)
    "https://haveibeenpwned.com/api/v3/breaches",                  # Список відомих брічів
    "https://www.dehashed.com/search?query=*",                     # Публічний пошук
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
]

BREACH_LIST_URL = "https://haveibeenpwned.com/api/v3/breaches"

PASTEBIN_RECENT = [
    "https://scrape.pastebin.com/api_scraping.php?limit=100",
]

OSINT_FEEDS = [
    "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=40",
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/json/",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
]


async def crawl_breaches():
    """Завантажує список відомих breaches з HIBP (без ключа — тільки metadata)."""
    try:
        s, d = await engine.GET(BREACH_LIST_URL, timeout=20)
        if s == 200 and isinstance(d, list):
            for breach in d:
                name    = breach.get("Name", "")
                domain  = breach.get("Domain", "")
                date    = breach.get("BreachDate", "")
                count   = breach.get("PwnCount", 0)
                classes = breach.get("DataClasses", [])

                if domain:
                    await db.save_collected(
                        domain, "breach_meta", "haveibeenpwned.com",
                        f"Breach: {name} | Date: {date} | Count: {count:,} | Data: {', '.join(classes[:4])}"
                    )
            log.info(f"✅ Crawled {len(d)} breaches from HIBP")
    except Exception as e:
        log.warning(f"crawl_breaches: {e}")


async def crawl_alienvault_pulses():
    """Завантажує OTX pulse indicators."""
    try:
        s, d = await engine.GET(
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20",
            headers={"X-OTX-API-KEY": "free"}, timeout=20
        )
        if s == 200 and isinstance(d, dict):
            pulses = d.get("results", [])
            for pulse in pulses:
                for indicator in pulse.get("indicators", [])[:10]:
                    itype  = indicator.get("type", "")
                    ival   = indicator.get("indicator", "")
                    if itype in ("IPv4", "domain", "email", "URL") and ival:
                        await db.save_collected(
                            ival, itype.lower(), "alienvault.com",
                            f"Pulse: {pulse.get('name','')[:60]} | Tags: {', '.join(pulse.get('tags',[])[:3])}"
                        )
            log.info(f"Crawled OTX pulses")
    except Exception as e:
        log.debug(f"crawl_otx: {e}")


async def crawl_threatfox():
    """Завантажує ThreatFox IOC list."""
    try:
        s, d = await engine.POST(
            "https://threatfox-api.abuse.ch/api/v1/",
            jdata={"query": "get_iocs", "days": 1},
            timeout=20
        )
        if s == 200 and isinstance(d, dict) and d.get("query_status") == "ok":
            iocs = d.get("data", [])
            for ioc in iocs[:50]:
                val   = ioc.get("ioc_value", "")
                itype = ioc.get("ioc_type", "")
                malware = ioc.get("malware", "")
                if val:
                    await db.save_collected(
                        val, itype, "threatfox.abuse.ch",
                        f"Malware: {malware} | Confidence: {ioc.get('confidence_level',0)}"
                    )
            log.info(f"Crawled {len(iocs)} ThreatFox IOCs")
    except Exception as e:
        log.debug(f"crawl_threatfox: {e}")


async def crawl_ipsum():
    """Завантажує список підозрілих IP."""
    try:
        s, txt = await engine.GET(
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            timeout=20
        )
        if s == 200 and isinstance(txt, str):
            count = 0
            for line in txt.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and re.match(r'^\d+\.\d+\.\d+\.\d+', line):
                    parts = line.split()
                    ip    = parts[0]
                    score = int(parts[1]) if len(parts) > 1 else 1
                    if score >= 3:  # Тільки з рейтингом 3+
                        await db.save_collected(
                            ip, "ip", "ipsum/github",
                            f"Blacklist score: {score}"
                        )
                        count += 1
                        if count >= 200: break
            log.info(f"Crawled {count} IPs from ipsum")
    except Exception as e:
        log.debug(f"crawl_ipsum: {e}")


async def crawl_phishing():
    """Завантажує список фішингових доменів."""
    try:
        s, txt = await engine.GET("https://openphish.com/feed.txt", timeout=15)
        if s == 200 and isinstance(txt, str):
            count = 0
            for line in txt.strip().split("\n")[:100]:
                url = line.strip()
                if url.startswith("http"):
                    domain = re.search(r"https?://([^/]+)", url)
                    if domain:
                        await db.save_collected(
                            domain.group(1), "domain", "openphish.com",
                            f"Phishing URL: {url[:100]}"
                        )
                        count += 1
            log.info(f"Crawled {count} phishing domains from OpenPhish")
    except Exception as e:
        log.debug(f"crawl_phishing: {e}")


async def crawl_urlhaus():
    """URLhaus malicious URLs."""
    try:
        s, d = await engine.GET("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=15)
        if s == 200 and isinstance(d, dict):
            urls = d.get("urls", [])
            for u in urls[:50]:
                url     = u.get("url", "")
                domain  = u.get("host", "")
                status  = u.get("url_status", "")
                tags    = ", ".join(u.get("tags", [])[:3])
                if domain:
                    await db.save_collected(
                        domain, "domain", "urlhaus.abuse.ch",
                        f"Malware URL: {url[:80]} | Status: {status} | Tags: {tags}"
                    )
            log.info(f"Crawled {len(urls)} URLhaus entries")
    except Exception as e:
        log.debug(f"crawl_urlhaus: {e}")


async def process_queue():
    """Обробляє чергу цілей для OSINT."""
    pending = await db.queue_pending(limit=5)
    for item in pending:
        target = item["target"]
        ttype  = item["ttype"]
        try:
            if ttype == "phone":
                data = await asyncio.wait_for(engine.scan_phone(target), timeout=25)
                pn = data.get("pn", {})
                await db.save_phone(
                    target,
                    name    = data.get("truecaller", {}).get("name", ""),
                    carrier = pn.get("carrier", ""),
                    country = pn.get("country_en", ""),
                    extra   = data
                )
            elif ttype == "email":
                data = await asyncio.wait_for(engine.scan_email(target), timeout=25)
                er = data.get("emailrep", {})
                gv = data.get("gravatar", {})
                await db.save_email_data(
                    target,
                    name     = gv.get("name", "") if gv.get("found") else "",
                    breached = er.get("breached", False),
                    profiles = er.get("profiles", []),
                    extra    = data
                )
            elif ttype == "ip":
                data = await asyncio.wait_for(engine.scan_ip(target), timeout=20)
                ii = data.get("ipinfo", {})
                ab = data.get("abuseipdb", {})
                await db.save_ip_data(
                    target,
                    country = ii.get("country", ""),
                    isp     = ii.get("org", ""),
                    score   = ab.get("score", 0),
                    extra   = data
                )
            log.info(f"Queue processed: {ttype} {target}")
        except Exception as e:
            log.warning(f"Queue error {ttype} {target}: {e}")
        finally:
            await db.queue_done(item["id"])


# ═══════════════════════════════════════════
#  ГОЛОВНИЙ КРАУЛЕР
# ═══════════════════════════════════════════
async def crawler_main():
    """
    Фоновий краулер. Запускається як asyncio task.
    Цикл: збір публічних даних → сон 1год → знов.
    """
    log.info("🕷 Crawler started")

    # Перший запуск — завантажуємо всі бази
    await asyncio.sleep(10)  # Чекаємо поки бот запуститься

    cycle = 0
    while True:
        try:
            log.info(f"🕷 Crawler cycle #{cycle}")

            # Щогодини: HIBP + ThreatFox
            if cycle % 1 == 0:
                await asyncio.gather(
                    crawl_breaches(),
                    crawl_threatfox(),
                    crawl_ipsum(),
                    crawl_phishing(),
                    crawl_urlhaus(),
                    return_exceptions=True
                )

            # Кожні 6 циклів: OTX
            if cycle % 6 == 0:
                await crawl_alienvault_pulses()

            # Обробляємо чергу цілей
            await process_queue()

            log.info(f"🕷 Crawler cycle #{cycle} done")
            cycle += 1

        except Exception as e:
            log.error(f"Crawler error: {e}")

        # Сон 1 година між циклами
        await asyncio.sleep(3600)


async def start_crawler():
    """Запускає краулер як фоновий task."""
    asyncio.create_task(crawler_main())
    log.info("🕷 Crawler task created")
