import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ═══════════════════════════════════════════
#  CORE
# ═══════════════════════════════════════════
BOT_TOKEN   = os.getenv("BOT_TOKEN", "")
ADMIN_IDS   = [8525242680]          # твій TG ID
DB_PATH     = "data/osint.db"
LOG_FILE    = "data/bot.log"

# ═══════════════════════════════════════════
#  API KEYS (всі опціональні)
# ═══════════════════════════════════════════
RAPID_KEY     = os.getenv("RAPID_API_KEY", "")      # rapidapi.com master key
INFLUEENCER   = os.getenv("INFLUEENCER_KEY", "")    # influeencer social API
PROXY         = os.getenv("PROXY_URL", "")          # socks5://...

# ═══════════════════════════════════════════
#  HTTP
# ═══════════════════════════════════════════
TIMEOUT_FAST = 8
TIMEOUT_MED  = 15
TIMEOUT_SLOW = 30

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

def get_headers(extra: dict = None) -> dict:
    import random
    h = {
        "User-Agent":      random.choice(UA_LIST),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,uk;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT":             "1",
        "Connection":      "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if extra:
        h.update(extra)
    return h
