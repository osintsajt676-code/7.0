"""
OSINT Aggregator — Database Layer
SQLite + aiosqlite
Таблиці: users, searches, profiles, leaks, notes, phones, emails, ips, crawl_queue
"""
import aiosqlite, json, logging, time
from pathlib import Path
import config

log = logging.getLogger("db")

# ═══════════════════════════════════════════
#  INIT
# ═══════════════════════════════════════════
async def init():
    Path("data").mkdir(exist_ok=True)
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;

        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY,
            username    TEXT    DEFAULT '',
            name        TEXT    DEFAULT '',
            is_admin    INTEGER DEFAULT 0,
            is_banned   INTEGER DEFAULT 0,
            api_key     TEXT    DEFAULT '',
            inf_key     TEXT    DEFAULT '',
            searches    INTEGER DEFAULT 0,
            joined      INTEGER DEFAULT (strftime('%s','now'))
        );

        -- Всі пошуки (для історії)
        CREATE TABLE IF NOT EXISTS searches (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            uid     INTEGER,
            stype   TEXT,
            target  TEXT,
            result  TEXT,
            ts      INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_s_uid    ON searches(uid);
        CREATE INDEX IF NOT EXISTS idx_s_target ON searches(target);

        -- Профілі з соцмереж (агрегатор)
        CREATE TABLE IF NOT EXISTS profiles (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            target   TEXT,
            platform TEXT,
            url      TEXT,
            data     TEXT,
            ts       INTEGER DEFAULT (strftime('%s','now')),
            UNIQUE(target, platform)
        );
        CREATE INDEX IF NOT EXISTS idx_p_target ON profiles(target);

        -- Витоки (email:pass пари, дампи)
        CREATE TABLE IF NOT EXISTS leaks (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            target   TEXT,
            source   TEXT,
            ltype    TEXT,
            data     TEXT,
            ts       INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_l_target ON leaks(target);

        -- Телефони
        CREATE TABLE IF NOT EXISTS phones (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            number   TEXT UNIQUE,
            name     TEXT DEFAULT '',
            carrier  TEXT DEFAULT '',
            country  TEXT DEFAULT '',
            extra    TEXT DEFAULT '{}',
            ts       INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_ph_num ON phones(number);

        -- Emails
        CREATE TABLE IF NOT EXISTS emails (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            email    TEXT UNIQUE,
            name     TEXT DEFAULT '',
            breached INTEGER DEFAULT 0,
            profiles TEXT DEFAULT '[]',
            extra    TEXT DEFAULT '{}',
            ts       INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_em_em ON emails(email);

        -- IP адреси
        CREATE TABLE IF NOT EXISTS ips (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ip       TEXT UNIQUE,
            country  TEXT DEFAULT '',
            isp      TEXT DEFAULT '',
            score    INTEGER DEFAULT 0,
            extra    TEXT DEFAULT '{}',
            ts       INTEGER DEFAULT (strftime('%s','now'))
        );

        -- Нотатки
        CREATE TABLE IF NOT EXISTS notes (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            uid     INTEGER,
            target  TEXT,
            note    TEXT,
            ts      INTEGER DEFAULT (strftime('%s','now'))
        );

        -- Черга краулера (для фонового збору)
        CREATE TABLE IF NOT EXISTS crawl_queue (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            target   TEXT,
            ttype    TEXT,
            status   TEXT DEFAULT 'pending',
            source   TEXT DEFAULT '',
            ts       INTEGER DEFAULT (strftime('%s','now')),
            UNIQUE(target, ttype)
        );
        CREATE INDEX IF NOT EXISTS idx_cq_status ON crawl_queue(status);

        -- Зібрані БД (паблік джерела)
        CREATE TABLE IF NOT EXISTS collected_db (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            target  TEXT,
            ttype   TEXT,
            source  TEXT,
            snippet TEXT,
            ts      INTEGER DEFAULT (strftime('%s','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_cd_target ON collected_db(target);
        """)
        await cx.commit()
    log.info("✅ DB ready")


# ═══════════════════════════════════════════
#  USERS
# ═══════════════════════════════════════════
async def get_user(uid: int) -> dict | None:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute("SELECT * FROM users WHERE id=?", (uid,)) as c:
            r = await c.fetchone()
            return dict(r) if r else None


async def upsert_user(uid: int, username: str, name: str) -> dict:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        is_admin = 1 if uid in config.ADMIN_IDS else 0
        await cx.execute("""
            INSERT INTO users(id, username, name, is_admin)
            VALUES(?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                username = excluded.username,
                name     = excluded.name,
                is_admin = MAX(is_admin, excluded.is_admin)
        """, (uid, username or "", name or "", is_admin))
        await cx.commit()
    return await get_user(uid)


async def set_key(uid: int, key: str, keytype: str = "api"):
    col = "api_key" if keytype == "api" else "inf_key"
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute(f"UPDATE users SET {col}=? WHERE id=?", (key, uid))
        await cx.commit()


async def get_keys(uid: int) -> tuple[str, str]:
    """Повертає (rapid_key, inf_key) — спочатку юзера, потім master."""
    u = await get_user(uid)
    rk = (u.get("api_key") if u else "") or config.RAPID_KEY
    ik = (u.get("inf_key") if u else "") or config.INFLUEENCER
    return rk, ik


async def inc_searches(uid: int):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute("UPDATE users SET searches=searches+1 WHERE id=?", (uid,))
        await cx.commit()


async def all_users() -> list:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute("SELECT * FROM users ORDER BY joined DESC") as c:
            return [dict(r) for r in await c.fetchall()]


async def ban(uid: int, v: int):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute("UPDATE users SET is_banned=? WHERE id=?", (v, uid))
        await cx.commit()


async def set_admin(uid: int, v: int):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute("UPDATE users SET is_admin=? WHERE id=?", (v, uid))
        await cx.commit()


# ═══════════════════════════════════════════
#  SEARCHES
# ═══════════════════════════════════════════
async def save_search(uid: int, stype: str, target: str, result: dict):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute(
            "INSERT INTO searches(uid,stype,target,result) VALUES(?,?,?,?)",
            (uid, stype, target, json.dumps(result, ensure_ascii=False))
        )
        await cx.commit()
    await inc_searches(uid)


async def get_history(uid: int, limit=25) -> list:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute(
            "SELECT id,stype,target,ts FROM searches WHERE uid=? ORDER BY ts DESC LIMIT ?",
            (uid, limit)
        ) as c:
            return [dict(r) for r in await c.fetchall()]


# ═══════════════════════════════════════════
#  PROFILES (соцмережі)
# ═══════════════════════════════════════════
async def save_profile(target: str, platform: str, url: str, data: dict):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute("""
            INSERT INTO profiles(target, platform, url, data)
            VALUES(?,?,?,?)
            ON CONFLICT(target, platform) DO UPDATE SET
                url=excluded.url, data=excluded.data, ts=strftime('%s','now')
        """, (target.lower(), platform, url, json.dumps(data, ensure_ascii=False)))
        await cx.commit()


async def get_profiles(target: str) -> list:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute(
            "SELECT * FROM profiles WHERE target=? ORDER BY ts DESC",
            (target.lower(),)
        ) as c:
            rows = [dict(r) for r in await c.fetchall()]
            for r in rows:
                try: r["data"] = json.loads(r["data"])
                except: pass
            return rows


# ═══════════════════════════════════════════
#  LEAKS
# ═══════════════════════════════════════════
async def save_leak(target: str, source: str, ltype: str, data: str):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute(
            "INSERT INTO leaks(target,source,ltype,data) VALUES(?,?,?,?)",
            (target.lower(), source, ltype, data)
        )
        await cx.commit()


async def get_leaks(target: str = None, uid_filter: int = None, limit=50) -> list:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        if target:
            async with cx.execute(
                "SELECT * FROM leaks WHERE target LIKE ? ORDER BY ts DESC LIMIT ?",
                (f"%{target.lower()}%", limit)
            ) as c:
                return [dict(r) for r in await c.fetchall()]
        async with cx.execute(
            "SELECT * FROM leaks ORDER BY ts DESC LIMIT ?", (limit,)
        ) as c:
            return [dict(r) for r in await c.fetchall()]


async def leaks_count() -> int:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        async with cx.execute("SELECT COUNT(*) FROM leaks") as c:
            return (await c.fetchone())[0]


# ═══════════════════════════════════════════
#  PHONES
# ═══════════════════════════════════════════
async def save_phone(number: str, name: str = "", carrier: str = "", country: str = "", extra: dict = None):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute("""
            INSERT INTO phones(number, name, carrier, country, extra)
            VALUES(?,?,?,?,?)
            ON CONFLICT(number) DO UPDATE SET
                name=COALESCE(NULLIF(excluded.name,''), name),
                carrier=COALESCE(NULLIF(excluded.carrier,''), carrier),
                country=COALESCE(NULLIF(excluded.country,''), country),
                extra=excluded.extra, ts=strftime('%s','now')
        """, (number, name, carrier, country, json.dumps(extra or {}, ensure_ascii=False)))
        await cx.commit()


async def get_phone_db(number: str) -> dict | None:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute("SELECT * FROM phones WHERE number=?", (number,)) as c:
            r = await c.fetchone()
            if r:
                d = dict(r)
                try: d["extra"] = json.loads(d["extra"])
                except: pass
                return d
    return None


# ═══════════════════════════════════════════
#  EMAILS
# ═══════════════════════════════════════════
async def save_email_data(email: str, name: str = "", breached: bool = False,
                          profiles: list = None, extra: dict = None):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute("""
            INSERT INTO emails(email, name, breached, profiles, extra)
            VALUES(?,?,?,?,?)
            ON CONFLICT(email) DO UPDATE SET
                name=COALESCE(NULLIF(excluded.name,''), name),
                breached=MAX(breached, excluded.breached),
                profiles=excluded.profiles,
                extra=excluded.extra, ts=strftime('%s','now')
        """, (email.lower(), name, int(breached),
              json.dumps(profiles or [], ensure_ascii=False),
              json.dumps(extra or {}, ensure_ascii=False)))
        await cx.commit()


async def get_email_db(email: str) -> dict | None:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute("SELECT * FROM emails WHERE email=?", (email.lower(),)) as c:
            r = await c.fetchone()
            if r:
                d = dict(r)
                try: d["profiles"] = json.loads(d["profiles"])
                except: pass
                try: d["extra"] = json.loads(d["extra"])
                except: pass
                return d
    return None


# ═══════════════════════════════════════════
#  IPs
# ═══════════════════════════════════════════
async def save_ip_data(ip: str, country: str = "", isp: str = "", score: int = 0, extra: dict = None):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute("""
            INSERT INTO ips(ip, country, isp, score, extra)
            VALUES(?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                country=excluded.country, isp=excluded.isp,
                score=excluded.score, extra=excluded.extra,
                ts=strftime('%s','now')
        """, (ip, country, isp, score, json.dumps(extra or {}, ensure_ascii=False)))
        await cx.commit()


async def get_ip_db(ip: str) -> dict | None:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute("SELECT * FROM ips WHERE ip=?", (ip,)) as c:
            r = await c.fetchone()
            if r:
                d = dict(r)
                try: d["extra"] = json.loads(d["extra"])
                except: pass
                return d
    return None


# ═══════════════════════════════════════════
#  NOTES
# ═══════════════════════════════════════════
async def add_note(uid: int, target: str, note: str):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute(
            "INSERT INTO notes(uid,target,note) VALUES(?,?,?)",
            (uid, target, note)
        )
        await cx.commit()


async def get_notes(uid: int) -> list:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute(
            "SELECT * FROM notes WHERE uid=? ORDER BY ts DESC LIMIT 50", (uid,)
        ) as c:
            return [dict(r) for r in await c.fetchall()]


# ═══════════════════════════════════════════
#  CRAWL QUEUE
# ═══════════════════════════════════════════
async def queue_add(target: str, ttype: str, source: str = ""):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        try:
            await cx.execute(
                "INSERT INTO crawl_queue(target,ttype,source) VALUES(?,?,?)",
                (target, ttype, source)
            )
            await cx.commit()
        except Exception:
            pass


async def queue_pending(limit=20) -> list:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute(
            "SELECT * FROM crawl_queue WHERE status='pending' ORDER BY ts ASC LIMIT ?",
            (limit,)
        ) as c:
            return [dict(r) for r in await c.fetchall()]


async def queue_done(qid: int):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute("UPDATE crawl_queue SET status='done' WHERE id=?", (qid,))
        await cx.commit()


# ═══════════════════════════════════════════
#  COLLECTED DB (паблік джерела)
# ═══════════════════════════════════════════
async def save_collected(target: str, ttype: str, source: str, snippet: str):
    async with aiosqlite.connect(config.DB_PATH) as cx:
        await cx.execute(
            "INSERT INTO collected_db(target,ttype,source,snippet) VALUES(?,?,?,?)",
            (target.lower(), ttype, source, snippet)
        )
        await cx.commit()


async def search_collected(target: str) -> list:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        cx.row_factory = aiosqlite.Row
        async with cx.execute(
            "SELECT * FROM collected_db WHERE target LIKE ? ORDER BY ts DESC LIMIT 30",
            (f"%{target.lower()}%",)
        ) as c:
            return [dict(r) for r in await c.fetchall()]


# ═══════════════════════════════════════════
#  STATS
# ═══════════════════════════════════════════
async def get_stats() -> dict:
    async with aiosqlite.connect(config.DB_PATH) as cx:
        async with cx.execute("SELECT COUNT(*) FROM users")        as c: u  = (await c.fetchone())[0]
        async with cx.execute("SELECT COUNT(*) FROM searches")     as c: s  = (await c.fetchone())[0]
        async with cx.execute("SELECT COUNT(*) FROM leaks")        as c: lk = (await c.fetchone())[0]
        async with cx.execute("SELECT COUNT(*) FROM profiles")     as c: pr = (await c.fetchone())[0]
        async with cx.execute("SELECT COUNT(*) FROM phones")       as c: ph = (await c.fetchone())[0]
        async with cx.execute("SELECT COUNT(*) FROM emails")       as c: em = (await c.fetchone())[0]
        async with cx.execute("SELECT COUNT(*) FROM collected_db") as c: cd = (await c.fetchone())[0]
        async with cx.execute(
            "SELECT stype, COUNT(*) FROM searches GROUP BY stype ORDER BY 2 DESC"
        ) as c:
            by_type = {r[0]: r[1] for r in await c.fetchall()}
    return {
        "users": u, "searches": s, "leaks": lk, "profiles": pr,
        "phones": ph, "emails": em, "collected": cd, "by_type": by_type
    }
