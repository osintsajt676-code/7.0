"""
OSINT Aggregator Bot v7.0
Агресивний OSINT агрегатор з ланцюговим пошуком та фоновою БД.
"""
from keep_alive import keep_alive
keep_alive()

import asyncio, logging, re, json
from pathlib import Path
from aiogram import Bot, Dispatcher, Router, F
from aiogram.filters import Command
from aiogram.types import (Message, CallbackQuery,
                            InlineKeyboardMarkup, InlineKeyboardButton)
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

import config, db, engine, crawler

Path("data").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
    ]
)
log = logging.getLogger("bot")
router = Router()


# ═══════════════════════════════════════════
#  FSM
# ═══════════════════════════════════════════
class NoteState(StatesGroup):
    target = State()
    text   = State()

class SetKeyState(StatesGroup):
    waiting = State()


# ═══════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════
def ikb(*rows) -> InlineKeyboardMarkup:
    """ikb([("Text","cb"), ...], ...)"""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t, callback_data=c) for t, c in row]
            for row in rows
        ]
    )

def ts(epoch) -> str:
    import datetime
    try:
        return datetime.datetime.fromtimestamp(int(epoch)).strftime("%d.%m.%Y %H:%M")
    except Exception:
        return str(epoch)

async def auth(msg: Message) -> dict | None:
    uid = msg.from_user.id
    u   = await db.upsert_user(uid, msg.from_user.username or "", msg.from_user.first_name or "")
    if u.get("is_banned"):
        await msg.answer("🚫 Ви заблоковані."); return None
    return u

def is_admin_id(uid: int) -> bool:
    return uid in config.ADMIN_IDS

async def is_admin(uid: int) -> bool:
    u = await db.get_user(uid)
    return bool(u and (u.get("is_admin") or uid in config.ADMIN_IDS))

async def send_long(msg: Message, text: str, parse_mode="HTML"):
    for i in range(0, len(text), 4000):
        chunk = text[i:i+4000]
        try:
            await msg.answer(chunk, parse_mode=parse_mode, disable_web_page_preview=True)
        except Exception:
            try:
                await msg.answer(chunk, disable_web_page_preview=True)
            except Exception:
                pass

async def edit_or_send(msg: Message, text: str):
    try:
        await msg.edit_text(text, parse_mode="HTML", disable_web_page_preview=True)
    except Exception:
        await msg.answer(text, parse_mode="HTML", disable_web_page_preview=True)

def yn(v) -> str:
    if v is True:  return "🔴 ТАК"
    if v is False: return "🟢 НІ"
    return str(v) if v is not None else "—"

def score_bar(score: int) -> str:
    s = max(0, min(100, int(score or 0)))
    filled = s // 10
    ic = "🔴" if s > 75 else ("🟡" if s > 40 else "🟢")
    return f"{ic} {s}/100 [{'█'*filled}{'░'*(10-filled)}]"


# ═══════════════════════════════════════════
#  /start
# ═══════════════════════════════════════════
@router.message(Command("start"))
async def cmd_start(msg: Message):
    u = await auth(msg)
    if not u: return

    adm = "⭐ <b>Адмін режим активний</b>\n" if await is_admin(msg.from_user.id) else ""
    await msg.answer(
        f"🕵 <b>OSINT Aggregator v7.0</b>\n{adm}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "<b>🔍 OSINT модулі:</b>\n"
        "/ip &lt;адреса&gt; — IP розвідка (11 джерел)\n"
        "/domain &lt;домен&gt; — домен (WHOIS+DNS+crt.sh+субдомени)\n"
        "/email &lt;email&gt; — витоки+Gravatar+реєстрація\n"
        "/phone &lt;номер&gt; — оператор+Truecaller+Telegram\n"
        "/social &lt;username&gt; — 60+ соцмереж\n"
        "/hosting &lt;домен&gt; — хостинг+технології\n"
        "/chain &lt;ціль&gt; — 🔗 ланцюговий OSINT\n"
        "/dork &lt;запит&gt; — реальний Google пошук\n\n"
        "<b>💾 База даних:</b>\n"
        "/history — мої пошуки\n"
        "/leaks &lt;ціль&gt; — витоки в локальній БД\n"
        "/db_search &lt;ціль&gt; — пошук у зібраній БД\n"
        "/note — нотатки\n\n"
        "<b>⚙️ Налаштування:</b>\n"
        "/setkey — API ключі (RapidAPI + Influeencer)\n"
        "/me — профіль",
        parse_mode="HTML",
        reply_markup=ikb(
            [("👤 Профіль","me"), ("📋 Історія","hist")],
            [("💾 Витоки","leaks"), ("🕷 Статус БД","dbstats")],
        )
    )


# ═══════════════════════════════════════════
#  /me
# ═══════════════════════════════════════════
@router.message(Command("me"))
@router.callback_query(F.data == "me")
async def cmd_me(ev):
    msg = ev.message if isinstance(ev, CallbackQuery) else ev
    uid = ev.from_user.id
    u   = await db.get_user(uid) or await db.upsert_user(uid, "", "")
    rk, ik = await db.get_keys(uid)

    stats  = await db.get_stats()
    hist   = await db.get_history(uid, 5)

    rk_st = f"✅ Твій: <code>{u.get('api_key','')[:8]}...</code>" if u.get("api_key") \
            else ("✅ Master активний" if config.RAPID_KEY else "⬜ Немає")
    ik_st = f"✅ Твій: <code>{u.get('inf_key','')[:8]}...</code>" if u.get("inf_key") \
            else ("✅ Master активний" if config.INFLUEENCER else "⬜ Немає")

    text = (
        f"👤 <b>Профіль</b>\n\n"
        f"ID: <code>{uid}</code>\n"
        f"Username: @{u.get('username','—')}\n"
        f"Реєстрація: {ts(u.get('joined'))}\n"
        f"Пошуків: <b>{u.get('searches',0)}</b>\n"
        f"Адмін: {'✅' if await is_admin(uid) else '❌'}\n\n"
        f"<b>🔑 API ключі:</b>\n"
        f"  RapidAPI: {rk_st}\n"
        f"  Influeencer: {ik_st}\n\n"
        f"<b>📊 Загальна БД:</b>\n"
        f"  Витоків: {stats['leaks']:,}\n"
        f"  Профілів: {stats['profiles']:,}\n"
        f"  Зібрано даних: {stats['collected']:,}\n"
    )
    if hist:
        text += "\n<b>Останні пошуки:</b>\n"
        ic = {"ip":"🖥","domain":"🌐","email":"📧","phone":"📱","social":"👤","chain":"🔗"}
        for h in hist:
            text += f"  {ic.get(h['stype'],'🔍')} <code>{h['target']}</code> {ts(h['ts'])}\n"

    await msg.answer(text, parse_mode="HTML",
                     reply_markup=ikb([("📋 Історія","hist"),("💾 Витоки","leaks")]))
    if isinstance(ev, CallbackQuery): await ev.answer()


# ═══════════════════════════════════════════
#  /setkey
# ═══════════════════════════════════════════
@router.message(Command("setkey"))
async def cmd_setkey(msg: Message):
    if not await auth(msg): return
    await msg.answer(
        "🔑 <b>Встановити API ключі</b>\n\n"
        "<b>RapidAPI ключ (Truecaller, IP Fraud, Email Score):</b>\n"
        "<code>/setrapid ВАШ_КЛЮЧ</code>\n\n"
        "<b>Influeencer API (соцмережі + людський пошук):</b>\n"
        "<code>/setinf ВАШ_КЛЮЧ</code>\n\n"
        "Де взяти:\n"
        "• rapidapi.com → My Apps → X-RapidAPI-Key\n"
        "• Influeencer: <a href='https://rapidapi.com/influeencerapp/api/influeencer'>посилання</a>",
        parse_mode="HTML", disable_web_page_preview=True
    )


@router.message(Command("setrapid"))
async def cmd_setrapid(msg: Message):
    if not await auth(msg): return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or len(parts[1].strip()) < 10:
        await msg.answer("❌ <code>/setrapid ВАШ_RAPIDAPI_КЛЮЧ</code>", parse_mode="HTML"); return
    key = parts[1].strip()
    await db.set_key(msg.from_user.id, key, "api")
    await msg.answer(f"✅ RapidAPI ключ збережено: <code>{key[:8]}...</code>", parse_mode="HTML")


@router.message(Command("setinf"))
async def cmd_setinf(msg: Message):
    if not await auth(msg): return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or len(parts[1].strip()) < 10:
        await msg.answer("❌ <code>/setinf ВАШ_INFLUEENCER_КЛЮЧ</code>", parse_mode="HTML"); return
    key = parts[1].strip()
    await db.set_key(msg.from_user.id, key, "inf")
    await msg.answer(f"✅ Influeencer ключ збережено: <code>{key[:8]}...</code>", parse_mode="HTML")


# ═══════════════════════════════════════════
#  /ip
# ═══════════════════════════════════════════
@router.message(Command("ip"))
async def cmd_ip(msg: Message):
    u = await auth(msg)
    if not u: return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("❌ Приклад: <code>/ip 8.8.8.8</code>", parse_mode="HTML"); return

    ip = parts[1].strip()
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        await msg.answer("❌ Невірний формат IP."); return
    if any(ip.startswith(p) for p in ("192.168.","10.","127.","172.16.","169.254.")):
        await msg.answer("⚠️ Приватний IP."); return

    # Спершу шукаємо в локальній БД
    cached = await db.get_ip_db(ip)
    if cached:
        await msg.answer(
            f"💾 <b>З локальної БД: {ip}</b>\n"
            f"Країна: {cached.get('country','')}\n"
            f"ISP: {cached.get('isp','')}\n"
            f"Score: {cached.get('score',0)}\n"
            f"Оновлено: {ts(cached.get('ts'))}\n\n"
            "<i>Виконую актуальний пошук...</i>",
            parse_mode="HTML"
        )

    pm  = await msg.answer(f"🔍 IP аналіз <code>{ip}</code> (11 джерел)...", parse_mode="HTML")
    rk, _ = await db.get_keys(msg.from_user.id)

    try:
        data = await asyncio.wait_for(engine.scan_ip(ip, rk), timeout=35)
    except asyncio.TimeoutError:
        await edit_or_send(pm, "⏱ Таймаут."); return
    except Exception as e:
        await edit_or_send(pm, f"❌ {e}"); return

    await db.save_search(msg.from_user.id, "ip", ip, data)

    # Зберігаємо в локальну БД
    ii = data.get("ipinfo",{}) or {}
    ab = data.get("abuseipdb",{}) or {}
    await db.save_ip_data(ip,
        country = ii.get("country",""),
        isp     = ii.get("org",""),
        score   = ab.get("score",0),
        extra   = data
    )

    ia  = data.get("ipapi",{}) or {}
    bgp = data.get("bgp",{}) or {}
    otx = data.get("otx",{}) or {}
    gn  = data.get("greynoise",{}) or {}
    qs  = data.get("ipqs",{}) or {}
    sh  = data.get("shodan",{}) or {}
    vt  = data.get("virustotal",{}) or {}
    rd  = data.get("rapid",{}) or {}

    flags = []
    if ia.get("proxy") or qs.get("proxy"):       flags.append("🔴 PROXY")
    if qs.get("vpn") or rd.get("vpn"):           flags.append("🔴 VPN")
    if qs.get("tor") or rd.get("tor") or ab.get("is_tor"): flags.append("🔴 TOR")
    if qs.get("bot") or rd.get("bot"):           flags.append("🔴 BOT")
    if ia.get("hosting"):                        flags.append("☁️ HOSTING")
    if ia.get("mobile"):                         flags.append("📱 MOBILE")
    if sh.get("vulns"):                          flags.append(f"⚠️ VULN×{len(sh['vulns'])}")

    max_score = max(int(ab.get("score") or 0), int(qs.get("fraud") or 0), int(rd.get("fraud") or 0))

    text = f"🖥 <b>IP: {ip}</b>\n"
    if data.get("rdns"): text += f"PTR: <code>{data['rdns']}</code>\n"
    text += "━━━━━━━━━━━━━━━━━━\n"
    text += "<b>📍 Геолокація:</b>\n"
    text += f"  {ii.get('country','')} {ia.get('regionName','')} {ia.get('city','')}\n"
    if ii.get("loc"):      text += f"  📌 <code>{ii['loc']}</code>\n"
    if ii.get("timezone"): text += f"  🕐 {ii['timezone']}\n"

    text += "\n<b>🏢 Мережа / ASN:</b>\n"
    text += f"  ISP: {ia.get('isp','') or ii.get('org','')}\n"
    if ia.get("org") and ia["org"] != ia.get("isp",""): text += f"  Org: {ia['org']}\n"
    if ia.get("as"): text += f"  ASN: {ia['as']}\n"
    if bgp.get("rir"): text += f"  RIR: {bgp['rir']}\n"
    if bgp.get("ptr"): text += f"  PTR: {bgp['ptr']}\n"
    for asn_info in (bgp.get("asns") or [])[:2]:
        text += f"  AS{asn_info['asn']} {asn_info['name'][:40]} [{asn_info['country']}]\n"

    text += f"\n<b>⚠️ Репутація:</b>\n"
    text += f"  Загальний: {score_bar(max_score)}\n"
    if ab.get("score") is not None:
        text += f"  AbuseIPDB: {ab['score']}/100"
        if ab.get("reports"): text += f" ({ab['reports']} скарг)"
        if ab.get("domain"):  text += f" [{ab['domain']}]"
        text += "\n"
    if qs.get("fraud") is not None: text += f"  IPQuality:  {qs['fraud']}/100\n"
    if rd.get("fraud") is not None: text += f"  RapidAPI:   {rd['fraud']}/100\n"
    if gn.get("classification"):
        text += f"  GreyNoise:  {gn['classification']}"
        if gn.get("name"): text += f" ({gn['name']})"
        text += "\n"
    if otx.get("pulses"):
        text += f"  OTX: {otx['pulses']} pulses"
        if otx.get("tags"): text += f" — {', '.join(otx['tags'][:3])}"
        text += "\n"
    if vt.get("detected_urls"):
        text += f"  VirusTotal: {vt['detected_urls']} шкідливих URL\n"

    if sh.get("ports"):
        text += f"\n<b>🔌 Відкриті порти (Shodan):</b>\n"
        text += f"  {', '.join(str(p) for p in sh['ports'][:15])}\n"
        if sh.get("vulns"):
            text += f"  ⚠️ Вразливості: {', '.join(sh['vulns'][:5])}\n"
        if sh.get("cpes"):
            text += f"  CPE: {', '.join(sh['cpes'][:3])}\n"

    if flags:
        text += f"\n🏴 {' '.join(flags)}\n"

    # Перевіряємо в зібраній БД
    collected = await db.search_collected(ip)
    if collected:
        text += f"\n<b>💾 Знайдено в локальній БД ({len(collected)}):</b>\n"
        for c in collected[:3]:
            text += f"  📌 {c['source']}: {c['snippet'][:80]}\n"

    await edit_or_send(pm, text)


# ═══════════════════════════════════════════
#  /domain
# ═══════════════════════════════════════════
@router.message(Command("domain"))
async def cmd_domain(msg: Message):
    u = await auth(msg)
    if not u: return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("❌ Приклад: <code>/domain example.com</code>", parse_mode="HTML"); return

    dom = parts[1].strip().replace("https://","").replace("http://","").split("/")[0].lower().strip()
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$', dom):
        await msg.answer("❌ Невірний домен."); return

    pm = await msg.answer(f"🔍 Аналіз домену <code>{dom}</code>...", parse_mode="HTML")
    rk, _ = await db.get_keys(msg.from_user.id)

    try:
        data = await asyncio.wait_for(engine.scan_domain(dom, rk), timeout=50)
    except asyncio.TimeoutError:
        await edit_or_send(pm, "⏱ Таймаут."); return
    except Exception as e:
        await edit_or_send(pm, f"❌ {e}"); return

    await db.save_search(msg.from_user.id, "domain", dom, data)

    w   = data.get("whois") or {}
    dns = data.get("dns") or {}
    crt = data.get("crt") or {}
    ht  = data.get("hackertarget") or []
    us  = data.get("urlscan") or {}
    wb  = data.get("wayback") or {}
    ex  = data.get("extras") or {}

    text = f"🌐 <b>Domain: {dom}</b>\n"
    if data.get("alive"): text += "✅ Сайт доступний\n"
    text += "━━━━━━━━━━━━━━━━━━\n"

    if w and not w.get("error"):
        text += "<b>📋 WHOIS:</b>\n"
        if w.get("registrar"):   text += f"  Реєстратор: {w['registrar']}\n"
        if w.get("registrant"):  text += f"  Власник: {w['registrant']}\n"
        if w.get("org"):         text += f"  Org: {w['org']}\n"
        if w.get("country"):     text += f"  Країна: {w['country']}\n"
        if w.get("created"):     text += f"  Створено: {w['created']}\n"
        if w.get("expires"):     text += f"  Закінчується: {w['expires']}\n"
        if w.get("emails"):      text += f"  📧 {', '.join(w['emails'][:2])}\n"
        if w.get("nameservers"): text += f"  NS: {', '.join(w['nameservers'][:3])}\n"
        text += "\n"
    elif w.get("error"):
        text += f"WHOIS: {w['error']}\n\n"

    if dns:
        text += "<b>🔢 DNS:</b>\n"
        for rtype, vals in list(dns.items())[:7]:
            text += f"  {rtype}: {' | '.join(str(v)[:50] for v in vals[:3])}\n"
        text += "\n"

    all_subs = []
    if crt.get("subs"):
        all_subs.extend(crt["subs"])
        text += f"<b>📜 Сертифікати (crt.sh):</b> {crt.get('total_certs',0)} | Субдомени: {len(crt['subs'])}\n"
        for s in crt["subs"][:8]:
            text += f"  • {s}\n"
        if len(crt["subs"]) > 8:
            text += f"  <i>...+{len(crt['subs'])-8} ще</i>\n"
        text += "\n"

    if ht:
        text += f"<b>🔎 Субдомени (HackerTarget):</b> {len(ht)}\n"
        for h in ht[:8]:
            text += f"  • {h['host']} → {h['ip']}\n"
        if len(ht) > 8:
            text += f"  <i>...+{len(ht)-8} ще</i>\n"
        text += "\n"

    if us.get("total"):
        text += f"<b>🔍 URLScan:</b> {us['total']} сканів\n"
        for sc in (us.get("scans") or [])[:3]:
            if sc.get("ip"): text += f"  {sc['ip']} [{sc.get('country','')}] {sc.get('server','')}\n"
        text += "\n"

    if wb.get("url"):
        text += f"<b>📦 Wayback:</b> {wb.get('date','')} → <a href='{wb['url']}'>архів</a>\n"

    if ex.get("robots"):
        text += f"\n<b>🤖 robots.txt:</b> <code>{ex['robots'][:200]}</code>\n"
    if ex.get("security_txt"):
        text += f"\n<b>🔒 security.txt:</b>\n<code>{ex['security_txt'][:200]}</code>\n"

    # Локальна БД
    collected = await db.search_collected(dom)
    if collected:
        text += f"\n<b>💾 Локальна БД ({len(collected)}):</b>\n"
        for c in collected[:3]:
            text += f"  📌 {c['source']}: {c['snippet'][:80]}\n"

    await edit_or_send(pm, text)

    # Якщо багато субдоменів — окреме повідомлення
    if len(all_subs) > 8:
        full = "\n".join(sorted(set(all_subs)))
        await msg.answer(
            f"<b>Всі субдомени {dom} ({len(all_subs)}):</b>\n<code>{full[:3500]}</code>",
            parse_mode="HTML"
        )


# ═══════════════════════════════════════════
#  /email
# ═══════════════════════════════════════════
@router.message(Command("email"))
async def cmd_email(msg: Message):
    u = await auth(msg)
    if not u: return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', parts[1].strip()):
        await msg.answer("❌ Приклад: <code>/email user@example.com</code>", parse_mode="HTML"); return

    addr = parts[1].strip().lower()

    # Локальна БД спочатку
    cached = await db.get_email_db(addr)
    if cached:
        await msg.answer(
            f"💾 <b>З БД: {addr}</b>\n"
            f"Ім'я: {cached.get('name','—')}\n"
            f"Breach: {yn(bool(cached.get('breached')))}\n"
            f"Оновлено: {ts(cached.get('ts'))}\n\n<i>Актуальний пошук...</i>",
            parse_mode="HTML"
        )

    pm  = await msg.answer(f"🔍 Email аналіз <code>{addr}</code>...", parse_mode="HTML")
    rk, _ = await db.get_keys(msg.from_user.id)

    try:
        data = await asyncio.wait_for(engine.scan_email(addr, rk), timeout=30)
    except asyncio.TimeoutError:
        await edit_or_send(pm, "⏱ Таймаут."); return
    except Exception as e:
        await edit_or_send(pm, f"❌ {e}"); return

    await db.save_search(msg.from_user.id, "email", addr, data)

    er = data.get("emailrep") or {}
    gv = data.get("gravatar") or {}
    br = data.get("breach_dir") or {}
    dp = data.get("disposable")
    tw = data.get("twitter_reg")
    gh = data.get("github_reg")
    hn = data.get("hunter") or {}
    rd = data.get("rapid") or {}

    # Зберігаємо
    await db.save_email_data(addr,
        name     = gv.get("name","") if gv.get("found") else "",
        breached = er.get("breached", False) or br.get("found", False),
        profiles = er.get("profiles", []),
        extra    = data
    )
    if er.get("breached") or er.get("leaked"):
        await db.save_leak(addr, "emailrep.io", "breach",
                           f"breach={er.get('breached')}, leak={er.get('leaked')}")
    if br.get("found"):
        await db.save_leak(addr, "breachdirectory.org", "breach",
                           f"{br.get('count',0)} записів")

    flags = []
    if er.get("breached"):                      flags.append("🔴 BREACH")
    if er.get("leaked"):                        flags.append("🔴 LEAK")
    if er.get("disposable") or dp is True:      flags.append("⚠️ DISPOSABLE")
    if er.get("spam"):                          flags.append("⚠️ SPAM")
    if er.get("suspicious"):                    flags.append("⚠️ SUSPICIOUS")

    rep = er.get("reputation","")
    ric = "🟢" if rep=="high" else ("🟡" if rep=="medium" else "🔴")

    text = f"📧 <b>Email: {addr}</b>\n━━━━━━━━━━━━━━━━━━\n"

    if er:
        text += f"<b>📋 EmailRep:</b> {ric} {rep or '?'}"
        if er.get("refs"): text += f" ({er['refs']} посилань)"
        text += "\n"
        if er.get("first_seen"): text += f"  Вперше: {er['first_seen']}\n"
        if er.get("last_seen"):  text += f"  Востаннє: {er['last_seen']}\n"
        if er.get("profiles"):   text += f"  Профілі: {', '.join(er['profiles'][:6])}\n"
        text += "\n"

    text += "<b>💾 Витоки:</b>\n"
    text += f"  Дані в базах: {yn(er.get('breached'))}\n"
    text += f"  Паролі витекли: {yn(er.get('leaked'))}\n"
    if br:
        if br.get("found"):
            text += f"  BreachDir: 🔴 {br.get('count',0)} записів\n"
            for src in (br.get("samples") or [])[:3]:
                text += f"    • {src}\n"
        else:
            text += f"  BreachDir: 🟢 чисто\n"

    text += "\n<b>🌐 Реєстрація в сервісах:</b>\n"
    if tw is not None: text += f"  Twitter/X: {'🔴 Так' if tw else '🟢 Ні'}\n"
    if gh is not None: text += f"  GitHub:    {'🔴 Так' if gh else '🟢 Ні'}\n"
    if dp is not None: text += f"  Disposable: {'⚠️ Так' if dp else '🟢 Ні'}\n"

    if hn:
        text += f"\n<b>📊 Hunter.io:</b>\n"
        text += f"  Result: {hn.get('result','')} | Score: {hn.get('score',0)}\n"
        text += f"  SMTP: {yn(hn.get('smtp_check'))} | MX: {yn(hn.get('mx_records'))}\n"

    if gv.get("found"):
        text += f"\n<b>🖼 Gravatar:</b> знайдено\n"
        if gv.get("name"):     text += f"  Ім'я: <b>{gv['name']}</b>\n"
        if gv.get("location"): text += f"  📍 {gv['location']}\n"
        if gv.get("bio"):      text += f"  {gv['bio']}\n"
        if gv.get("accounts"): text += f"  Акаунти: {', '.join(gv['accounts'][:5])}\n"
        if gv.get("emails"):   text += f"  📧 {', '.join(gv['emails'][:3])}\n"
    else:
        text += "\n<b>🖼 Gravatar:</b> не знайдено\n"

    if rd:
        text += f"\n<b>RapidAPI:</b> score={rd.get('score','?')} risky={yn(rd.get('risky'))}\n"

    if flags:
        text += f"\n🏴 {' '.join(flags)}\n"

    # Локальна БД витоків
    lk = await db.get_leaks(addr)
    if lk:
        text += f"\n💾 <i>У локальній БД: {len(lk)} записів → /leaks {addr}</i>\n"

    # Додаємо в чергу для подальшого збору
    await db.queue_add(addr, "email", "user_search")

    await edit_or_send(pm, text)


# ═══════════════════════════════════════════
#  /phone
# ═══════════════════════════════════════════
@router.message(Command("phone"))
async def cmd_phone(msg: Message):
    u = await auth(msg)
    if not u: return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("❌ Приклад: <code>/phone +380XXXXXXXXX</code>", parse_mode="HTML"); return

    phone = parts[1].strip()
    if not phone.startswith("+"): phone = "+" + phone
    if not re.match(r'^\+\d{7,16}$', phone):
        await msg.answer("❌ Формат: +380XXXXXXXXX"); return

    # Локальна БД
    cached = await db.get_phone_db(phone)
    if cached and (cached.get("name") or cached.get("carrier")):
        await msg.answer(
            f"💾 <b>З БД: {phone}</b>\n"
            f"Ім'я: <b>{cached.get('name','—')}</b>\n"
            f"Оператор: {cached.get('carrier','—')}\n"
            f"Країна: {cached.get('country','—')}\n\n<i>Актуальний пошук...</i>",
            parse_mode="HTML"
        )

    pm  = await msg.answer(f"🔍 Аналіз <code>{phone}</code>...", parse_mode="HTML")
    rk, _ = await db.get_keys(msg.from_user.id)

    try:
        data = await asyncio.wait_for(engine.scan_phone(phone, rk), timeout=30)
    except asyncio.TimeoutError:
        await edit_or_send(pm, "⏱ Таймаут."); return
    except Exception as e:
        await edit_or_send(pm, f"❌ {e}"); return

    await db.save_search(msg.from_user.id, "phone", phone, data)

    pn = data.get("pn") or {}
    fr = data.get("fragment") or {}
    tc = data.get("truecaller") or {}
    pv = data.get("phval") or {}
    gc = data.get("getcontact") or {}
    ln = data.get("links") or {}
    ie = data.get("influeencer_phone") or {}

    # Зберігаємо в БД
    await db.save_phone(phone,
        name    = tc.get("name","") or ie.get("name",""),
        carrier = pn.get("carrier","") or tc.get("carrier",""),
        country = pn.get("country_en",""),
        extra   = data
    )
    # Додаємо в чергу
    await db.queue_add(phone, "phone", "user_search")

    text = f"📱 <b>Телефон: {phone}</b>\n━━━━━━━━━━━━━━━━━━\n"

    if pn:
        text += "<b>📋 Google phonenumbers:</b>\n"
        text += f"  {'✅ Валідний' if pn.get('valid') else '❌ Невалідний'}\n"
        text += f"  Формат: {pn.get('intl','')}\n"
        text += f"  Країна: {pn.get('country','—')} ({pn.get('region','')})\n"
        text += f"  Оператор: <b>{pn.get('carrier','—') or '—'}</b>\n"
        text += f"  Тип: {pn.get('type','—')}\n"
        if pn.get("tz"): text += f"  TZ: {pn['tz'][0]}\n"
        text += "\n"

    if tc.get("name"):
        text += f"<b>👤 Truecaller:</b>\n"
        text += f"  Ім'я: <b>{tc['name']}</b>\n"
        if tc.get("carrier"): text += f"  Оператор: {tc['carrier']}\n"
        if tc.get("type"):    text += f"  Тип: {tc['type']}\n"
        if tc.get("score") and tc["score"] > 0:
            text += f"  🔴 Spam score: {tc['score']}\n"
        if tc.get("tags"):    text += f"  Теги: {', '.join(str(t) for t in tc['tags'])}\n"
        if tc.get("emails"):
            emails = [e.get("id","") if isinstance(e,dict) else str(e) for e in tc["emails"][:2]]
            text += f"  📧 {', '.join(emails)}\n"
        text += "\n"
    elif rk:
        text += "<b>👤 Truecaller:</b> нічого не знайдено\n\n"
    else:
        text += "<b>👤 Truecaller:</b> потрібен /setrapid\n\n"

    if pv and (pv.get("carrier") or pv.get("location")):
        text += "<b>📞 Phone Lookup:</b>\n"
        if pv.get("country"):  text += f"  Країна: {pv['country']}\n"
        if pv.get("location"): text += f"  Регіон: {pv['location']}\n"
        if pv.get("carrier"):  text += f"  Оператор: {pv['carrier']}\n"
        if pv.get("line"):     text += f"  Тип лінії: {pv['line']}\n"
        text += "\n"

    if gc.get("tags") or gc.get("names"):
        text += "<b>📇 GetContact:</b>\n"
        if gc.get("names"): text += f"  Імена: {', '.join(gc['names'][:3])}\n"
        if gc.get("tags"):  text += f"  Теги: {', '.join(gc['tags'][:5])}\n"
        text += "\n"

    if ie:
        text += f"<b>🔮 Influeencer API:</b>\n"
        for k, v in list(ie.items())[:5]:
            if v: text += f"  {k}: {str(v)[:60]}\n"
        text += "\n"

    text += "<b>✈️ Telegram (Fragment):</b>\n"
    if fr.get("registered") is True:
        text += f"  🔴 <b>ЗАРЕЄСТРОВАНИЙ</b>\n"
        if fr.get("name"):      text += f"  Ім'я: {fr['name']}\n"
        if fr.get("price_ton"): text += f"  💎 {fr['price_ton']} TON\n"
    elif fr.get("registered") is False:
        text += "  🟢 Не зареєстрований\n"
    else:
        text += "  ⚠️ Не вдалося перевірити\n"
    if fr.get("url"): text += f"  <a href='{fr['url']}'>Fragment</a>\n"

    text += "\n<b>🔗 Месенджери:</b>\n"
    if ln.get("whatsapp"): text += f"  <a href='{ln['whatsapp']}'>💬 WhatsApp</a>  "
    if ln.get("viber"):    text += f"<a href='{ln['viber']}'>📲 Viber</a>  "
    if ln.get("telegram"): text += f"<a href='{ln['telegram']}'>✈️ Telegram</a>\n"

    # Публічні витоки
    pub_leaks = await db.search_collected(phone)
    if pub_leaks:
        text += f"\n<b>💾 Знайдено в зібраній БД ({len(pub_leaks)}):</b>\n"
        for pl in pub_leaks[:3]:
            text += f"  📌 {pl['source']}: {pl['snippet'][:80]}\n"

    await edit_or_send(pm, text)


# ═══════════════════════════════════════════
#  /social
# ═══════════════════════════════════════════
@router.message(Command("social"))
async def cmd_social(msg: Message):
    u = await auth(msg)
    if not u: return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2 or not 2 <= len(parts[1].strip()) <= 50:
        await msg.answer("❌ Приклад: <code>/social username</code>", parse_mode="HTML"); return

    username = parts[1].strip()
    total    = len(engine.PLATFORMS)
    pm       = await msg.answer(
        f"🔍 Сканую <b>{username}</b> по {total} платформах...", parse_mode="HTML"
    )
    _, inf_key = await db.get_keys(msg.from_user.id)

    try:
        data = await asyncio.wait_for(engine.scan_social(username, inf_key), timeout=70)
    except asyncio.TimeoutError:
        await edit_or_send(pm, "⏱ Таймаут."); return
    except Exception as e:
        await edit_or_send(pm, f"❌ {e}"); return

    await db.save_search(msg.from_user.id, "social", username, data)

    found    = [(k, v) for k, v in data.items() if isinstance(v,dict) and v.get("found")]
    notfound = [(k, v) for k, v in data.items() if isinstance(v,dict) and not v.get("found")]

    # Зберігаємо профілі
    for name, v in found:
        await db.save_profile(username, name, v.get("url",""), v)

    text = (
        f"👤 <b>{username}</b>\n"
        f"✅ {len(found)} знайдено | ❌ {len(notfound)} не знайдено\n"
        f"━━━━━━━━━━━━━━━━━━\n"
    )

    if found:
        text += "<b>🟢 Знайдені профілі:</b>\n"
        for name, v in found:
            url = v.get("url","")
            line = f'• <a href="{url}">{name}</a>'
            if v.get("name") and v["name"] != username: line += f" — <b>{v['name']}</b>"
            details = []
            if v.get("followers"): details.append(f"👥{v['followers']}")
            if v.get("karma"):     details.append(f"⭐{v['karma']}")
            if v.get("repos"):     details.append(f"📦{v['repos']}")
            if v.get("posts"):     details.append(f"📝{v['posts']}")
            if details: line += f" {' '.join(details)}"
            text += line + "\n"
            if v.get("bio"):      text += f"   <i>{str(v['bio'])[:60]}</i>\n"
            if v.get("email"):    text += f"   📧 {v['email']}\n"
            if v.get("location"): text += f"   📍 {v['location']}\n"
            if v.get("subs"):     text += f"   {v['subs']}\n"
            if v.get("twitter"):  text += f"   🐦 @{v['twitter']}\n"
            if v.get("blog"):     text += f"   🔗 {v['blog'][:50]}\n"

    not_found_names = ", ".join(k for k, _ in notfound)
    text += f"\n<b>❌ Не знайдено:</b> <i>{not_found_names[:200]}</i>"

    await send_long(pm if len(text) < 4000 else msg, text)
    if len(text) >= 4000:
        try: await pm.delete()
        except: pass


# ═══════════════════════════════════════════
#  /hosting
# ═══════════════════════════════════════════
@router.message(Command("hosting"))
async def cmd_hosting(msg: Message):
    u = await auth(msg)
    if not u: return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("❌ Приклад: <code>/hosting example.com</code>", parse_mode="HTML"); return

    target = parts[1].strip().replace("https://","").replace("http://","").split("/")[0].lower()
    pm     = await msg.answer(f"🔍 Аналіз хостингу <code>{target}</code>...", parse_mode="HTML")

    try:
        data = await asyncio.wait_for(engine.scan_hosting(target), timeout=25)
    except asyncio.TimeoutError:
        await edit_or_send(pm, "⏱ Таймаут."); return
    except Exception as e:
        await edit_or_send(pm, f"❌ {e}"); return

    await db.save_search(msg.from_user.id, "hosting", target, data)

    text = f"🏠 <b>Hosting: {target}</b>\n━━━━━━━━━━━━━━━━━━\n"
    if data.get("ip"):         text += f"IP: <code>{data['ip']}</code>\n"
    if data.get("provider"):   text += f"Провайдер: <b>{data['provider']}</b>\n"
    if data.get("hosting_org"):text += f"Org: {data['hosting_org']}\n"
    if data.get("hosting_country"): text += f"Країна: {data['hosting_country']}\n"

    sh = data.get("shodan") or {}
    if sh.get("ports"):
        text += f"\n<b>🔌 Відкриті порти:</b>\n  {', '.join(str(p) for p in sh['ports'][:20])}\n"
    if sh.get("vulns"):
        text += f"⚠️ Вразливості: {', '.join(sh['vulns'][:8])}\n"
    if sh.get("cpes"):
        text += f"CPE: {', '.join(sh['cpes'][:5])}\n"
    if sh.get("hostnames"):
        text += f"Hostnames: {', '.join(sh['hostnames'][:5])}\n"
    if sh.get("tags"):
        text += f"Tags: {', '.join(sh['tags'][:5])}\n"

    tech = data.get("technologies") or []
    if tech:
        text += f"\n<b>⚙️ Технології:</b>\n  {', '.join(tech)}\n"
    if data.get("cms"):
        text += f"CMS: {data['cms']}\n"

    await edit_or_send(pm, text)


# ═══════════════════════════════════════════
#  /chain — ланцюговий OSINT
# ═══════════════════════════════════════════
@router.message(Command("chain"))
async def cmd_chain(msg: Message):
    u = await auth(msg)
    if not u: return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer(
            "❌ <b>Ланцюговий OSINT</b>\n\n"
            "Автоматично визначає тип і запускає повний пошук:\n"
            "<code>/chain +380954283372</code>\n"
            "<code>/chain user@gmail.com</code>\n"
            "<code>/chain johndoe</code>\n\n"
            "Бот: знаходить → за знайденим шукає ще → і так далі",
            parse_mode="HTML"
        ); return

    target = parts[1].strip()

    # Визначаємо тип
    if re.match(r'^\+?\d{7,16}$', target.replace(" ","")):
        stype = "phone"
        if not target.startswith("+"): target = "+" + target
    elif re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
        stype = "email"
    else:
        stype = "username"

    pm = await msg.answer(
        f"🔗 <b>Ланцюговий OSINT: {target}</b>\n"
        f"Тип: {stype}\n\n"
        "🔄 Запускаю ланцюг пошуку...",
        parse_mode="HTML"
    )
    rk, ik = await db.get_keys(msg.from_user.id)

    try:
        chain = await asyncio.wait_for(
            engine.chain_search(target, stype, rk, ik), timeout=120
        )
    except asyncio.TimeoutError:
        await edit_or_send(pm, "⏱ Таймаут (120с). Часткові результати збережені."); return
    except Exception as e:
        await edit_or_send(pm, f"❌ {e}"); return

    await db.save_search(msg.from_user.id, "chain", target, chain)

    summary = chain.get("summary", {})
    steps   = chain.get("steps", [])

    text = (
        f"🔗 <b>Ланцюговий OSINT: {target}</b>\n"
        f"Кроків виконано: {len(steps)}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
    )

    if summary.get("names"):
        text += f"\n👤 <b>Знайдені імена:</b>\n"
        for n in summary["names"][:5]: text += f"  • <b>{n}</b>\n"

    if summary.get("emails"):
        text += f"\n📧 <b>Знайдені emails:</b>\n"
        for e in summary["emails"][:5]: text += f"  • <code>{e}</code>\n"

    if summary.get("phones"):
        text += f"\n📱 <b>Знайдені телефони:</b>\n"
        for p in summary["phones"][:5]: text += f"  • <code>{p}</code>\n"

    if summary.get("usernames"):
        text += f"\n👥 <b>Знайдені usernames:</b>\n"
        for u in summary["usernames"][:8]: text += f"  • {u}\n"

    if summary.get("domains"):
        text += f"\n🌐 <b>Знайдені домени:</b>\n"
        for d in summary["domains"][:5]: text += f"  • {d}\n"

    text += f"\n<b>📋 Кроки пошуку:</b>\n"
    for step in steps:
        label = step.get("step","")
        if step.get("error"):
            text += f"  ❌ {label}: {step['error']}\n"
        else:
            data_keys = list((step.get("data") or {}).keys())[:3]
            text += f"  ✅ {label}: {', '.join(data_keys) if data_keys else 'OK'}\n"

    await send_long(pm if len(text) < 4000 else msg, text)


# ═══════════════════════════════════════════
#  /dork — реальний пошук і показ результатів
# ═══════════════════════════════════════════
@router.message(Command("dork"))
async def cmd_dork(msg: Message):
    u = await auth(msg)
    if not u: return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer(
            "❌ <b>Google Dork пошук</b>\n\n"
            "Виконує РЕАЛЬНИЙ пошук і показує результати:\n"
            "<code>/dork site:pastebin.com user@gmail.com</code>\n"
            "<code>/dork \"John Doe\" phone -site:linkedin.com</code>\n"
            "<code>/dork site:example.com filetype:sql</code>",
            parse_mode="HTML"
        ); return

    query = parts[1].strip()
    pm    = await msg.answer(f"🔍 Пошук: <code>{query}</code>...", parse_mode="HTML")

    try:
        results = await asyncio.wait_for(
            engine.dork_search(query, "ddg", limit=8), timeout=20
        )
    except asyncio.TimeoutError:
        # Fallback на bing
        try:
            results = await asyncio.wait_for(
                engine.dork_search(query, "bing", limit=8), timeout=20
            )
        except Exception:
            results = []
    except Exception as e:
        await edit_or_send(pm, f"❌ {e}"); return

    if not results:
        # Ще один fallback
        try:
            results = await asyncio.wait_for(
                engine.dork_search(query, "google", limit=5), timeout=20
            )
        except Exception:
            results = []

    if not results:
        await edit_or_send(pm,
            f"🔍 <b>Результати для:</b> <code>{query}</code>\n\n"
            "Нічого не знайдено. Спробуй уточнити запит."
        ); return

    text = f"🔍 <b>Результати ({len(results)}):</b> <code>{query[:50]}</code>\n━━━━━━━━━━━━━━━━━━\n\n"
    for i, r in enumerate(results, 1):
        text += f"<b>{i}. {r.get('title','Без заголовку')}</b>\n"
        text += f"🔗 <a href='{r.get('url','#')}'>{r.get('url','')[:70]}</a>\n"
        if r.get("snippet"):
            text += f"<i>{r['snippet'][:150]}</i>\n"
        text += "\n"

    await edit_or_send(pm, text)


# ═══════════════════════════════════════════
#  /leaks
# ═══════════════════════════════════════════
@router.message(Command("leaks"))
@router.callback_query(F.data == "leaks")
async def cmd_leaks(ev):
    msg    = ev.message if isinstance(ev, CallbackQuery) else ev
    uid    = ev.from_user.id
    target = None
    if hasattr(msg, "text") and msg.text:
        parts = msg.text.strip().split(maxsplit=1)
        target = parts[1].strip() if len(parts) > 1 else None

    leaks = await db.get_leaks(target)
    if not leaks:
        await msg.answer(
            "💾 Витоків немає.\n<i>Зберігаються автоматично при /email та /chain</i>",
            parse_mode="HTML"
        )
        if isinstance(ev, CallbackQuery): await ev.answer()
        return

    text = f"<b>💾 Витоки ({len(leaks)}){' для: '+target if target else ''}:</b>\n━━━━━━━━━━━━━━━━━━\n\n"
    for l in leaks[:20]:
        text += f"🔴 <code>{l['target']}</code>\n"
        text += f"   Джерело: {l['source']}\n"
        text += f"   Тип: {l['ltype']}\n"
        text += f"   {l['data'][:100]}\n"
        text += f"   <i>{ts(l['ts'])}</i>\n\n"

    if len(leaks) > 20:
        text += f"<i>...+{len(leaks)-20} ще</i>"

    await send_long(msg, text)
    if isinstance(ev, CallbackQuery): await ev.answer()


# ═══════════════════════════════════════════
#  /db_search — пошук у зібраній БД
# ═══════════════════════════════════════════
@router.message(Command("db_search"))
async def cmd_db_search(msg: Message):
    if not await auth(msg): return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("❌ <code>/db_search email@example.com</code>", parse_mode="HTML"); return

    target = parts[1].strip()
    pm     = await msg.answer(f"💾 Пошук <code>{target}</code> в локальній БД...", parse_mode="HTML")

    # Шукаємо в усіх таблицях паралельно
    phone_res  = await db.get_phone_db(target) if re.match(r'^\+?\d{7,}$', target.replace(" ","")) else None
    email_res  = await db.get_email_db(target) if "@" in target else None
    ip_res     = await db.get_ip_db(target) if re.match(r'^\d+\.\d+\.\d+\.\d+$', target) else None
    profiles   = await db.get_profiles(target)
    collected  = await db.search_collected(target)
    leaks      = await db.get_leaks(target)

    text = f"💾 <b>Локальна БД: {target}</b>\n━━━━━━━━━━━━━━━━━━\n\n"
    found_any = False

    if phone_res:
        found_any = True
        text += "<b>📱 Телефон:</b>\n"
        text += f"  Ім'я: {phone_res.get('name','—')}\n"
        text += f"  Оператор: {phone_res.get('carrier','—')}\n"
        text += f"  Країна: {phone_res.get('country','—')}\n"
        text += f"  Оновлено: {ts(phone_res.get('ts'))}\n\n"

    if email_res:
        found_any = True
        text += "<b>📧 Email:</b>\n"
        text += f"  Ім'я: {email_res.get('name','—')}\n"
        text += f"  Breach: {yn(bool(email_res.get('breached')))}\n"
        if email_res.get("profiles"): text += f"  Профілі: {', '.join(email_res['profiles'][:5])}\n"
        text += "\n"

    if ip_res:
        found_any = True
        text += "<b>🖥 IP:</b>\n"
        text += f"  Країна: {ip_res.get('country','')}\n"
        text += f"  ISP: {ip_res.get('isp','')}\n"
        text += f"  Score: {ip_res.get('score',0)}\n\n"

    if profiles:
        found_any = True
        text += f"<b>👤 Профілі ({len(profiles)}):</b>\n"
        for p in profiles[:5]:
            text += f"  • {p['platform']}: <a href='{p['url']}'>{p['url'][:50]}</a>\n"
        text += "\n"

    if leaks:
        found_any = True
        text += f"<b>🔴 Витоки ({len(leaks)}):</b>\n"
        for l in leaks[:3]:
            text += f"  • {l['source']}: {l['data'][:60]}\n"
        text += "\n"

    if collected:
        found_any = True
        text += f"<b>💾 Зібрані дані ({len(collected)}):</b>\n"
        for c in collected[:5]:
            text += f"  📌 [{c['source']}] {c['snippet'][:80]}\n"
        text += "\n"

    if not found_any:
        text += "❌ Нічого не знайдено в локальній БД.\n\n"
        text += "💡 Спробуй спочатку: /email /phone /ip /chain"

    await edit_or_send(pm, text)


# ═══════════════════════════════════════════
#  /history
# ═══════════════════════════════════════════
@router.message(Command("history"))
@router.callback_query(F.data == "hist")
async def cmd_history(ev):
    msg = ev.message if isinstance(ev, CallbackQuery) else ev
    uid = ev.from_user.id

    hist = await db.get_history(uid, 30)
    if not hist:
        await msg.answer("📋 Історія порожня."); return

    ic   = {"ip":"🖥","domain":"🌐","email":"📧","phone":"📱","social":"👤","chain":"🔗","hosting":"🏠","dork":"🔍"}
    text = f"<b>📋 Мої пошуки ({len(hist)}):</b>\n\n"
    for h in hist:
        text += f"{ic.get(h['stype'],'🔍')} <code>{h['target']}</code> [{h['stype']}] — {ts(h['ts'])}\n"

    await msg.answer(text, parse_mode="HTML")
    if isinstance(ev, CallbackQuery): await ev.answer()


# ═══════════════════════════════════════════
#  /note
# ═══════════════════════════════════════════
@router.message(Command("note"))
async def cmd_note(msg: Message, state: FSMContext):
    if not await auth(msg): return
    parts = msg.text.strip().split(maxsplit=2)
    if len(parts) == 3:
        await db.add_note(msg.from_user.id, parts[1], parts[2])
        await msg.answer(f"✅ Нотатка збережена для <code>{parts[1]}</code>", parse_mode="HTML")
        return
    if len(parts) == 2:
        await state.update_data(target=parts[1])
        await msg.answer(f"📝 Введи текст нотатки для <code>{parts[1]}</code>:", parse_mode="HTML")
        await state.set_state(NoteState.text)
        return
    await msg.answer("Приклад: <code>/note 8.8.8.8 Google DNS server</code>", parse_mode="HTML")
    await state.set_state(NoteState.target)


@router.message(NoteState.target)
async def note_get_target(msg: Message, state: FSMContext):
    await state.update_data(target=msg.text.strip())
    await msg.answer(f"📝 Текст нотатки для <code>{msg.text.strip()}</code>:", parse_mode="HTML")
    await state.set_state(NoteState.text)


@router.message(NoteState.text)
async def note_get_text(msg: Message, state: FSMContext):
    d = await state.get_data()
    await db.add_note(msg.from_user.id, d.get("target","?"), msg.text.strip())
    await state.clear()
    await msg.answer("✅ Нотатка збережена")


@router.message(Command("notes"))
async def cmd_notes(msg: Message):
    if not await auth(msg): return
    notes = await db.get_notes(msg.from_user.id)
    if not notes:
        await msg.answer("📝 Нотатки порожні. Приклад: <code>/note 8.8.8.8 текст</code>", parse_mode="HTML"); return
    text = "<b>📝 Мої нотатки:</b>\n\n"
    for n in notes:
        text += f"📌 <code>{n['target']}</code>\n  {n['note']}\n  <i>{ts(n['ts'])}</i>\n\n"
    await send_long(msg, text)


# ═══════════════════════════════════════════
#  /dbstats
# ═══════════════════════════════════════════
@router.message(Command("dbstats"))
@router.callback_query(F.data == "dbstats")
async def cmd_dbstats(ev):
    msg = ev.message if isinstance(ev, CallbackQuery) else ev
    s = await db.get_stats()
    by_type = "\n".join(f"  {k}: {v:,}" for k, v in s["by_type"].items())
    text = (
        f"📊 <b>Статистика БД:</b>\n\n"
        f"👥 Юзерів: {s['users']:,}\n"
        f"🔍 Пошуків: {s['searches']:,}\n"
        f"🔴 Витоків: {s['leaks']:,}\n"
        f"👤 Профілів: {s['profiles']:,}\n"
        f"📱 Телефонів: {s['phones']:,}\n"
        f"📧 Emails: {s['emails']:,}\n"
        f"💾 Зібрано IOC: {s['collected']:,}\n\n"
        f"<b>По типах пошуку:</b>\n{by_type}\n\n"
        f"<i>🕷 Краулер працює в фоні (оновлення кожну годину)</i>"
    )
    await msg.answer(text, parse_mode="HTML")
    if isinstance(ev, CallbackQuery): await ev.answer()


# ═══════════════════════════════════════════
#  ADMIN COMMANDS
# ═══════════════════════════════════════════
@router.message(Command("stat"))
async def cmd_stat(msg: Message):
    if not await is_admin(msg.from_user.id): return
    s = await db.get_stats()
    by_type = "\n".join(f"  {k}: {v:,}" for k, v in s["by_type"].items())
    await msg.answer(
        f"<b>📊 Адмін статистика:</b>\n\n"
        f"Юзерів: {s['users']:,}\n"
        f"Пошуків: {s['searches']:,}\n"
        f"Витоків: {s['leaks']:,}\n"
        f"Профілів: {s['profiles']:,}\n"
        f"Зібрано: {s['collected']:,}\n\n"
        f"<b>По типах:</b>\n{by_type}",
        parse_mode="HTML"
    )


@router.message(Command("users"))
async def cmd_users(msg: Message):
    if not await is_admin(msg.from_user.id): return
    users = await db.all_users()
    text  = f"<b>👥 Юзери ({len(users)}):</b>\n\n"
    for u in users[:30]:
        marks = ""
        if u.get("is_admin"):  marks += "⭐"
        if u.get("is_banned"): marks += "🚫"
        rk = "🔑" if u.get("api_key") else ""
        text += f"{marks}{rk} @{u.get('username','—')} <code>{u['id']}</code> — {u.get('searches',0)} пошуків\n"
    await msg.answer(text, parse_mode="HTML")


@router.message(Command("ban"))
async def cmd_ban(msg: Message):
    if not await is_admin(msg.from_user.id): return
    parts = msg.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        await msg.answer("Приклад: <code>/ban 123456789</code>", parse_mode="HTML"); return
    await db.ban(int(parts[1]), 1)
    await msg.answer(f"🚫 Заблоковано <code>{parts[1]}</code>", parse_mode="HTML")


@router.message(Command("unban"))
async def cmd_unban(msg: Message):
    if not await is_admin(msg.from_user.id): return
    parts = msg.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit():
        await msg.answer("Приклад: <code>/unban 123456789</code>", parse_mode="HTML"); return
    await db.ban(int(parts[1]), 0)
    await msg.answer(f"✅ Розблоковано <code>{parts[1]}</code>", parse_mode="HTML")


@router.message(Command("addadmin"))
async def cmd_addadmin(msg: Message):
    if not await is_admin(msg.from_user.id): return
    parts = msg.text.strip().split()
    if len(parts) < 2 or not parts[1].isdigit(): return
    await db.set_admin(int(parts[1]), 1)
    await msg.answer(f"⭐ <code>{parts[1]}</code> тепер адмін", parse_mode="HTML")


@router.message(Command("broadcast"))
async def cmd_broadcast(msg: Message):
    """Розсилка всім юзерам."""
    if not await is_admin(msg.from_user.id): return
    parts = msg.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await msg.answer("Приклад: <code>/broadcast Текст повідомлення</code>", parse_mode="HTML"); return
    text  = parts[1]
    users = await db.all_users()
    bot   = msg.bot
    ok = 0
    for u in users:
        if u.get("is_banned"): continue
        try:
            await bot.send_message(u["id"], f"📢 {text}", parse_mode="HTML")
            ok += 1
            await asyncio.sleep(0.05)
        except Exception:
            pass
    await msg.answer(f"✅ Розіслано {ok}/{len(users)}")


@router.message(Command("help"))
async def cmd_help(msg: Message):
    if not await auth(msg): return
    await msg.answer(
        "🕵 <b>OSINT Aggregator v7.0</b>\n\n"
        "<b>🔍 OSINT:</b>\n"
        "/ip &lt;ip&gt; — 11 джерел аналізу\n"
        "/domain &lt;dom&gt; — WHOIS+DNS+crt+субдомени\n"
        "/email &lt;email&gt; — витоки+Gravatar+сервіси\n"
        "/phone &lt;+380...&gt; — оператор+Truecaller+TG\n"
        "/social &lt;user&gt; — 60+ соцмереж\n"
        "/hosting &lt;dom&gt; — хостинг+технології+порти\n"
        "/chain &lt;ціль&gt; — 🔗 ланцюговий авто-OSINT\n"
        "/dork &lt;запит&gt; — реальний Google пошук\n\n"
        "<b>💾 БД:</b>\n"
        "/history — мої пошуки\n"
        "/leaks — збережені витоки\n"
        "/leaks email — по конкретній цілі\n"
        "/db_search &lt;ціль&gt; — в локальній БД\n"
        "/dbstats — статистика зібраної БД\n"
        "/note — нотатки\n\n"
        "<b>⚙️:</b>\n"
        "/setkey — управління ключами\n"
        "/setrapid &lt;KEY&gt; — RapidAPI ключ\n"
        "/setinf &lt;KEY&gt; — Influeencer API ключ\n"
        "/me — профіль",
        parse_mode="HTML"
    )


# ═══════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════
async def main():
    if not config.BOT_TOKEN:
        log.error("❌ BOT_TOKEN не заданий у .env!")
        sys.exit(1)

    await db.init()

    bot = Bot(token=config.BOT_TOKEN)
    dp  = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)

    # Скидаємо старі апдейти
    await bot.delete_webhook(drop_pending_updates=True)

    # Запускаємо фоновий краулер
    await crawler.start_crawler()

    log.info("🤖 OSINT Aggregator v7.0 запущено")
    log.info(f"⭐ Адміни: {config.ADMIN_IDS}")
    log.info(f"🔑 RapidAPI: {'✅' if config.RAPID_KEY else '⬜'}")
    log.info(f"🔮 Influeencer: {'✅' if config.INFLUEENCER else '⬜'}")

    await dp.start_polling(bot, skip_updates=True)


if __name__ == "__main__":
    asyncio.run(main())
