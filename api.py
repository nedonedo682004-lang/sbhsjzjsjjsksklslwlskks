# ═══════════════════════════════════════════════════════════
#   JINX STRIPE API
#   Public API with full protection
#   • Rate limiting (per IP + global)
#   • SSRF protection
#   • Input validation
#   • Injection prevention
# ═══════════════════════════════════════════════════════════

import asyncio
import time
import re
import socket
import ipaddress
from typing import Optional, Dict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, validator
import uvicorn


# ═══════════ Config ═══════════
HOST = "0.0.0.0"
PORT = 8000

CHECKER_POOL = ThreadPoolExecutor(max_workers=2)

TEST_CARD = "5444224035733160|02|2029|832"
DEVELOPER = "@jinx_w"
DEVELOPER_URL = "https://t.me/jinx_w"

# Protection
IP_LIMIT_PER_MINUTE = 10
IP_BLOCK_DURATION = 300
GLOBAL_LIMIT_PER_MINUTE = 100
GLOBAL_COOLDOWN = 60


# ═══════════ FastAPI ═══════════
app = FastAPI(
    title="Jinx Stripe API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None,  # ✅ إخفاء redoc
)


# ═══════════ Memory Storage ═══════════
IP_HISTORY: Dict[str, list] = {}
IP_BLOCKED: Dict[str, float] = {}
GLOBAL_HISTORY: list = []
GLOBAL_COOLDOWN_UNTIL: float = 0


# ═══════════ ⚠️ Security Validators ═══════════

# 🚫 Characteres ممنوعة (Injection prevention)
FORBIDDEN_CHARS = set('<>"\'`\\\n\r\t\x00;|&$(){}[]%')

# 🚫 Local/Private IP ranges (SSRF prevention)
PRIVATE_RANGES = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.0.0.0/24'),
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('198.18.0.0/15'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
    ipaddress.ip_network('255.255.255.255/32'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fe80::/10'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('ff00::/8'),
]

# 🚫 Forbidden hostnames
FORBIDDEN_HOSTS = {
    'localhost', 'localhost.localdomain',
    'metadata.google.internal', 'metadata.google',
    'instance-data', 'metadata',
}


def has_forbidden_chars(text: str) -> bool:
    """✅ فحص شامل للـ injection"""
    if not text:
        return False
    return any(c in FORBIDDEN_CHARS for c in text)


def is_private_ip(ip_str: str) -> bool:
    """✅ فحص إن الـ IP داخلي"""
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in PRIVATE_RANGES:
            if ip in network:
                return True
        return False
    except:
        return True


def is_safe_site(site: str) -> tuple[bool, str]:
    """✅ فحص الموقع بالكامل (SSRF + Format)"""
    if not site:
        return False, "Empty site"
    
    # 🚫 Injection
    if has_forbidden_chars(site):
        return False, "Forbidden characters detected"
    
    # 🚫 Too long
    if len(site) > 100:
        return False, "Site too long"
    
    # 🚫 Clean it
    site = site.strip().lower()
    site = site.replace('https://', '').replace('http://', '').rstrip('/')
    
    # 🚫 Must contain /
    if '/' in site:
        site = site.split('/')[0]
    
    # 🚫 Remove port
    if ':' in site:
        site = site.split(':')[0]
    
    # 🚫 Forbidden hostnames
    if site in FORBIDDEN_HOSTS:
        return False, "Forbidden hostname"
    
    # 🚫 Must be valid domain format
    if not re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}$', site):
        return False, "Invalid domain format"
    
    # 🚫 Try to resolve
    try:
        ip_str = socket.gethostbyname(site)
        if is_private_ip(ip_str):
            return False, "Private IP not allowed"
    except socket.gaierror:
        return False, "Cannot resolve domain"
    except Exception:
        return False, "Domain error"
    
    return True, ""


def is_safe_cc(cc: str) -> tuple[bool, str]:
    """✅ فحص صيغة الكارت"""
    if not cc:
        return False, "Empty card"
    
    # 🚫 Injection
    if has_forbidden_chars(cc.replace('|', '')):
        return False, "Forbidden characters"
    
    # 🚫 Length
    if len(cc) > 30:
        return False, "Card too long"
    
    # 🚫 Format: 16|MM|YYYY|CVV
    if not re.match(r'^\d{15,16}\|\d{1,2}\|\d{2,4}\|\d{3,4}$', cc):
        return False, "Invalid card format"
    
    # ✅ Luhn check
    parts = cc.split('|')
    if len(parts) != 4:
        return False, "Invalid format"
    
    number = parts[0]
    try:
        digits = [int(d) for d in number]
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        if checksum % 10 != 0:
            return False, "Invalid card number (Luhn)"
    except:
        return False, "Card validation error"
    
    return True, ""


def is_safe_proxy(proxy: str) -> tuple[bool, str]:
    """✅ فحص صيغة البروكسي"""
    if not proxy:
        return True, ""  # اختياري
    
    # 🚫 Injection
    if has_forbidden_chars(proxy):
        return False, "Forbidden characters"
    
    # 🚫 Length
    if len(proxy) > 100:
        return False, "Proxy too long"
    
    # 🚫 Format: ip:port أو user:pass@ip:port
    patterns = [
        r'^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$',                      # ip:port
        r'^[\w\-\.]+:[\w\-\.]+@\d{1,3}(\.\d{1,3}){3}:\d{1,5}$',   # user:pass@ip:port
    ]
    if not any(re.match(p, proxy) for p in patterns):
        return False, "Invalid proxy format"
    
    return True, ""


# ═══════════ Models ═══════════
class CheckRequest(BaseModel):
    site: str
    cc: str
    proxy: Optional[str] = None


class TestSiteRequest(BaseModel):
    site: str
    proxy: Optional[str] = None


# ═══════════ Helpers ═══════════
def clean_site(site: str) -> str:
    site = site.strip().lower()
    site = site.replace('https://', '').replace('http://', '').rstrip('/')
    if '/' in site:
        site = site.split('/')[0]
    if ':' in site:
        site = site.split(':')[0]
    return site


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def check_ip_allowed(request: Request) -> tuple[bool, str]:
    ip = get_client_ip(request)
    now = time.time()
    
    if ip in IP_BLOCKED:
        blocked_until = IP_BLOCKED[ip]
        if now < blocked_until:
            remaining = int(blocked_until - now)
            return False, f"IP blocked. Try again in {remaining}s"
        else:
            del IP_BLOCKED[ip]
            if ip in IP_HISTORY:
                del IP_HISTORY[ip]
    
    if ip not in IP_HISTORY:
        IP_HISTORY[ip] = []
    
    IP_HISTORY[ip] = [t for t in IP_HISTORY[ip] if now - t < 60]
    
    if len(IP_HISTORY[ip]) >= IP_LIMIT_PER_MINUTE:
        IP_BLOCKED[ip] = now + IP_BLOCK_DURATION
        return False, f"Too many requests. IP blocked for {IP_BLOCK_DURATION}s"
    
    IP_HISTORY[ip].append(now)
    return True, ""


def check_global_allowed() -> tuple[bool, str]:
    global GLOBAL_COOLDOWN_UNTIL, GLOBAL_HISTORY
    now = time.time()
    
    if now < GLOBAL_COOLDOWN_UNTIL:
        remaining = int(GLOBAL_COOLDOWN_UNTIL - now)
        return False, f"API is in cooldown. Try again in {remaining}s"
    
    GLOBAL_HISTORY = [t for t in GLOBAL_HISTORY if now - t < 60]
    
    if len(GLOBAL_HISTORY) >= GLOBAL_LIMIT_PER_MINUTE:
        GLOBAL_COOLDOWN_UNTIL = now + GLOBAL_COOLDOWN
        GLOBAL_HISTORY = []
        return False, f"API overloaded. Pausing for {GLOBAL_COOLDOWN}s"
    
    GLOBAL_HISTORY.append(now)
    return True, ""


# ═══════════ Core ═══════════
async def check_card_async(site: str, cc: str, proxy: Optional[str] = None):
    try:
        from stripe_auth_checker import auth
        url = site if site.startswith('http') else f'https://{site}'
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(CHECKER_POOL, auth, url, cc, proxy)
        
        message = (result.get('message') or '').lower()
        success = result.get('success', False)
        
        if any(k in message for k in ["requires_action", "3d", "otp", "requires additional"]):
            return {"status": "3d_secure", "emoji": "⚠️", "title": "3D SECURE",
                    "message": "Card requires 3D Secure authentication", "success": False}
        elif success:
            return {"status": "approved", "emoji": "✅", "title": "APPROVED",
                    "message": "Card approved successfully", "success": True}
        else:
            return {"status": "declined", "emoji": "❌", "title": "DECLINED",
                    "message": "Card was declined", "success": False}
    except Exception:
        return {"status": "error", "emoji": "⛔", "title": "ERROR",
                "message": "Internal error", "success": False}


async def test_site_async(site: str, proxy: Optional[str] = None):
    try:
        from stripe_auth_checker import auth
        url = site if site.startswith('http') else f'https://{site}'
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(CHECKER_POOL, auth, url, TEST_CARD, proxy)
        
        is_working = bool(
            result.get('pm_id') and 
            (result.get('raw_response') or result.get('raw_response_json'))
        )
        
        if is_working:
            return {"status": "alive", "emoji": "🟢", "title": "SITE IS ALIVE",
                    "message": "Site is working and accepts Stripe payments", "success": True}
        else:
            return {"status": "dead", "emoji": "🔴", "title": "SITE IS DEAD",
                    "message": "Site is not working with Stripe", "success": False}
    except Exception:
        return {"status": "dead", "emoji": "🔴", "title": "SITE IS DEAD",
                "message": "Connection failed", "success": False}


# ═══════════ Routes ═══════════

@app.get("/")
async def root():
    return {
        "service": "Jinx Stripe API",
        "version": "1.0.0",
        "developer": DEVELOPER,
        "developer_url": DEVELOPER_URL,
        "status": "online",
    }


@app.post("/check")
async def check_post(req: CheckRequest, request: Request):
    # ✅ IP protection
    allowed, error = check_ip_allowed(request)
    if not allowed:
        raise HTTPException(status_code=429, detail=error)
    
    # ✅ Global protection
    allowed, error = check_global_allowed()
    if not allowed:
        raise HTTPException(status_code=503, detail=error)
    
    # ✅ Validate site
    site_clean = clean_site(req.site)
    safe, err = is_safe_site(site_clean)
    if not safe:
        raise HTTPException(status_code=400, detail=f"Site error: {err}")
    
    # ✅ Validate cc
    safe, err = is_safe_cc(req.cc.strip())
    if not safe:
        raise HTTPException(status_code=400, detail=f"Card error: {err}")
    
    # ✅ Validate proxy
    if req.proxy:
        safe, err = is_safe_proxy(req.proxy.strip())
        if not safe:
            raise HTTPException(status_code=400, detail=f"Proxy error: {err}")
    
    result = await check_card_async(site_clean, req.cc.strip(), req.proxy)
    
    return {
        "success": True,
        "site": site_clean,
        "cc": req.cc.strip(),
        "result": result,
        "time": datetime.now().isoformat(),
        "developer": DEVELOPER,
        "developer_url": DEVELOPER_URL,
    }


@app.get("/check/{site:path}/{cc}")
async def check_get(site: str, cc: str, request: Request, proxy: Optional[str] = Query(None)):
    allowed, error = check_ip_allowed(request)
    if not allowed:
        raise HTTPException(status_code=429, detail=error)
    
    allowed, error = check_global_allowed()
    if not allowed:
        raise HTTPException(status_code=503, detail=error)
    
    site_clean = clean_site(site)
    safe, err = is_safe_site(site_clean)
    if not safe:
        raise HTTPException(status_code=400, detail=f"Site error: {err}")
    
    safe, err = is_safe_cc(cc.strip())
    if not safe:
        raise HTTPException(status_code=400, detail=f"Card error: {err}")
    
    if proxy:
        safe, err = is_safe_proxy(proxy.strip())
        if not safe:
            raise HTTPException(status_code=400, detail=f"Proxy error: {err}")
    
    result = await check_card_async(site_clean, cc.strip(), proxy)
    
    return {
        "success": True,
        "site": site_clean,
        "cc": cc.strip(),
        "result": result,
        "time": datetime.now().isoformat(),
        "developer": DEVELOPER,
        "developer_url": DEVELOPER_URL,
    }


@app.post("/test-site")
async def test_site_post(req: TestSiteRequest, request: Request):
    allowed, error = check_ip_allowed(request)
    if not allowed:
        raise HTTPException(status_code=429, detail=error)
    
    allowed, error = check_global_allowed()
    if not allowed:
        raise HTTPException(status_code=503, detail=error)
    
    site_clean = clean_site(req.site)
    safe, err = is_safe_site(site_clean)
    if not safe:
        raise HTTPException(status_code=400, detail=f"Site error: {err}")
    
    if req.proxy:
        safe, err = is_safe_proxy(req.proxy.strip())
        if not safe:
            raise HTTPException(status_code=400, detail=f"Proxy error: {err}")
    
    result = await test_site_async(site_clean, req.proxy)
    
    return {
        "success": True,
        "site": site_clean,
        "test_card": TEST_CARD,
        "result": result,
        "time": datetime.now().isoformat(),
        "developer": DEVELOPER,
        "developer_url": DEVELOPER_URL,
    }


@app.get("/test-site/{site:path}")
async def test_site_get(site: str, request: Request, proxy: Optional[str] = Query(None)):
    allowed, error = check_ip_allowed(request)
    if not allowed:
        raise HTTPException(status_code=429, detail=error)
    
    allowed, error = check_global_allowed()
    if not allowed:
        raise HTTPException(status_code=503, detail=error)
    
    site_clean = clean_site(site)
    safe, err = is_safe_site(site_clean)
    if not safe:
        raise HTTPException(status_code=400, detail=f"Site error: {err}")
    
    if proxy:
        safe, err = is_safe_proxy(proxy.strip())
        if not safe:
            raise HTTPException(status_code=400, detail=f"Proxy error: {err}")
    
    result = await test_site_async(site_clean, proxy)
    
    return {
        "success": True,
        "site": site_clean,
        "test_card": TEST_CARD,
        "result": result,
        "time": datetime.now().isoformat(),
        "developer": DEVELOPER,
        "developer_url": DEVELOPER_URL,
    }


# ═══════════ Main ═══════════
if __name__ == "__main__":
    print("=" * 55)
    print("🛡️ JINX STRIPE API (FULLY PROTECTED)")
    print("=" * 55)
    print(f"📡 http://{HOST}:{PORT}")
    print(f"👤 Developer: {DEVELOPER}")
    print("=" * 55)
    print("🛡️ Protections:")
    print(f"  ✅ SSRF Protection")
    print(f"  ✅ Injection Prevention")
    print(f"  ✅ Input Validation")
    print(f"  ✅ Card Luhn Check")
    print(f"  ✅ IP Rate Limiting")
    print(f"  ✅ Global Emergency Brake")
    print("=" * 55)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
