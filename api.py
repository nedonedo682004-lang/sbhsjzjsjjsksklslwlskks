# ═══════════════════════════════════════════════════════════
#   JINX STRIPE API
#   Endpoints:
#   • POST /check                → فحص كارت (JSON)
#   • GET  /check/{site}/{cc}    → فحص كارت (URL)
#   • POST /test-site            → فحص موقع (JSON)
#   • GET  /test-site/{site}     → فحص موقع (URL)
# ═══════════════════════════════════════════════════════════

import asyncio
from typing import Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import uvicorn


# ═══════════ Config ═══════════
HOST = "0.0.0.0"
PORT = 8000
CHECKER_POOL = ThreadPoolExecutor(max_workers=100)

# ✅ كارت اختبار للموقع
TEST_CARD = "5444224035733160|02|2029|832"

# ✅ معلومات المطور
DEVELOPER = "@jinx_w"
DEVELOPER_URL = "https://t.me/jinx_w"


# ═══════════ FastAPI ═══════════
app = FastAPI(title="Jinx Stripe API", version="1.0.0")


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
    return site.strip().lower().replace('https://', '').replace('http://', '').rstrip('/')


def dev_footer():
    """✅ فوتر المطور يضاف لكل رد"""
    return {
        "developer": DEVELOPER,
        "developer_url": DEVELOPER_URL,
    }


# ═══════════ Core: Check Card ═══════════
async def check_card_async(site: str, cc: str, proxy: Optional[str] = None):
    """Check card against Stripe site"""
    try:
        from stripe_auth_checker import auth
        
        url = site if site.startswith('http') else f'https://{site}'
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(CHECKER_POOL, auth, url, cc, proxy)
        
        message = (result.get('message') or '').lower()
        success = result.get('success', False)
        
        if any(k in message for k in ["requires_action", "3d", "otp", "requires additional"]):
            return {
                "status": "3d_secure",
                "emoji": "⚠️",
                "title": "3D SECURE",
                "message": "Card requires 3D Secure authentication",
                "success": False,
            }
        elif success:
            return {
                "status": "approved",
                "emoji": "✅",
                "title": "APPROVED",
                "message": "Card approved successfully",
                "success": True,
            }
        else:
            return {
                "status": "declined",
                "emoji": "❌",
                "title": "DECLINED",
                "message": result.get('message', 'Card was declined'),
                "success": False,
            }
    
    except Exception as e:
        return {
            "status": "error",
            "emoji": "⛔",
            "title": "ERROR",
            "message": str(e),
            "success": False,
        }


# ═══════════ Core: Test Site ═══════════
async def test_site_async(site: str, proxy: Optional[str] = None):
    """Test site with a test card"""
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
            return {
                "status": "alive",
                "emoji": "🟢",
                "title": "SITE IS ALIVE",
                "message": "Site is working and accepts Stripe payments",
                "success": True,
            }
        else:
            return {
                "status": "dead",
                "emoji": "🔴",
                "title": "SITE IS DEAD",
                "message": result.get('message', 'Site is not working with Stripe'),
                "success": False,
            }
    
    except Exception as e:
        return {
            "status": "dead",
            "emoji": "🔴",
            "title": "SITE IS DEAD",
            "message": str(e),
            "success": False,
        }


# ═══════════ Routes ═══════════

@app.get("/")
async def root():
    return {
        "service": "Jinx Stripe API",
        "version": "1.0.0",
        "developer": DEVELOPER,
        "developer_url": DEVELOPER_URL,
        "endpoints": {
            "POST /check": "Check a card (JSON body)",
            "GET /check/{site}/{cc}": "Check a card (URL)",
            "POST /test-site": "Test site (JSON body)",
            "GET /test-site/{site}": "Test site (URL)",
        },
        "examples": {
            "check_get": "/check/example.com/4111111111111111|12|2028|123",
            "test_site_get": "/test-site/example.com",
        }
    }


# ✅ فحص كارت (POST)
@app.post("/check")
async def check_post(req: CheckRequest):
    if not req.site or not req.cc:
        raise HTTPException(status_code=400, detail="'site' and 'cc' are required")
    
    site = clean_site(req.site)
    result = await check_card_async(site, req.cc.strip(), req.proxy)
    
    return {
        "success": True,
        "site": site,
        "cc": req.cc.strip(),
        "result": {
            "status": result["status"],
            "emoji": result["emoji"],
            "title": result["title"],
            "message": result["message"],
            "success": result["success"],
        },
        "time": datetime.now().isoformat(),
        **dev_footer(),  # ✅ المطور
    }


# ✅ فحص كارت (GET)
@app.get("/check/{site:path}/{cc}")
async def check_get(
    site: str,
    cc: str,
    proxy: Optional[str] = Query(None)
):
    if not site or not cc:
        raise HTTPException(status_code=400, detail="'site' and 'cc' are required")
    
    site = clean_site(site)
    result = await check_card_async(site, cc.strip(), proxy)
    
    return {
        "success": True,
        "site": site,
        "cc": cc.strip(),
        "result": {
            "status": result["status"],
            "emoji": result["emoji"],
            "title": result["title"],
            "message": result["message"],
            "success": result["success"],
        },
        "time": datetime.now().isoformat(),
        **dev_footer(),  # ✅ المطور
    }


# ✅ فحص موقع (POST)
@app.post("/test-site")
async def test_site_post(req: TestSiteRequest):
    if not req.site:
        raise HTTPException(status_code=400, detail="'site' is required")
    
    site = clean_site(req.site)
    result = await test_site_async(site, req.proxy)
    
    return {
        "success": True,
        "site": site,
        "test_card": TEST_CARD,
        "result": {
            "status": result["status"],
            "emoji": result["emoji"],
            "title": result["title"],
            "message": result["message"],
            "success": result["success"],
        },
        "time": datetime.now().isoformat(),
        **dev_footer(),  # ✅ المطور
    }


# ✅ فحص موقع (GET)
@app.get("/test-site/{site:path}")
async def test_site_get(
    site: str,
    proxy: Optional[str] = Query(None)
):
    if not site:
        raise HTTPException(status_code=400, detail="'site' is required")
    
    site = clean_site(site)
    result = await test_site_async(site, proxy)
    
    return {
        "success": True,
        "site": site,
        "test_card": TEST_CARD,
        "result": {
            "status": result["status"],
            "emoji": result["emoji"],
            "title": result["title"],
            "message": result["message"],
            "success": result["success"],
        },
        "time": datetime.now().isoformat(),
        **dev_footer(),  # ✅ المطور
    }


# ═══════════ Main ═══════════
if __name__ == "__main__":
    print("=" * 50)
    print("🚀 JINX STRIPE API STARTED")
    print("=" * 50)
    print(f"📡 http://{HOST}:{PORT}")
    print(f"📚 Docs: http://{HOST}:{PORT}/docs")
    print(f"👤 Developer: {DEVELOPER}")
    print("=" * 50)
    print("Endpoints:")
    print("  • POST /check")
    print("  • GET  /check/{site}/{cc}")
    print("  • POST /test-site")
    print("  • GET  /test-site/{site}")
    print("=" * 50)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")