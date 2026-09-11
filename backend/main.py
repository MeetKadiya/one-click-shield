import os
import sys
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.engine import UnifiedScannerEngine
from core.remediator import AutoRemediator
from core.db import init_db, save_scan, get_recent_scans, get_scan_by_target

app = FastAPI(
    title="One-Click Shield API",
    description="Unified Scanner & Auto-Remediator for Web Security Configuration Weaknesses",
    version="2.0.0"
)

# Initialize persistent SQLite database
init_db()

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = UnifiedScannerEngine(timeout=8.0)

# In-memory scan cache
SCAN_CACHE: Dict[str, Dict[str, Any]] = {}
SCAN_HISTORY: List[Dict[str, Any]] = []


class ScanRequest(BaseModel):
    target: str
    scenario: Optional[str] = None  # None, "demo-vulnerable", "demo-secure", etc.


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "One-Click Shield Engine",
        "version": "2.0.0"
    }


@app.post("/api/scan")
async def scan_domain(request: ScanRequest):
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target domain or URL is required.")

    try:
        results = await engine.scan_target(target, is_demo_scenario=request.scenario)
        clean_name = results["target"]
        SCAN_CACHE[clean_name] = results

        # Persist to SQLite Database
        try:
            save_scan(results)
        except Exception as db_err:
            print(f"Warning: Could not write scan to SQLite: {db_err}")

        # Add to history summary
        history_item = {
            "target": clean_name,
            "timestamp": results["scan_timestamp"],
            "score": results["score"]["overall_score"],
            "grade": results["score"]["grade"],
            "total_issues": results["score"]["total_issues"],
            "critical_count": results["score"]["severity_counts"]["CRITICAL"],
            "high_count": results["score"]["severity_counts"]["HIGH"]
        }
        # Avoid duplicate consecutive entries in memory history
        if not any(h["target"] == clean_name and h["timestamp"] == history_item["timestamp"] for h in SCAN_HISTORY):
            SCAN_HISTORY.insert(0, history_item)
            if len(SCAN_HISTORY) > 30:
                SCAN_HISTORY.pop()

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan execution failed: {str(e)}")


@app.get("/api/history")
def get_history():
    # Attempt to read from persistent SQLite first
    db_history = get_recent_scans(limit=30)
    if db_history:
        return {"history": db_history}
    return {"history": SCAN_HISTORY}


@app.get("/api/db/audits")
def get_db_audits():
    """Returns persistent SQLite scan audit logs."""
    return {"audits": get_recent_scans(limit=100)}


@app.get("/api/remediate/{domain}")
async def get_remediations(domain: str):
    clean_domain = engine._clean_target(domain)
    scan_data = SCAN_CACHE.get(clean_domain)
    if not scan_data:
        # Run a quick evaluation to generate remediations
        scan_data = await engine.scan_target(clean_domain)

    remediations = AutoRemediator.generate_all_remediations(clean_domain, scan_data)
    return {"domain": clean_domain, "remediations": remediations}


@app.get("/api/download-fix-pack")
async def download_fix_pack(domain: str = Query(..., description="Target domain for the fix pack")):
    clean_domain = engine._clean_target(domain)
    scan_data = SCAN_CACHE.get(clean_domain)
    if not scan_data:
        scan_data = await engine.scan_target(clean_domain)

    zip_bytes = AutoRemediator.generate_zip_bundle(clean_domain, scan_data)
    filename = f"one-click-shield-{clean_domain}-fixes.zip"

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# Mount static React frontend build if present
from fastapi.staticfiles import StaticFiles
possible_dist_paths = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "dist")),
    "/app/frontend/dist"
]
for dist_path in possible_dist_paths:
    if os.path.exists(dist_path):
        app.mount("/", StaticFiles(directory=dist_path, html=True), name="frontend")
        break


if __name__ == "__main__":
    import uvicorn
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, app_dir=current_dir)
