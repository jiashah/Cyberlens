import json
import os
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fastapi import FastAPI, File, HTTPException, Request, UploadFile  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from run_pipeline import ScanError, analyze_scan, load_assets  # noqa: E402
from project_config import config_fingerprint  # noqa: E402

MAX_UPLOAD_BYTES = int(os.environ.get("CYBERLENS_MAX_UPLOAD_MB", "10")) * 1024 * 1024
CHECKPOINT = os.environ.get("CYBERLENS_CHECKPOINT")

app = FastAPI(title="CyberLens", version="1.0")


@lru_cache(maxsize=1)
def assets():
    return load_assets(CHECKPOINT)


def _analyze(scan, name):
    try:
        return analyze_scan(scan, name, assets())
    except ScanError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.get("/health")
def health():
    a = assets()
    return {"status": "ok", "encoder": a["ck"]["hparams"]["encoder"], "datasets_trained_on": len(a["ck"]["datasets"]),
            "score_config_fingerprint": config_fingerprint(a["cfg"]),
            "config_matches_checkpoint": a["ck"]["score_config_fingerprint"] == config_fingerprint(a["cfg"]),
            "link_suggestions": a["link_model"] is not None}


@app.post("/analyze")
async def analyze(request: Request, name: str = "scan"):
    raw = await request.body()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="scan too large")
    try:
        scan = json.loads(raw)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=422, detail=f"body is not valid JSON: {e}")
    return _analyze(scan, name)


@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="scan too large")
    try:
        scan = json.loads(raw)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=422, detail=f"file is not valid JSON: {e}")
    return _analyze(scan, Path(file.filename or "scan").stem)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("CYBERLENS_HOST", "127.0.0.1"), port=int(os.environ.get("CYBERLENS_PORT", "8000")))
