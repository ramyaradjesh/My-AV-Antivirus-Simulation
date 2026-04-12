"""
virustotal_lookup.py — Real threat intelligence via VirusTotal API v3.

How to get your FREE API key:
  1. Go to https://www.virustotal.com
  2. Click "Join our community" and sign up
  3. Click your username (top right) → "API key"
  4. Paste your key below where it says PASTE_YOUR_KEY_HERE

Free tier limits:
  - 4 lookups per minute
  - 500 lookups per day
  - 15,500 lookups per month
"""

import time
import json
import os

# ── Paste your VirusTotal API key here ───────────────────────────────────────
VT_API_KEY = "PASTE_YOUR_KEY_HERE"

# ── VirusTotal API endpoint ───────────────────────────────────────────────────
VT_URL = "https://www.virustotal.com/api/v3/files/{}"

# ── Cache file — avoids re-querying the same hash repeatedly ─────────────────
VT_CACHE_FILE = "vt_cache.json"

# ── How many AV engines must flag it before we call it a THREAT ──────────────
VT_THRESHOLD = 3


def _load_cache() -> dict:
    """Load previously queried hashes from local cache."""
    if os.path.exists(VT_CACHE_FILE):
        try:
            with open(VT_CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_cache(cache: dict):
    """Save cache to disk so we don't re-query the same hash."""
    with open(VT_CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def check_virustotal(file_hash: str, use_cache: bool = True) -> dict:
    """
    Send a SHA-256 hash to VirusTotal and return the analysis result.

    Returns a dict:
      {
        "found":       True/False  — whether VT has seen this hash before
        "malicious":   int         — how many AV engines flagged it
        "suspicious":  int         — how many flagged it as suspicious
        "total":       int         — total engines that scanned it
        "cached":      True/False  — whether this came from local cache
        "error":       str or None — any error message
      }
    """
    # ── Check cache first to avoid wasting API quota ──────────────────────────
    if use_cache:
        cache = _load_cache()
        if file_hash in cache:
            result = cache[file_hash].copy()
            result["cached"] = True
            return result

    # ── No API key set ────────────────────────────────────────────────────────
    if VT_API_KEY == "PASTE_YOUR_KEY_HERE" or not VT_API_KEY.strip():
        return {
            "found": False,
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
            "cached": False,
            "error": "No API key set. Edit VT_API_KEY in virustotal_lookup.py",
        }

    # ── Make the API request ──────────────────────────────────────────────────
    try:
        import urllib.request
        import urllib.error

        req = urllib.request.Request(
            VT_URL.format(file_hash),
            headers={"x-apikey": VT_API_KEY, "Accept": "application/json"},
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        stats = data["data"]["attributes"]["last_analysis_stats"]
        result = {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()),
            "cached": False,
            "error": None,
        }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Hash genuinely not in VT database yet
            result = {
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "total": 0,
                "cached": False,
                "error": None,
            }
        elif e.code == 429:
            result = {
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "total": 0,
                "cached": False,
                "error": "Rate limit hit (4/min). Wait 60 seconds.",
            }
        else:
            result = {
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "total": 0,
                "cached": False,
                "error": f"HTTP {e.code}: {str(e)}",
            }

    except Exception as e:
        result = {
            "found": False,
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
            "cached": False,
            "error": str(e),
        }

    # ── Save to cache ─────────────────────────────────────────────────────────
    if use_cache and result["error"] is None:
        cache = _load_cache()
        cache[file_hash] = {k: v for k, v in result.items() if k != "cached"}
        _save_cache(cache)

    return result


def is_vt_threat(file_hash: str, threshold: int = VT_THRESHOLD) -> tuple:
    """
    Returns (is_threat: bool, result: dict).
    A file is a threat if threshold or more AV engines flagged it.
    Default threshold = 3 to avoid false positives from noisy engines.
    """
    result = check_virustotal(file_hash)
    is_threat = result.get("malicious", 0) >= threshold
    return is_threat, result


def format_vt_verdict(result: dict) -> str:
    """Return a human-readable VT verdict string for display."""
    if result.get("error"):
        return f"VT error: {result['error']}"
    if not result.get("found"):
        return "Not in VirusTotal database"
    m = result.get("malicious", 0)
    t = result.get("total", 0)
    cached = " (cached)" if result.get("cached") else ""
    return f"VirusTotal: {m}/{t} engines flagged as malicious{cached}"
