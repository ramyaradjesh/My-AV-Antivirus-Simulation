"""
Basic Antivirus Simulation — Three-Layer Detection Engine

Layer 1 — Local signature DB     (signatures.json)   offline, instant
Layer 2 — VirusTotal API         (virustotal_lookup)  real cloud intelligence
Layer 3 — Heuristic Detection    (heuristics.py)      catches new/unknown threats
"""

import os
import hashlib
import shutil
import json
import time
import datetime
from pathlib import Path

SIGNATURES_DB       = "signatures.json"
QUARANTINE_DIR      = "quarantine"
LOG_FILE            = "scan_log.txt"
VT_RATE_LIMIT_DELAY = 15


def compute_hash(filepath: str, algorithm: str = "sha256") -> str:
    """Compute the cryptographic hash of a file."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError) as e:
        return f"ERROR: {e}"


def load_signatures(db_path: str) -> dict:
    """Load known malware signatures from the JSON database."""
    if not os.path.exists(db_path):
        print(f"[!] Signature database '{db_path}' not found. Creating empty DB.")
        return {}
    with open(db_path, "r") as f:
        return json.load(f)


def save_signatures(db_path: str, signatures: dict):
    """Save the signature database to disk."""
    with open(db_path, "w") as f:
        json.dump(signatures, f, indent=2)
    print(f"[+] Signature database saved to '{db_path}'.")


def add_signature(db_path: str, filepath: str, label: str = None):
    """Add a file's hash to the malware signature database."""
    signatures = load_signatures(db_path)
    file_hash  = compute_hash(filepath)
    name       = label or os.path.basename(filepath)
    signatures[file_hash] = {"name": name, "added": str(datetime.datetime.now())}
    save_signatures(db_path, signatures)
    print(f"[+] Added signature: {file_hash[:16]}...  ->  '{name}'")


def quarantine_file(filepath: str) -> str:
    """Move a detected malicious file to the quarantine folder."""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    dest = os.path.join(QUARANTINE_DIR, os.path.basename(filepath))
    if os.path.exists(dest):
        base, ext = os.path.splitext(dest)
        dest = f"{base}_{int(datetime.datetime.now().timestamp())}{ext}"
    shutil.move(filepath, dest)
    return dest


def log_event(message: str) -> str:
    """Append a timestamped entry to the scan log."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry     = f"[{timestamp}] {message}"
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(entry + "\n")
    return entry


def scan_file(
    filepath: str,
    signatures: dict,
    quarantine: bool       = False,
    use_virustotal: bool   = False,
    use_heuristics: bool   = True,
    send_email: bool       = False,
) -> dict:
    """
    Scan a single file through all three detection layers.

    Layer 1 — Local signatures.json     (offline, instant)
    Layer 2 — VirusTotal API            (cloud, requires key)
    Layer 3 — Heuristic engine          (pattern-based, no signature needed)

    Returns a full result dictionary.
    """
    result = {
        "file":             filepath,
        "hash":             None,
        "status":           "CLEAN",
        "threat_name":      None,
        "detection_source": None,
        "vt_result":        None,
        "heuristic_result": None,
        "quarantined_to":   None,
        "error":            None,
    }

    if not os.path.isfile(filepath):
        result["error"]  = "File not found"
        result["status"] = "ERROR"
        return result

    # ── Step 1: Hash the file ─────────────────────────────────────────────────
    file_hash    = compute_hash(filepath)
    result["hash"] = file_hash

    # ── Step 2: Layer 1 — Local signature DB ──────────────────────────────────
    if file_hash in signatures:
        result["status"]           = "THREAT"
        result["threat_name"]      = signatures[file_hash]["name"]
        result["detection_source"] = "local"
        log_event(f"THREAT [L1-LOCAL] | {filepath} | {result['threat_name']} | {file_hash[:16]}...")

    # ── Step 3: Layer 2 — VirusTotal API ─────────────────────────────────────
    elif use_virustotal:
        try:
            from virustotal_lookup import is_vt_threat, format_vt_verdict
            is_threat, vt_data = is_vt_threat(file_hash)
            result["vt_result"] = vt_data

            if is_threat:
                m = vt_data.get("malicious", 0)
                t = vt_data.get("total", 0)
                result["status"]           = "THREAT"
                result["threat_name"]      = f"VirusTotal ({m}/{t} engines flagged)"
                result["detection_source"] = "virustotal"
                log_event(f"THREAT [L2-VT] | {filepath} | {result['threat_name']} | {file_hash[:16]}...")
            else:
                log_event(f"CLEAN [L2-VT] | {filepath} | {format_vt_verdict(vt_data)}")

            if not vt_data.get("cached"):
                time.sleep(VT_RATE_LIMIT_DELAY)

        except ImportError:
            log_event(f"CLEAN [L2-VT skipped] | {filepath}")

    else:
        log_event(f"CLEAN [L1 only] | {filepath} | {file_hash[:16]}...")

    # ── Step 4: Layer 3 — Heuristic Detection ────────────────────────────────
    # Runs on ALL files regardless of Layer 1/2 result
    # Even a THREAT file gets heuristic results for the report
    if use_heuristics:
        try:
            from heuristics import run_heuristics
            h_result = run_heuristics(filepath)
            result["heuristic_result"] = h_result

            if h_result["status"] == "SUSPICIOUS":
                log_event(f"SUSPICIOUS [L3-HEURISTIC] | {filepath} | {h_result['summary']}")

                # Only upgrade to SUSPICIOUS if not already a confirmed THREAT
                if result["status"] == "CLEAN":
                    result["status"]           = "SUSPICIOUS"
                    result["threat_name"]      = h_result["summary"]
                    result["detection_source"] = "heuristic"

                # Send suspicious email alert
                if send_email:
                    try:
                        from email_alert import send_suspicious_alert
                        send_suspicious_alert(filepath, h_result["findings"])
                    except ImportError:
                        pass

        except ImportError:
            pass

    # ── Step 5: Send threat email alert ──────────────────────────────────────
    if result["status"] == "THREAT" and send_email:
        try:
            from email_alert import send_threat_alert
            send_threat_alert(
                filepath         = filepath,
                threat_name      = result["threat_name"],
                detection_source = result["detection_source"],
                file_hash        = file_hash,
            )
        except ImportError:
            pass

    # ── Step 6: Quarantine confirmed threats ──────────────────────────────────
    # SUSPICIOUS files are NOT auto-quarantined — user decides
    if result["status"] == "THREAT" and quarantine:
        dest = quarantine_file(filepath)
        result["quarantined_to"] = dest
        log_event(f"QUARANTINED | {filepath} -> {dest}")

    return result


def scan_folder(
    folder: str,
    signatures: dict,
    quarantine: bool      = False,
    use_virustotal: bool  = False,
    use_heuristics: bool  = True,
    send_email: bool      = False,
) -> list:
    """Recursively scan all files in a folder through all detection layers."""
    results     = []
    folder_path = Path(folder)

    if not folder_path.exists():
        print(f"[!] Folder '{folder}' does not exist.")
        return results

    files_only = [f for f in folder_path.rglob("*") if f.is_file()]

    layers = []
    if use_virustotal:  layers.append("VirusTotal")
    if use_heuristics:  layers.append("Heuristics")
    layer_label = " + " + " + ".join(layers) if layers else ""

    print(f"\n{'='*64}")
    print(f"  Scanning: {folder}  ({len(files_only)} files){layer_label}")
    print(f"{'='*64}")

    threats    = 0
    suspicious = 0

    for filepath in files_only:
        if QUARANTINE_DIR in str(filepath):
            continue

        result = scan_file(
            str(filepath), signatures,
            quarantine     = quarantine,
            use_virustotal = use_virustotal,
            use_heuristics = use_heuristics,
            send_email     = send_email,
        )
        results.append(result)

        # ── Print per-file result ─────────────────────────────────────────────
        if result["status"] == "THREAT":
            src   = result.get("detection_source", "?").upper()
            label = f"THREAT [{src}] {result['threat_name']}"
            icon  = "[THREAT]    "
            threats += 1
        elif result["status"] == "SUSPICIOUS":
            label = f"SUSPICIOUS  {result['threat_name'][:45]}"
            icon  = "[SUSPICIOUS]"
            suspicious += 1
        elif result["status"] == "ERROR":
            label = f"ERROR: {result['error']}"
            icon  = "[ERROR]     "
        else:
            icon  = "[CLEAN]     "
            label = "CLEAN"
            if result.get("vt_result") and result["vt_result"].get("found"):
                label += f" (VT: 0/{result['vt_result'].get('total','?')})"

        hash_preview = result["hash"][:16] + "..." if result["hash"] else "N/A"
        print(f"  {icon}  {label:<50}  {hash_preview}  {filepath.name}")

        if result["status"] == "THREAT" and result["quarantined_to"]:
            print(f"               -> Quarantined: {result['quarantined_to']}")

        # Show heuristic findings inline
        h = result.get("heuristic_result")
        if h and h.get("findings") and result["status"] != "THREAT":
            for f in h["findings"]:
                print(f"               [{f['severity']}] {f['reason']}")

    print(f"\n{'-'*64}")
    print(f"  Scan complete. Files: {len(results)}  |  Threats: {threats}  |  Suspicious: {suspicious}")
    print(f"{'-'*64}\n")
    return results


def print_report(results: list):
    """Print a full summary report."""
    total      = len(results)
    threats    = [r for r in results if r["status"] == "THREAT"]
    suspicious = [r for r in results if r["status"] == "SUSPICIOUS"]
    clean      = [r for r in results if r["status"] == "CLEAN"]
    errors     = [r for r in results if r["status"] == "ERROR"]
    local      = [r for r in threats if r.get("detection_source") == "local"]
    vt_hits    = [r for r in threats if r.get("detection_source") == "virustotal"]
    heur_hits  = [r for r in threats if r.get("detection_source") == "heuristic"]

    print("\n" + "=" * 64)
    print("  SCAN REPORT — Three-Layer Detection")
    print("=" * 64)
    print(f"  Total files scanned          : {total}")
    print(f"  Clean                        : {len(clean)}")
    print(f"  Threats (confirmed)          : {len(threats)}")
    print(f"    -> Layer 1 Local DB        : {len(local)}")
    print(f"    -> Layer 2 VirusTotal      : {len(vt_hits)}")
    print(f"    -> Layer 3 Heuristic       : {len(heur_hits)}")
    print(f"  Suspicious (heuristic flags) : {len(suspicious)}")
    print(f"  Errors                       : {len(errors)}")

    if threats:
        print("\n  Confirmed threats:")
        for r in threats:
            src = r.get("detection_source", "?").upper()
            q   = f" -> quarantined" if r["quarantined_to"] else ""
            print(f"    [{src}] {r['file']} | {r['threat_name']}{q}")

    if suspicious:
        print("\n  Suspicious files (review manually):")
        for r in suspicious:
            h = r.get("heuristic_result", {})
            for f in h.get("findings", []):
                print(f"    [{f['severity']}] {r['file']}")
                print(f"           {f['reason']}")

    print("=" * 64 + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="MyAV — Three-Layer Antivirus: Local + VirusTotal + Heuristics"
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="Scan a file or folder")
    scan_p.add_argument("target")
    scan_p.add_argument("--quarantine",   "-q",  action="store_true")
    scan_p.add_argument("--virustotal",   "-vt", action="store_true")
    scan_p.add_argument("--no-heuristics",       action="store_true", help="Disable Layer 3")
    scan_p.add_argument("--email",               action="store_true", help="Send email alerts")

    sig_p = subparsers.add_parser("add-sig")
    sig_p.add_argument("file")
    sig_p.add_argument("--label", "-l")

    subparsers.add_parser("list-sigs")
    subparsers.add_parser("setup-demo")

    args = parser.parse_args()

    if args.command == "setup-demo":
        from demo_setup import create_demo_environment
        create_demo_environment()

    elif args.command == "add-sig":
        add_signature(SIGNATURES_DB, args.file, args.label)

    elif args.command == "list-sigs":
        sigs = load_signatures(SIGNATURES_DB)
        if not sigs:
            print("[i] No signatures in database.")
        else:
            print(f"\n{'-'*64}")
            for h, info in sigs.items():
                print(f"  {h[:32]}...  ->  {info['name']}")
            print(f"{'-'*64}\n")

    elif args.command == "scan":
        signatures    = load_signatures(SIGNATURES_DB)
        use_vt        = getattr(args, "virustotal", False)
        use_heur      = not getattr(args, "no_heuristics", False)
        do_email      = getattr(args, "email", False)

        print(f"[*] Layers active: L1-Local  |  {'L2-VirusTotal  |  ' if use_vt else ''}{'L3-Heuristics' if use_heur else ''}")

        if os.path.isdir(args.target):
            results = scan_folder(
                args.target, signatures,
                quarantine     = args.quarantine,
                use_virustotal = use_vt,
                use_heuristics = use_heur,
                send_email     = do_email,
            )
        else:
            result  = scan_file(
                args.target, signatures,
                quarantine     = args.quarantine,
                use_virustotal = use_vt,
                use_heuristics = use_heur,
                send_email     = do_email,
            )
            results = [result]
            print(f"\n[{result['status']}] {result['file']}")
            if result["threat_name"]:
                print(f"  -> {result['threat_name']}  [{result.get('detection_source','?').upper()}]")
            h = result.get("heuristic_result")
            if h and h.get("findings"):
                for f in h["findings"]:
                    print(f"  -> [{f['severity']}] {f['reason']}")

        print_report(results)

    else:
        parser.print_help()
