"""
Basic Antivirus Simulation (Signature Scanner) — with VirusTotal integration.

Detection works in two layers:
  Layer 1 — Local signature DB (signatures.json)  — instant, offline
  Layer 2 — VirusTotal API                        — real threat intelligence
             (requires free API key in virustotal_lookup.py)
"""

import os
import hashlib
import shutil
import json
import time
import datetime
from pathlib import Path

SIGNATURES_DB  = "signatures.json"
QUARANTINE_DIR = "quarantine"
LOG_FILE       = "scan_log.txt"
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
    file_hash = compute_hash(filepath)
    name = label or os.path.basename(filepath)
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
    entry = f"[{timestamp}] {message}"
    with open(LOG_FILE, "a") as log:
        log.write(entry + "\n")
    return entry


def scan_file(filepath: str, signatures: dict, quarantine: bool = False, use_virustotal: bool = False) -> dict:
    """
    Scan a single file.

    Detection order:
      1. Compute SHA-256 hash
      2. Check local signatures.json     (Layer 1 - offline, instant)
      3. If unknown AND use_virustotal   (Layer 2 - real VT intelligence)
      4. Quarantine if threat found
      5. Log the result
    """
    result = {
        "file":             filepath,
        "hash":             None,
        "status":           "CLEAN",
        "threat_name":      None,
        "detection_source": None,
        "vt_result":        None,
        "quarantined_to":   None,
        "error":            None,
    }

    if not os.path.isfile(filepath):
        result["error"]  = "File not found"
        result["status"] = "ERROR"
        return result

    # Step 1: Hash
    file_hash = compute_hash(filepath)
    result["hash"] = file_hash

    # Step 2: Local signature check (Layer 1)
    if file_hash in signatures:
        result["status"]           = "THREAT"
        result["threat_name"]      = signatures[file_hash]["name"]
        result["detection_source"] = "local"
        log_event(f"THREAT DETECTED [LOCAL] | {filepath} | {result['threat_name']} | {file_hash[:16]}...")

    # Step 3: VirusTotal check (Layer 2) - only if not already caught locally
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
                log_event(f"THREAT DETECTED [VT] | {filepath} | {result['threat_name']} | {file_hash[:16]}...")
            else:
                verdict = format_vt_verdict(vt_data)
                log_event(f"CLEAN [VT checked] | {filepath} | {verdict}")

            # Respect free tier rate limit: 4 requests/minute
            if not vt_data.get("cached"):
                time.sleep(VT_RATE_LIMIT_DELAY)

        except ImportError:
            log_event(f"CLEAN [VT skipped] | {filepath}")

    else:
        log_event(f"CLEAN | {filepath} | {file_hash[:16]}...")

    # Step 4: Quarantine if threat
    if result["status"] == "THREAT" and quarantine:
        dest = quarantine_file(filepath)
        result["quarantined_to"] = dest
        log_event(f"QUARANTINED | {filepath} -> {dest}")

    return result


def scan_folder(folder: str, signatures: dict, quarantine: bool = False, use_virustotal: bool = False) -> list:
    """Recursively scan all files in a folder."""
    results     = []
    folder_path = Path(folder)

    if not folder_path.exists():
        print(f"[!] Folder '{folder}' does not exist.")
        return results

    files_only = [f for f in folder_path.rglob("*") if f.is_file()]
    vt_label   = " + VirusTotal" if use_virustotal else ""

    print(f"\n{'='*62}")
    print(f"  Scanning: {folder}  ({len(files_only)} files){vt_label}")
    print(f"{'='*62}")

    threats = 0
    for filepath in files_only:
        if QUARANTINE_DIR in str(filepath):
            continue

        result = scan_file(str(filepath), signatures, quarantine=quarantine, use_virustotal=use_virustotal)
        results.append(result)

        if result["status"] == "THREAT":
            icon   = "[THREAT]"
            src    = result.get("detection_source", "?").upper()
            label  = f"THREAT [{src}] {result['threat_name']}"
            threats += 1
        elif result["status"] == "ERROR":
            icon  = "[ERROR]"
            label = f"ERROR: {result['error']}"
        else:
            icon  = "[CLEAN]"
            label = "CLEAN"
            if result.get("vt_result") and result["vt_result"].get("found"):
                vt = result["vt_result"]
                label += f" (VT: 0/{vt.get('total', '?')})"

        hash_preview = result["hash"][:16] + "..." if result["hash"] else "N/A"
        print(f"  {icon}  {label:<52}  {hash_preview}  {filepath.name}")

        if result["status"] == "THREAT" and result["quarantined_to"]:
            print(f"       -> Quarantined to: {result['quarantined_to']}")

    print(f"\n{'-'*62}")
    print(f"  Scan complete. Files: {len(results)}  |  Threats: {threats}")
    print(f"{'-'*62}\n")
    return results


def print_report(results: list):
    """Print a summary report of the scan."""
    total   = len(results)
    threats = [r for r in results if r["status"] == "THREAT"]
    clean   = [r for r in results if r["status"] == "CLEAN"]
    errors  = [r for r in results if r["status"] == "ERROR"]
    local   = [r for r in threats if r.get("detection_source") == "local"]
    vt_hits = [r for r in threats if r.get("detection_source") == "virustotal"]

    print("\n" + "=" * 62)
    print("  SCAN REPORT")
    print("=" * 62)
    print(f"  Total files scanned      : {total}")
    print(f"  Clean                    : {len(clean)}")
    print(f"  Threats found            : {len(threats)}")
    print(f"    -> Caught by local DB  : {len(local)}")
    print(f"    -> Caught by VT        : {len(vt_hits)}")
    print(f"  Errors                   : {len(errors)}")

    if threats:
        print("\n  Detected threats:")
        for r in threats:
            src = r.get("detection_source", "?").upper()
            q   = f" -> quarantined to {r['quarantined_to']}" if r["quarantined_to"] else ""
            print(f"    [{src}] {r['file']}  |  {r['threat_name']}{q}")

    print("=" * 62 + "\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Basic Antivirus Simulation - Signature Scanner + VirusTotal")
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="Scan a file or folder")
    scan_p.add_argument("target", help="File or folder to scan")
    scan_p.add_argument("--quarantine", "-q", action="store_true", help="Move threats to quarantine")
    scan_p.add_argument("--virustotal", "-vt", action="store_true", help="Also check VirusTotal API")

    sig_p = subparsers.add_parser("add-sig", help="Add a file hash to signature DB")
    sig_p.add_argument("file", help="File to add")
    sig_p.add_argument("--label", "-l", help="Threat label")

    subparsers.add_parser("list-sigs", help="List all signatures")
    subparsers.add_parser("setup-demo", help="Create demo environment")

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
            print(f"\n{'-'*62}")
            print(f"  Signature Database  ({len(sigs)} entries)")
            print(f"{'-'*62}")
            for h, info in sigs.items():
                print(f"  {h[:32]}...  ->  {info['name']}")
            print(f"{'-'*62}\n")

    elif args.command == "scan":
        signatures = load_signatures(SIGNATURES_DB)
        use_vt     = getattr(args, "virustotal", False)
        target     = args.target

        if use_vt:
            print("[*] VirusTotal mode ON — unknown files will be checked online")
            print("[*] Free tier: 4 lookups/min. Scanning may be slower.\n")

        if os.path.isdir(target):
            results = scan_folder(target, signatures, args.quarantine, use_vt)
        else:
            result  = scan_file(target, signatures, args.quarantine, use_vt)
            results = [result]
            icon    = "[THREAT]" if result["status"] == "THREAT" else "[CLEAN]"
            print(f"\n{icon} {result['status']} - {result['file']}")
            if result["threat_name"]:
                print(f"   Threat : {result['threat_name']}  [{result.get('detection_source','?').upper()}]")
            if result["quarantined_to"]:
                print(f"   Quarantined to: {result['quarantined_to']}")

        print_report(results)

    else:
        parser.print_help()
