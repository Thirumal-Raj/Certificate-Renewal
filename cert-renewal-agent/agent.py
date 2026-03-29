"""
Certificate Renewal Agent — Main Orchestrator (polling mode)

Runs continuously, checking Gmail every POLL_INTERVAL_SECS seconds.
Only processes emails the agent has not seen before (tracked by Message-ID
in seen_emails.json). Already-processed emails are never re-processed,
regardless of their read/unread status in Gmail.

Flow per poll cycle:
  1. Load seen Message-IDs from seen_emails.json
  2. Fetch Gmail for certificate attachments, skip already-seen emails
  3. Check each new certificate's expiry date
  4. Install certs that are expired or within warn threshold
  5. Save updated seen Message-IDs
  6. Sleep until next poll

Connector modes (set as2.mode in config.yaml):
  local    — no server needed; stores certs locally (default)
  openas2  — connects to a running OpenAS2 server

Environment variables required:
  GMAIL_APP_PASSWORD      — 16-char Gmail App Password
  AS2_API_PASSWORD        — OpenAS2 REST API password (if mode: openas2)
  AS2_KEYSTORE_PASSWORD   — JKS keystore password (default: changeit)
"""
import json
import logging
import signal
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from gmail_reader import GmailReader
from cert_checker import CertChecker
from cert_renewer import CertRenewer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

POLL_INTERVAL_SECS = 60


def load_config(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def load_seen_ids(path: Path) -> set:
    if path.exists():
        try:
            return set(json.loads(path.read_text()))
        except Exception:
            pass
    return set()


def save_seen_ids(path: Path, seen_ids: set) -> None:
    path.write_text(json.dumps(sorted(seen_ids), indent=2))


def run_once(config: dict, seen_ids: set) -> set:
    """
    Run a single poll cycle. Returns the updated seen_ids set.
    """
    warn_days = config["app"].get("cert_expiry_warn_days", 30)

    # ── Step 1: Download new cert attachments from Gmail ─────────────
    log.info("Step 1/3 — Checking Gmail for new certificate attachments …")
    reader = GmailReader(config)
    try:
        downloaded, new_seen_ids = reader.run(seen_ids=seen_ids)
    except EnvironmentError as e:
        log.error(str(e))
        return seen_ids
    except RuntimeError as e:
        log.error(str(e))
        return seen_ids

    # Always record the newly seen IDs even if no attachments were found
    updated_seen_ids = seen_ids | new_seen_ids

    if not downloaded:
        log.info("No new certificate attachments found.")
        return updated_seen_ids

    # ── Step 2: Check certificate expiry ─────────────────────────────
    log.info("Step 2/3 — Checking certificate expiry …")
    checker = CertChecker()
    cert_paths = [d["path"] for d in downloaded]
    results = checker.check_all(cert_paths)

    as2_id_map = {d["path"]: d["as2_id"] for d in downloaded}
    for r in results:
        r["as2_id"] = as2_id_map.get(r["path"])

    if not results:
        log.warning("No parseable certificates found among downloaded files.")
        return updated_seen_ids

    for info in results:
        if info["expired"]:
            status = "EXPIRED"
        else:
            status = f"expires in {info['days_remaining']} day(s)  [{info['expiry_date']}]"
        log.info(f"  {info['path'].name}: {status}")

    # ── Step 3: Install certs that are near expiry or expired ─────────
    mode = config.get("as2", {}).get("mode", "local")
    if mode == "openas2":
        from as2_connector.openas2 import OpenAS2Connector
        connector = OpenAS2Connector(config)
        log.info("Step 3/3 — Installing certificates to OpenAS2 server …")
    else:
        from as2_connector.local_store import LocalCertStore
        connector = LocalCertStore(config)
        log.info("Step 3/3 — Installing certificates to local cert store …")
    renewer = CertRenewer(config, connector)

    known_as2_ids = connector.get_known_as2_ids()
    known_as2_id_values = set(known_as2_ids.values())
    log.info(f"  Known AS2 IDs in OpenAS2: {sorted(known_as2_id_values)}")

    renewed, skipped = [], []
    renewed_partners = set()
    for info in results:
        if info["expired"] or info["days_remaining"] <= warn_days:
            email_as2_id = info.get("as2_id")
            if not email_as2_id:
                log.warning(
                    f"  Skipping {info['path'].name} — no AS2 ID found in email body."
                )
                skipped.append(info)
                continue
            if email_as2_id not in known_as2_id_values:
                log.warning(
                    f"  Skipping {info['path'].name} — AS2 ID '{email_as2_id}' "
                    f"does not match any known partner in OpenAS2."
                )
                skipped.append(info)
                continue
            matched_partner = next(
                name for name, aid in known_as2_ids.items() if aid == email_as2_id
            )
            if matched_partner in renewed_partners:
                log.info(
                    f"  Skipping {info['path'].name} — partner '{matched_partner}' "
                    f"already renewed in this run."
                )
                skipped.append(info)
                continue
            log.info(
                f"  AS2 ID '{email_as2_id}' matched partner '{matched_partner}'. "
                f"Proceeding with renewal."
            )
            try:
                renewer.install(info["path"], info, partner_name=matched_partner)
                renewed.append(info["path"])
                renewed_partners.add(matched_partner)
            except Exception as e:
                log.error(f"  Failed to install {info['path'].name}: {e}")
        else:
            skipped.append(info)
            log.info(f"  Skipping {info['path'].name} — {info['days_remaining']} days remaining.")

    # ── Summary ───────────────────────────────────────────────────────
    log.info("-" * 50)
    log.info(f"  Downloaded : {len(downloaded)} attachment(s)")
    log.info(f"  Checked    : {len(results)} certificate(s)")
    log.info(f"  Installed  : {len(renewed)} certificate(s)")
    log.info(f"  Skipped    : {len(skipped)} certificate(s)")
    if renewed:
        for p in renewed:
            log.info(f"    ✓ {p.name}")

    return updated_seen_ids


def main():
    config_path = Path(__file__).parent / "config.yaml"
    seen_ids_path = Path(__file__).parent / "seen_emails.json"

    config = load_config(config_path)
    seen_ids = load_seen_ids(seen_ids_path)

    # Graceful shutdown on SIGINT / SIGTERM
    stop = {"flag": False}

    def _handle_signal(signum, frame):
        log.info("Shutdown signal received — stopping after current cycle.")
        stop["flag"] = True

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    log.info("=" * 50)
    log.info("  Certificate Renewal Agent  (polling mode)")
    log.info(f"  Poll interval : {POLL_INTERVAL_SECS}s")
    log.info(f"  Seen IDs file : {seen_ids_path}")
    log.info(f"  Already seen  : {len(seen_ids)} email(s)")
    log.info("=" * 50)

    while not stop["flag"]:
        log.info("=" * 50)
        log.info("  Starting poll cycle …")
        log.info("=" * 50)
        try:
            seen_ids = run_once(config, seen_ids)
            save_seen_ids(seen_ids_path, seen_ids)
        except Exception as e:
            log.error(f"Unexpected error in poll cycle: {e}", exc_info=True)

        if stop["flag"]:
            break

        next_run = datetime.now() + timedelta(seconds=POLL_INTERVAL_SECS)
        log.info(f"Next poll at {next_run.strftime('%H:%M:%S')} (in {POLL_INTERVAL_SECS}s) — Ctrl+C to stop")
        for _ in range(POLL_INTERVAL_SECS):
            if stop["flag"]:
                break
            time.sleep(1)

    log.info("Certificate Renewal Agent stopped.")


if __name__ == "__main__":
    main()
