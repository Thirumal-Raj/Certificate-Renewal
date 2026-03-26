"""
Certificate Renewal Agent — Main Orchestrator

Flow:
  1. Read Gmail for certificate attachments
  2. Check each certificate's expiry date
  3. Install certs that are expired or within warn threshold
  4. Reload config
  5. Print summary report

Connector modes (set as2.mode in config.yaml):
  local    — no server needed; stores certs locally (default)
  openas2  — connects to a running OpenAS2 server

Environment variables required:
  GMAIL_APP_PASSWORD      — 16-char Gmail App Password
  AS2_API_PASSWORD        — OpenAS2 REST API password (if mode: openas2)
  AS2_KEYSTORE_PASSWORD   — JKS keystore password (default: changeit)
"""
import logging
import sys
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


def load_config(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    log.info("=" * 50)
    log.info("  Certificate Renewal Agent")
    log.info("=" * 50)

    config_path = Path(__file__).parent / "config.yaml"
    config = load_config(config_path)
    warn_days = config["app"].get("cert_expiry_warn_days", 30)

    # ── Step 1: Download cert attachments from Gmail ──────────────────
    log.info("Step 1/3 — Checking Gmail for certificate attachments …")
    reader = GmailReader(config)
    try:
        downloaded = reader.run()
    except EnvironmentError as e:
        log.error(str(e))
        sys.exit(1)
    except RuntimeError as e:
        log.error(str(e))
        sys.exit(1)

    if not downloaded:
        log.info("No certificate attachments found. Nothing to do.")
        return

    # ── Step 2: Check certificate expiry ─────────────────────────────
    log.info("Step 2/3 — Checking certificate expiry …")
    checker = CertChecker()
    results = checker.check_all(downloaded)

    if not results:
        log.warning("No parseable certificates found among downloaded files.")
        return

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

    renewed, skipped = [], []
    for info in results:
        if info["expired"] or info["days_remaining"] <= warn_days:
            try:
                renewer.install(info["path"], info)
                renewed.append(info["path"])
            except Exception as e:
                log.error(f"  Failed to install {info['path'].name}: {e}")
        else:
            skipped.append(info)
            log.info(f"  Skipping {info['path'].name} — {info['days_remaining']} days remaining.")

    # ── Summary ───────────────────────────────────────────────────────
    log.info("=" * 50)
    log.info("  Summary")
    log.info("=" * 50)
    log.info(f"  Downloaded : {len(downloaded)} attachment(s)")
    log.info(f"  Checked    : {len(results)} certificate(s)")
    log.info(f"  Installed  : {len(renewed)} certificate(s)")
    log.info(f"  Skipped    : {len(skipped)} certificate(s) (still valid)")
    if renewed:
        for p in renewed:
            log.info(f"    ✓ {p.name}")


if __name__ == "__main__":
    main()
