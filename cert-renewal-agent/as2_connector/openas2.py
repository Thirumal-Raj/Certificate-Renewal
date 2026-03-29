"""
OpenAS2 Connector — renews partner certificates in an OpenAS2 server.

Renewal flow (correct approach):
  1. Look up partner's EXISTING x509_alias from partnerships.xml
  2. Stop OpenAS2 server
  3. Backup keystore
  4. Delete old cert under that alias from keystore
  5. Import new cert under the SAME alias
  6. partnerships.xml is NOT changed (alias stays the same)
  7. Restart OpenAS2 server

partnerships.xml is only updated when a partner has no alias yet (first-time setup).

Environment variables:
  AS2_API_PASSWORD        — password for the REST API (partner/cert listing)
  AS2_KEYSTORE_PASSWORD   — PKCS12 keystore password (default: changeit)
"""

import logging
import os
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

log = logging.getLogger(__name__)


class OpenAS2Connector:
    def __init__(self, config: dict):
        as2_cfg = config.get("as2", {})
        self.host = as2_cfg.get("host", "localhost")
        self.port = as2_cfg.get("port", 10080)
        self.api_enabled = as2_cfg.get("api_enabled", False)
        self.api_base = as2_cfg.get("api_base_url", f"http://{self.host}:{self.port}/api")
        self.api_username = as2_cfg.get("api_username", "admin")
        self.api_password = os.environ.get("AS2_API_PASSWORD", as2_cfg.get("api_password", ""))

        self.config_dir = Path(as2_cfg.get("config_dir", "/opt/openas2/config"))
        self.partners_file = self.config_dir / as2_cfg.get("partners_file", "partnerships.xml")
        self.keystore_path = Path(as2_cfg.get("keystore_path", self.config_dir / "as2_certs.p12"))
        self.keystore_password = os.environ.get(
            "AS2_KEYSTORE_PASSWORD",
            as2_cfg.get("keystore_password", "changeit") or "changeit",
        )

        # bin dir is one level up from config dir (e.g. .../OpenAS2Server-x.x.x/bin)
        self.bin_dir = Path(as2_cfg.get("bin_dir", self.config_dir.parent / "bin"))

        self.partner_cfg = as2_cfg.get("partner", {})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_partner_cert(self, cert_path: Path, partner_name: str = None, alias: str = None) -> bool:
        """
        Renew a partner's certificate using the correct replace-in-place flow:
          1. Resolve the alias — reuse existing alias from partnerships.xml
          2. Stop server
          3. Backup keystore
          4. Delete old cert under that alias
          5. Import new cert under the SAME alias
          6. Update partnerships.xml only if partner had no alias (first-time)
          7. Restart server
        Returns True on success.
        """
        partner_name = partner_name or self.partner_cfg.get("name", "partner")

        # Always reuse the existing alias so partnerships.xml stays unchanged
        existing_alias = self._get_partner_existing_alias(partner_name)
        use_alias = existing_alias or alias or cert_path.stem

        log.info(f"[as2] Renewing cert for '{partner_name}' — alias: '{use_alias}' …")
        if existing_alias:
            log.info(f"[as2] Reusing existing alias '{existing_alias}' — partnerships.xml will not change.")
        else:
            log.info(f"[as2] No existing alias found — will set x509_alias='{use_alias}' in partnerships.xml.")

        # Backup keystore before any changes
        self._backup_keystore()

        # Stop server so keystore can be safely modified
        self._stop_server()

        try:
            # Remove old cert, import new one under the SAME alias
            self._delete_keystore_alias(use_alias)
            self.import_cert_to_keystore(cert_path, use_alias)

            # Only touch partnerships.xml for brand-new partners with no alias yet
            if existing_alias is None:
                self._set_partner_alias_in_xml(partner_name, use_alias)

            return True

        except Exception as e:
            raise RuntimeError(f"Cert renewal failed for '{partner_name}': {e}") from e

        finally:
            # Always restart server — even if import failed
            self._start_server()

    def get_known_as2_ids(self) -> dict:
        """
        Return {partner_name: as2_id} for all partners.
        Tries REST API first, falls back to partnerships.xml.
        """
        if self.api_enabled and self.api_base:
            result = self._fetch_as2_ids_via_api()
            if result is not None:
                return result
        return self._fetch_as2_ids_from_xml()

    def reload_config(self) -> bool:
        """Ask OpenAS2 to reload its configuration after a cert update."""
        if self.api_enabled and self.api_base:
            try:
                import requests
                auth = (self.api_username, self.api_password) if self.api_password else None
                resp = requests.post(f"{self.api_base}/reload", auth=auth, timeout=10)
                if resp.ok:
                    log.info("[as2] Config reloaded via REST API.")
                    return True
            except Exception as e:
                log.warning(f"[as2] Reload via API failed: {e}")

        return self._reload_via_signal()

    def import_cert_to_keystore(self, cert_path: Path, alias: str) -> bool:
        """Import a PEM/DER cert into the PKCS12 keystore using keytool."""
        if not shutil.which("keytool"):
            log.warning("[as2] keytool not found — skipping keystore import.")
            return False

        cmd = [
            "keytool", "-importcert",
            "-noprompt",
            "-alias", alias,
            "-file", str(cert_path.resolve()),
            "-keystore", str(self.keystore_path),
            "-storepass", self.keystore_password,
            "-storetype", "PKCS12",
        ]
        log.info(f"[as2] Importing '{alias}' into keystore {self.keystore_path} …")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"keytool import failed: {result.stderr.strip()}")
        log.info(f"[as2] Keystore updated: alias '{alias}'")
        return True

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def _stop_server(self) -> None:
        """Stop the OpenAS2 server process gracefully."""
        result = subprocess.run(["pgrep", "-f", "OpenAS2Server"], capture_output=True, text=True)
        if result.returncode != 0:
            log.info("[as2] OpenAS2 server is not running — nothing to stop.")
            return

        pids = result.stdout.strip().split("\n")
        for pid in pids:
            pid = pid.strip()
            if pid:
                subprocess.run(["kill", pid])
                log.info(f"[as2] Sent SIGTERM to OpenAS2 process (PID {pid}).")

        # Wait for the process to exit
        for _ in range(10):
            time.sleep(1)
            check = subprocess.run(["pgrep", "-f", "OpenAS2Server"], capture_output=True)
            if check.returncode != 0:
                log.info("[as2] OpenAS2 server stopped.")
                return

        log.warning("[as2] OpenAS2 did not stop within 10s — forcing kill.")
        for pid in pids:
            pid = pid.strip()
            if pid:
                subprocess.run(["kill", "-9", pid], capture_output=True)

    def _start_server(self) -> None:
        """Start the OpenAS2 server via start-openas2.sh."""
        start_script = self.bin_dir / "start-openas2.sh"
        if not start_script.exists():
            log.warning(f"[as2] Start script not found at {start_script} — manual restart required.")
            return

        subprocess.Popen(
            ["sh", str(start_script)],
            cwd=str(self.bin_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info(f"[as2] OpenAS2 server starting via {start_script.name} …")

    # ------------------------------------------------------------------
    # Keystore helpers
    # ------------------------------------------------------------------

    def _backup_keystore(self) -> None:
        """Backup the keystore before modifying it."""
        if not self.keystore_path.exists():
            log.warning(f"[as2] Keystore not found at {self.keystore_path} — skipping backup.")
            return
        backup = self.keystore_path.with_suffix(".p12.bak")
        shutil.copy2(self.keystore_path, backup)
        log.info(f"[as2] Keystore backed up → {backup.name}")

    def _delete_keystore_alias(self, alias: str) -> None:
        """Remove an alias from the keystore (silently ignores if not present)."""
        cmd = [
            "keytool", "-delete",
            "-alias", alias,
            "-keystore", str(self.keystore_path),
            "-storepass", self.keystore_password,
            "-storetype", "PKCS12",
        ]
        subprocess.run(cmd, capture_output=True)
        log.info(f"[as2] Deleted alias '{alias}' from keystore (if it existed).")

    # ------------------------------------------------------------------
    # partnerships.xml helpers
    # ------------------------------------------------------------------

    def _get_partner_existing_alias(self, partner_name: str):
        """Return the current x509_alias for a partner, or None if not set."""
        if not self.partners_file.exists():
            return None
        try:
            tree = ET.parse(self.partners_file)
            for partner in tree.getroot().iter("partner"):
                if partner.get("name") == partner_name:
                    return partner.get("x509_alias") or None
        except Exception as e:
            log.warning(f"[as2] Could not read partnerships.xml: {e}")
        return None

    def _set_partner_alias_in_xml(self, partner_name: str, alias: str) -> None:
        """
        Set x509_alias for a partner in partnerships.xml.
        Only called for brand-new partners that have no alias yet.
        """
        if not self.partners_file.exists():
            log.warning(f"[as2] partnerships.xml not found — cannot set alias for '{partner_name}'.")
            return

        backup = Path(str(self.partners_file) + ".bak")
        shutil.copy2(self.partners_file, backup)

        try:
            tree = ET.parse(self.partners_file)
            root = tree.getroot()
            for partner in root.iter("partner"):
                if partner.get("name") == partner_name:
                    partner.set("x509_alias", alias)
                    tree.write(str(self.partners_file), xml_declaration=True, encoding="UTF-8")
                    log.info(f"[as2] Set x509_alias='{alias}' for partner '{partner_name}' in partnerships.xml.")
                    return
            log.warning(f"[as2] Partner '{partner_name}' not found in partnerships.xml.")
        except Exception as e:
            shutil.copy2(backup, self.partners_file)
            raise RuntimeError(f"Failed to update partnerships.xml: {e}") from e

    # ------------------------------------------------------------------
    # Known AS2 IDs (REST API + XML fallback)
    # ------------------------------------------------------------------

    def _fetch_as2_ids_via_api(self):
        """Fetch partner AS2 IDs via REST API. Returns dict or None on failure."""
        try:
            import requests
            auth = (self.api_username, self.api_password) if self.api_password else None
            resp = requests.get(f"{self.api_base}/partner/list", auth=auth, timeout=10)
            if not resp.ok:
                return None
            partner_names = resp.json().get("results", [])
            result = {}
            for name in partner_names:
                r2 = requests.get(f"{self.api_base}/partner/view/{name}", auth=auth, timeout=10)
                if r2.ok:
                    details = r2.json().get("results", [{}])
                    as2_id = details[0].get("as2_id", name) if details else name
                    result[name] = as2_id
            log.info(f"[as2] Loaded {len(result)} partner(s) from REST API.")
            return result
        except Exception as e:
            log.warning(f"[as2] Could not fetch partner list via API: {e}")
            return None

    def _fetch_as2_ids_from_xml(self) -> dict:
        """Parse partnerships.xml and return {partner_name: as2_id}."""
        if not self.partners_file.exists():
            log.warning(f"[as2] partnerships.xml not found at {self.partners_file}")
            return {}
        try:
            tree = ET.parse(self.partners_file)
            result = {}
            for partner in tree.getroot().iter("partner"):
                name = partner.get("name")
                as2_id = partner.get("as2_id", name)
                if name:
                    result[name] = as2_id
            log.info(f"[as2] Loaded {len(result)} partner(s) from partnerships.xml.")
            return result
        except Exception as e:
            log.warning(f"[as2] Could not parse partnerships.xml: {e}")
            return {}

    def _reload_via_signal(self) -> bool:
        result = subprocess.run(["pgrep", "-f", "openas2"], capture_output=True, text=True)
        if result.returncode == 0:
            pid = result.stdout.strip().split("\n")[0]
            subprocess.run(["kill", "-HUP", pid])
            log.info(f"[as2] Sent HUP to OpenAS2 process (PID {pid}).")
            return True
        log.warning("[as2] OpenAS2 process not found — manual restart may be required.")
        return False
