"""
OpenAS2 Connector — updates partner certificates in an OpenAS2 server.

Supports two modes (auto-detected from config):
  1. REST API mode  — calls the OpenAS2 REST API (api_enabled: true)
  2. XML config mode — directly edits partnerships.xml + imports to JKS keystore

Environment variables:
  AS2_API_PASSWORD    — password for the REST API (if api_enabled)
  AS2_KEYSTORE_PASSWORD — JKS keystore password (default: changeit)
"""

import base64
import logging
import os
import shutil
import subprocess
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
        self.keystore_path = Path(as2_cfg.get("keystore_path", self.config_dir / "as2_certs.jks"))
        self.keystore_password = os.environ.get(
            "AS2_KEYSTORE_PASSWORD",
            as2_cfg.get("keystore_password", "changeit") or "changeit",
        )

        self.partner_cfg = as2_cfg.get("partner", {})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_partner_cert(self, cert_path: Path, partner_name: str = None, alias: str = None) -> bool:
        """
        Install a certificate for a partner.
        Returns True on success.
        """
        partner_name = partner_name or self.partner_cfg.get("name", "partner")
        alias = alias or cert_path.stem

        log.info(f"[as2] Updating cert for partner '{partner_name}' (alias: {alias}) …")

        if self.api_enabled and self.api_base:
            success = self._update_via_api(partner_name, cert_path, alias)
            if success:
                return True
            log.warning("[as2] REST API failed, falling back to XML config mode.")

        return self._update_via_xml(partner_name, cert_path, alias)

    def reload_config(self) -> bool:
        """Ask OpenAS2 to reload its configuration."""
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
        """Import a PEM/DER cert into the JKS keystore using keytool."""
        if not shutil.which("keytool"):
            log.warning("[as2] keytool not found — skipping keystore import.")
            return False

        cmd = [
            "keytool", "-importcert",
            "-noprompt",
            "-alias", alias,
            "-file", str(cert_path),
            "-keystore", str(self.keystore_path),
            "-storepass", self.keystore_password,
        ]
        log.info(f"[as2] Importing '{alias}' into keystore {self.keystore_path} …")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            # alias already exists — delete and re-import
            if "already exists" in result.stderr:
                self._delete_keystore_alias(alias)
                result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"keytool import failed: {result.stderr.strip()}")
        log.info(f"[as2] Keystore updated: alias '{alias}'")
        return True

    # ------------------------------------------------------------------
    # REST API mode
    # ------------------------------------------------------------------

    def _update_via_api(self, partner_name: str, cert_path: Path, alias: str) -> bool:
        try:
            import requests
        except ImportError:
            log.warning("[as2] 'requests' library not installed.")
            return False

        cert_b64 = base64.b64encode(cert_path.read_bytes()).decode()
        auth = (self.api_username, self.api_password) if self.api_password else None

        url = f"{self.api_base}/partner/{partner_name}"
        try:
            resp = requests.put(
                url,
                json={"certificate": cert_b64, "cert_alias": alias},
                auth=auth,
                timeout=15,
            )
            resp.raise_for_status()
            log.info(f"[as2] Partner '{partner_name}' cert updated via API.")
            return True
        except Exception as e:
            log.warning(f"[as2] API update failed: {e}")
            return False

    # ------------------------------------------------------------------
    # XML config mode
    # ------------------------------------------------------------------

    def _update_via_xml(self, partner_name: str, cert_path: Path, alias: str) -> bool:
        if not self.partners_file.exists():
            log.warning(f"[as2] partnerships.xml not found at {self.partners_file}")
            return False

        # Backup before modifying
        backup = Path(str(self.partners_file) + ".bak")
        shutil.copy2(self.partners_file, backup)
        log.info(f"[as2] Backed up partnerships.xml → {backup.name}")

        try:
            ET.register_namespace("", "")
            tree = ET.parse(self.partners_file)
            root = tree.getroot()

            updated = False
            for partner in root.iter("partner"):
                if partner.get("name") == partner_name:
                    partner.set("x509_alias", alias)
                    updated = True
                    log.info(f"[as2] Set x509_alias='{alias}' for partner '{partner_name}'.")

            if not updated:
                log.warning(f"[as2] Partner '{partner_name}' not found in partnerships.xml.")
                return False

            tree.write(str(self.partners_file), xml_declaration=True, encoding="UTF-8")

            # Also import cert into JKS keystore
            self.import_cert_to_keystore(cert_path, alias)
            return True

        except Exception as e:
            # Restore backup on failure
            shutil.copy2(backup, self.partners_file)
            raise RuntimeError(f"XML config update failed: {e}") from e

    def _delete_keystore_alias(self, alias: str) -> None:
        cmd = [
            "keytool", "-delete",
            "-alias", alias,
            "-keystore", str(self.keystore_path),
            "-storepass", self.keystore_password,
        ]
        subprocess.run(cmd, capture_output=True)

    def _reload_via_signal(self) -> bool:
        result = subprocess.run(["pgrep", "-f", "openas2"], capture_output=True, text=True)
        if result.returncode == 0:
            pid = result.stdout.strip().split("\n")[0]
            subprocess.run(["kill", "-HUP", pid])
            log.info(f"[as2] Sent HUP to OpenAS2 process (PID {pid}).")
            return True
        log.warning("[as2] OpenAS2 process not found — manual restart may be required.")
        return False
