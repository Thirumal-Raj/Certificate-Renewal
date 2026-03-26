"""
Certificate Renewer — takes a downloaded certificate file and installs
it into OpenAS2 via the OpenAS2Connector.
"""
import logging
import shutil
from pathlib import Path

from as2_connector.openas2 import OpenAS2Connector

log = logging.getLogger(__name__)


class CertRenewer:
    def __init__(self, config: dict, connector: OpenAS2Connector):
        self.config = config
        self.connector = connector
        renew_cfg = config.get("cert_renewal", {})
        self.output_dir = Path(renew_cfg.get("output_dir", "downloads/renewed"))
        self.partner_name = config.get("as2", {}).get("partner", {}).get("name", "partner")

    def install(self, cert_path: Path, cert_info: dict) -> bool:
        """
        Install a certificate into OpenAS2 and reload config.

        Args:
            cert_path:  Path to the downloaded certificate file.
            cert_info:  Dict from CertChecker.check() with subject, expiry, etc.

        Returns True on success.
        """
        alias = cert_path.stem
        log.info(f"[renewer] Installing '{cert_path.name}' as alias '{alias}' for '{self.partner_name}' …")
        log.info(f"          Subject:  {cert_info.get('subject', 'N/A')}")
        log.info(f"          Issuer:   {cert_info.get('issuer', 'N/A')}")
        log.info(f"          Expires:  {cert_info.get('expiry_date', 'N/A')} "
                 f"({cert_info.get('days_remaining', 0)} days remaining)")

        # Archive a copy before installing
        self._archive(cert_path)

        # Update OpenAS2
        self.connector.update_partner_cert(cert_path, partner_name=self.partner_name, alias=alias)

        # Reload OpenAS2 config
        self.connector.reload_config()

        log.info(f"[renewer] Certificate '{cert_path.name}' installed successfully.")
        return True

    def _archive(self, cert_path: Path) -> None:
        """Copy cert to the output/archive directory."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        dest = self.output_dir / cert_path.name
        shutil.copy2(cert_path, dest)
        log.info(f"[renewer] Archived to {dest}")
