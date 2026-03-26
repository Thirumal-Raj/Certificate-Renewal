"""
Local Cert Store — simulates an AS2 certificate store locally.

Use this when you don't have an OpenAS2 server running. It:
  - Organises renewed certs in a local directory tree
  - Maintains a JSON registry (as2_cert_registry.json)
  - Logs what would be pushed to a real AS2 server
  - Supports the same interface as OpenAS2Connector

Switch to OpenAS2Connector (openas2.py) when you have a real server.
"""

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

REGISTRY_FILE = "as2_cert_registry.json"


class LocalCertStore:
    """
    Drop-in replacement for OpenAS2Connector.
    Stores certs locally and maintains a registry.
    """

    def __init__(self, config: dict):
        store_cfg = config.get("local_cert_store", {})
        self.store_dir = Path(store_cfg.get("store_dir", "as2_local_store"))
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.store_dir / REGISTRY_FILE
        self._registry = self._load_registry()

    # ------------------------------------------------------------------
    # Public interface (mirrors OpenAS2Connector)
    # ------------------------------------------------------------------

    def update_partner_cert(self, cert_path: Path, partner_name: str = None, alias: str = None) -> bool:
        """
        'Install' a cert for a partner — copies to the store and updates the registry.
        """
        partner_name = partner_name or "default-partner"
        alias = alias or cert_path.stem

        partner_dir = self.store_dir / partner_name
        partner_dir.mkdir(parents=True, exist_ok=True)

        dest = partner_dir / cert_path.name
        shutil.copy2(cert_path, dest)

        # Update registry
        self._registry[partner_name] = {
            "alias": alias,
            "cert_file": str(dest),
            "installed_at": datetime.now(tz=timezone.utc).isoformat(),
            "source": str(cert_path),
        }
        self._save_registry()

        log.info(f"[local-store] Cert '{cert_path.name}' stored for partner '{partner_name}'.")
        log.info(f"[local-store]   → {dest}")
        log.info(f"[local-store] (In production this would be pushed to OpenAS2 at {partner_name})")
        return True

    def reload_config(self) -> bool:
        """Simulated reload — just logs what would happen."""
        log.info("[local-store] Config reload simulated (no AS2 server running).")
        log.info("[local-store] In production: OpenAS2 would reload partnerships.xml here.")
        return True

    def import_cert_to_keystore(self, cert_path: Path, alias: str) -> bool:
        """Simulated keystore import."""
        log.info(f"[local-store] Keystore import simulated: alias='{alias}', file='{cert_path.name}'")
        return True

    # ------------------------------------------------------------------
    # Registry helpers
    # ------------------------------------------------------------------

    def list_certs(self) -> dict:
        """Return the current cert registry."""
        return dict(self._registry)

    def _load_registry(self) -> dict:
        if self.registry_path.exists():
            try:
                return json.loads(self.registry_path.read_text())
            except Exception:
                return {}
        return {}

    def _save_registry(self) -> None:
        self.registry_path.write_text(
            json.dumps(self._registry, indent=2)
        )
